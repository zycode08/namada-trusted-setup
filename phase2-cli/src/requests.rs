//! Requests sent to the [Coordinator](`phase2-coordinator::Coordinator`) server.

use bytes::Bytes;
use futures_util::Stream;
use phase2_coordinator::{
    authentication::{KeyPair, Production, Signature},
    objects::ContributionInfo,
    rest_utils::{
        RequestContent,
        SignatureHeaders,
        ACCESS_SECRET_HEADER,
        BODY_DIGEST_HEADER,
        CONTENT_LENGTH_HEADER,
        PUBKEY_HEADER,
        SIGNATURE_HEADER,
    },
    ContributionFileSignature,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
    RequestBuilder,
    Response,
    Url,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

use crate::{ContributorStatus, LockedLocators, PostChunkRequest};

/// Error returned from a request.
#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Error while parsing the coordinator url")]
    AddressParseError,
    #[error("Client-side error: {0}")]
    Client(String),
    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error("Json serialization of body failed")]
    JsonError(#[from] serde_json::Error),
    #[error("CDN Error: {0}")]
    Proxy(String),
    #[error("Request error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Error while signing the request")]
    SigningError,
    #[error("Server-side error: {0}")]
    Server(String),
}

type Result<T> = std::result::Result<T, RequestError>;
/// Wrapper type to convert [`SignatureHeaders`] into [`HeaderMap`]
struct HeaderWrap(HeaderMap);

impl From<HeaderWrap> for HeaderMap {
    fn from(value: HeaderWrap) -> Self {
        value.0
    }
}

impl TryFrom<SignatureHeaders<'_>> for HeaderWrap {
    type Error = RequestError;

    fn try_from(value: SignatureHeaders) -> std::result::Result<Self, Self::Error> {
        let mut result = HeaderMap::new();
        result.insert(PUBKEY_HEADER, HeaderValue::from_str(value.pubkey)?);

        if let Some(sig) = value.signature {
            result.insert(SIGNATURE_HEADER, HeaderValue::from_str(&sig)?);
        }

        if let Some(content) = value.content {
            let (content_len, content_digest) = content.to_header();
            result.insert(CONTENT_LENGTH_HEADER, content_len.into());
            result.insert(BODY_DIGEST_HEADER, HeaderValue::from_str(content_digest.as_str())?);
        }

        Ok(Self(result))
    }
}

trait Sign {
    fn try_sign(&mut self, sigkey: &str) -> Result<()>;
}

impl Sign for SignatureHeaders<'_> {
    fn try_sign(&mut self, sigkey: &str) -> Result<()> {
        let msg = self.to_string();
        self.signature = Some(
            Production
                .sign(sigkey, &msg)
                .map_err(|_| RequestError::SigningError)?
                .into(),
        );

        Ok(())
    }
}

enum Request<'a, T: Serialize> {
    Get,
    Post(Option<&'a T>),
}

/// Submit a signed json encoded request to the provided enpoint
async fn submit_request<T: Serialize>(
    client: &Client,
    coordinator_address: &Url,
    endpoint: &str,
    keypair: Option<&KeyPair>,
    custom_headers: Option<HeaderMap>,
    request: Request<'_, T>,
) -> Result<Response>
where
    T: Serialize,
{
    let address = coordinator_address
        .join(endpoint)
        .map_err(|_| RequestError::AddressParseError)?;
    let mut content: Option<RequestContent> = None;

    let mut req = match request {
        Request::Get => client.get(address),
        Request::Post(body) => match body {
            Some(b) => {
                let json_body = serde_json::to_vec(b)?;

                let mut hasher = Sha256::new();
                hasher.update(&json_body);
                let digest = hasher.finalize();

                content = Some(RequestContent::new(json_body.len(), digest));
                client
                    .post(address)
                    .body(json_body)
                    .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            }
            None => client.post(address),
        },
    };

    // Generate signatures headers if required
    if let Some(kp) = keypair {
        let mut headers = SignatureHeaders::new(kp.pubkey(), content, None);
        headers.try_sign(kp.sigkey())?;
        let header_map: HeaderWrap = headers.try_into()?;
        req = req.headers(header_map.into());
    }

    // Add custom headers if required
    if let Some(header_map) = custom_headers {
        req = req.headers(header_map);
    }

    loop {
        let response = req.try_clone().expect("Expected request not stream").send().await?;

        match decapsulate_response(response).await {
            Ok(response) => return Ok(response),
            Err(e) => match e {
                RequestError::Proxy(_) => eprintln!("CDN timeout expired, resubmitting the request..."),
                _ => return Err(e),
            },
        }
    }
}

/// Decapsulate the response and, if error, maps [`Response`] error to [`RequestError`].
async fn decapsulate_response(response: Response) -> Result<Response> {
    let status = response.status();

    if status.is_success() {
        Ok(response)
    } else if status.is_client_error() {
        Err(RequestError::Client(response.text().await?))
    } else {
        if status.as_u16() == reqwest::StatusCode::GATEWAY_TIMEOUT.as_u16() {
            Err(RequestError::Proxy(response.text().await?))
        } else {
            Err(RequestError::Server(response.text().await?))
        }
    }
}

/// Send a request to the [Coordinator](`phase2-coordinator::Coordinator`) to join the queue of contributors.
pub async fn post_join_queue(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    token: &String,
) -> Result<u64> {
    let response = submit_request::<String>(
        client,
        coordinator_address,
        "contributor/join_queue",
        Some(keypair),
        None,
        Request::Post(Some(token)),
    )
    .await?;

    Ok(response.json::<u64>().await?)
}

/// Send a request to the [Coordinator](`phase2-coordinator::Coordinator`) to lock the next [Chunk](`phase2-coordinator::objects::Chunk`).
pub async fn get_lock_chunk(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<LockedLocators> {
    let response = submit_request::<String>(
        client,
        coordinator_address,
        "contributor/lock_chunk",
        Some(keypair),
        None,
        Request::Get,
    )
    .await?;

    Ok(response.json::<LockedLocators>().await?)
}

/// Send a request to the [Coordinator](`phase2-coordinator::Coordinator`) to get the next challenge's key.
pub async fn get_challenge_url(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    round_height: &u64,
) -> Result<String> {
    let response = submit_request(
        client,
        coordinator_address,
        "contributor/challenge",
        Some(keypair),
        None,
        Request::Post(Some(round_height)),
    )
    .await?;

    Ok(response.json().await?)
}

/// Send a request to Amazon S3 to download the next challenge.
pub async fn get_challenge(
    client: &Client,
    challenge_url: &str,
) -> Result<(impl Stream<Item = reqwest::Result<Bytes>>, u64)> {
    let req = client.get(challenge_url);
    let response = req.send().await?;
    let stream_len = response.content_length().unwrap();

    Ok((decapsulate_response(response).await?.bytes_stream(), stream_len))
}

/// Send a request to the [Coordinator](`phase2-coordinator::Coordinator`) to get the target Strings where to upload the contribution and its signature.
pub async fn get_contribution_url(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    round_height: &u64,
) -> Result<(String, String)> {
    let response = submit_request::<u64>(
        client,
        coordinator_address,
        "upload/chunk",
        Some(keypair),
        None,
        Request::Post(Some(round_height)),
    )
    .await?;

    Ok(response.json().await?)
}

/// Upload a gneric object to S3.
async fn upload_object(req: RequestBuilder) -> Result<()> {
    let response = req.send().await?;
    decapsulate_response(response).await?;

    Ok(())
}

/// Upload a contribution and its signature to Amazon S3.
pub async fn upload_chunk<S>(
    client: &Client,
    contrib_url: &str,
    contrib_sig_url: &str,
    contribution_stream: S,
    contribution_len: u64,
    contribution_signature: &ContributionFileSignature,
) -> Result<()>
where
    S: Stream<Item = std::result::Result<Bytes, std::io::Error>> + std::marker::Send + std::marker::Sync + 'static,
{
    let json_sig = serde_json::to_vec(&contribution_signature)?;
    let contrib_req = client
        .put(contrib_url)
        .body(reqwest::Body::wrap_stream(contribution_stream))
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH_HEADER, contribution_len);
    let contrib_sig_req = client
        .put(contrib_sig_url)
        .body(json_sig)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    tokio::try_join!(upload_object(contrib_req), upload_object(contrib_sig_req))?;

    Ok(())
}

/// Send a request to notify the [Coordinator](`phase2-coordinator::Coordinator`) of an uploaded contribution.
pub async fn post_contribute_chunk(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    request_body: &PostChunkRequest,
) -> Result<()> {
    submit_request(
        client,
        coordinator_address,
        "contributor/contribute_chunk",
        Some(keypair),
        None,
        Request::Post(Some(request_body)),
    )
    .await?;

    Ok(())
}

/// Let the [Coordinator](`phase2-coordinator::Coordinator`) know that the contributor is still alive.
pub async fn post_heartbeat(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<String>(
        client,
        coordinator_address,
        "contributor/heartbeat",
        Some(keypair),
        None,
        Request::Post(None),
    )
    .await?;

    Ok(())
}

/// Request an update of the [Coordinator](`phase2-coordinator::Coordinator`) state.
#[cfg(debug_assertions)]
pub async fn get_update(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(
        client,
        coordinator_address,
        "/update",
        Some(keypair),
        None,
        Request::Get,
    )
    .await?;

    Ok(())
}

/// Stop the [Coordinator](`phase2-coordinator::Coordinator`).
pub async fn get_stop_coordinator(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/stop", Some(keypair), None, Request::Get).await?;

    Ok(())
}

/// Verify the pending contributions.
#[cfg(debug_assertions)]
pub async fn get_verify_chunks(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(
        client,
        coordinator_address,
        "/verify",
        Some(keypair),
        None,
        Request::Get,
    )
    .await?;

    Ok(())
}

/// Get Contributor queue status.
pub async fn get_contributor_queue_status(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
) -> Result<ContributorStatus> {
    let response = submit_request::<()>(
        client,
        coordinator_address,
        "contributor/queue_status",
        Some(keypair),
        None,
        Request::Get,
    )
    .await?;

    Ok(response.json::<ContributorStatus>().await?)
}

/// Send [`ContributionInfo`] to the Coordinator.
pub async fn post_contribution_info(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    request_body: &ContributionInfo,
) -> Result<()> {
    submit_request::<ContributionInfo>(
        client,
        coordinator_address,
        "contributor/contribution_info",
        Some(keypair),
        None,
        Request::Post(Some(request_body)),
    )
    .await?;

    Ok(())
}

/// Send an attestation of the contribution to the Coordinator.
pub async fn post_attestation(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    request_body: &String,
) -> Result<()> {
    submit_request::<String>(
        client,
        coordinator_address,
        "/contributor/attestation",
        Some(keypair),
        None,
        Request::Post(Some(request_body)),
    )
    .await?;

    Ok(())
}

/// Query health endpoint of the Coordinator to check the connection
pub async fn ping_coordinator(client: &Client, coordinator_address: &Url) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/healthcheck", None, None, Request::Get).await?;

    Ok(())
}

/// Retrieve the list of contributions, json encoded
#[cfg(debug_assertions)]
pub async fn get_contributions_info(coordinator_address: &Url) -> Result<Vec<u8>> {
    let client = Client::builder().brotli(true).build()?;

    let response = submit_request::<()>(
        &client,
        coordinator_address,
        "/contribution_info",
        None,
        None,
        Request::Get,
    )
    .await?;

    Ok(response.bytes().await?.to_vec())
}

/// Retrieve the state of the coordinator, json encoded. Needs to provide a secret access token to the endpoint
pub async fn get_coordinator_state(coordinator_address: &Url, access_secret: &str) -> Result<Vec<u8>> {
    let client = Client::builder().brotli(true).build()?;
    let mut header = HeaderMap::new();
    header.insert(ACCESS_SECRET_HEADER, HeaderValue::from_str(access_secret)?);

    let response = submit_request::<()>(
        &client,
        coordinator_address,
        "/coordinator_status",
        None,
        Some(header),
        Request::Get,
    )
    .await?;

    Ok(response.bytes().await?.to_vec())
}

/// Updates the cohort. [`tokens`] parameter must be the content of the tokens.zip file
pub async fn post_update_cohorts(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    tokens: &Vec<u8>,
) -> Result<()> {
    submit_request::<Vec<u8>>(
        &client,
        coordinator_address,
        "/update_cohorts",
        Some(keypair),
        None,
        Request::Post(Some(tokens)),
    )
    .await?;

    Ok(())
}
