//! Requests sent to the [Coordinator](`phase1-coordinator::Coordinator`) server.

use phase1_coordinator::{
    authentication::{KeyPair, Production, Signature},
    objects::{ContributionInfo, TrimmedContributionInfo},
    rest::{
        RequestContent,
        SignatureHeaders,
        BODY_DIGEST_HEADER,
        CONTENT_LENGTH_HEADER,
        PUBKEY_HEADER,
        SIGNATURE_HEADER,
    },
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
    Response,
    Url,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::LinkedList,
    convert::{TryFrom, TryInto},
    ops::{Deref, DerefMut},
};
use thiserror::Error;

use crate::{ContributionLocator, ContributorStatus, LockedLocators, PostChunkRequest, Task};

/// Error returned from a request. Could be due to a Client or Server error.
#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Error while parsing the coordinator url")]
    AddressParseError,
    #[error("Digest header is missing hashing algorithm")]
    InvalidDigestHeaderFormat,
    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error("Json serialization of body failed")]
    JsonError(#[from] serde_json::Error),
    #[error("Request error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("The required {0} header is missing")]
    MissingRequiredHeader(&'static str),
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
    keypair: &KeyPair,
    request: Request<'_, T>,
) -> Result<Response>
where
    T: Serialize,
{
    let address = coordinator_address
        .join(endpoint)
        .map_err(|_| RequestError::AddressParseError)?;
    let mut content: Option<RequestContent> = None;

    let req = match request {
        Request::Get => client.get(address),
        Request::Post(body) => match body {
            Some(b) => {
                let json_body = serde_json::to_string(b)?;

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

    // Generate headers
    let mut headers = SignatureHeaders::new(keypair.pubkey(), content, None);
    headers.try_sign(keypair.sigkey())?;
    let header_map: HeaderWrap = headers.try_into()?;

    let response = req.headers(header_map.into()).send().await?;

    if response.status().is_success() {
        Ok(response)
    } else {
        Err(RequestError::Server(response.text().await?))
    }
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to join the queue of contributors.
pub async fn post_join_queue(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<String>(
        client,
        coordinator_address,
        "contributor/join_queue",
        keypair,
        Request::Post(None),
    )
    .await?;

    Ok(())
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to lock the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn get_lock_chunk(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<LockedLocators> {
    let response = submit_request::<String>(
        client,
        coordinator_address,
        "contributor/lock_chunk",
        keypair,
        Request::Get,
    )
    .await?;

    Ok(response.json::<LockedLocators>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to get the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn get_chunk(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    request_body: &LockedLocators,
) -> Result<Task> {
    let response = submit_request(
        client,
        coordinator_address,
        "download/chunk",
        keypair,
        Request::Post(Some(request_body)),
    )
    .await?;

    Ok(response.json::<Task>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to get the next challenge.
pub async fn get_challenge(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    request_body: &LockedLocators,
) -> Result<Vec<u8>> {
    let response = submit_request(
        client,
        coordinator_address,
        "contributor/challenge",
        keypair,
        Request::Post(Some(request_body)),
    )
    .await?;

    Ok(response.json::<Vec<u8>>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to upload a contribution.
pub async fn post_chunk(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    request_body: &PostChunkRequest,
) -> Result<()> {
    submit_request(
        client,
        coordinator_address,
        "upload/chunk",
        keypair,
        Request::Post(Some(request_body)),
    )
    .await?;

    Ok(())
}

/// Send a request to notify the [Coordinator](`phase1-coordinator::Coordinator`) of an uploaded contribution.
pub async fn post_contribute_chunk(
    client: &Client,
    coordinator_address: &Url,
    keypair: &KeyPair,
    request_body: u64,
) -> Result<ContributionLocator> {
    let response = submit_request(
        client,
        coordinator_address,
        "contributor/contribute_chunk",
        keypair,
        Request::Post(Some(&request_body)),
    )
    .await?;

    Ok(response.json::<ContributionLocator>().await?)
}

/// Let the [Coordinator](`phase1-coordinator::Coordinator`) know that the contributor is still alive.
pub async fn post_heartbeat(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<String>(
        client,
        coordinator_address,
        "contributor/heartbeat",
        keypair,
        Request::Post(None),
    )
    .await?;

    Ok(())
}

/// Get pending tasks of the contributor.
pub async fn get_tasks_left(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<LinkedList<Task>> {
    let response = submit_request::<String>(
        client,
        coordinator_address,
        "contributor/get_tasks_left",
        keypair,
        Request::Get,
    )
    .await?;

    Ok(response.json::<LinkedList<Task>>().await?)
}

/// Request an update of the [Coordinator](`phase1-coordinator::Coordinator`) state.
#[cfg(debug_assertions)]
pub async fn get_update(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/update", keypair, Request::Get).await?;

    Ok(())
}

/// Stop the [Coordinator](`phase1-coordinator::Coordinator`).
pub async fn get_stop_coordinator(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/stop", keypair, Request::Get).await?;

    Ok(())
}

/// Verify the pending contributions.
#[cfg(debug_assertions)]
pub async fn get_verify_chunks(client: &Client, coordinator_address: &Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/verify", keypair, Request::Get).await?;

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
        keypair,
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
        keypair,
        Request::Post(Some(request_body)),
    )
    .await?;

    Ok(())
}

/// Retrieve the list of contributions
pub async fn get_contributions_info(
    client: &Client,
    coordinator_address: &Url,
) -> Result<Vec<TrimmedContributionInfo>> {
    let address = coordinator_address
        .join("/contribution_info")
        .map_err(|_| RequestError::AddressParseError)?;
    // FIXME: manage accept-encoding header with compression only in production build (create a feature aws)
    let req = client.get(address);
    let response = req.send().await?;

    if response.status().is_success() {
        Ok(response.json::<Vec<TrimmedContributionInfo>>().await?)
    } else {
        Err(RequestError::Server(response.text().await?))
    }
}
