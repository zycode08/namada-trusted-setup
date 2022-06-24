//! Requests sent to the [Coordinator](`phase1-coordinator::Coordinator`) server.

use anyhow::Ok;
use phase1_coordinator::{
    authentication::KeyPair,
    objects::{ContributionInfo, TrimmedContributionInfo},
    rest::{
        PUBKEY_HEADER,
        BODY_DIGEST_HEADER,
        SIGNATURE_HEADER,
        CONTENT_LENGTH_HEADER,
        DATE_HEADER,
        SignatureHeaders
    },
};
use reqwest::{Client, header::HeaderMap, Response, Url};
use serde::Serialize;
use std::{collections::LinkedList, convert::TryFrom};
use thiserror::Error;

use crate::{ContributionLocator, ContributorStatus, LockedLocators, PostChunkRequest, Task};

#[derive(Debug, Error)]
enum ClientError {
    #[error("Request error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("The required {0} header is missing")]
    MissingRequiredHeader(&'static str),
    #[error("Error while signing the request")]
    SigningError,
}

/// Error returned from a request. Could be due to a Client or Server error.
#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Client-side error: {0}")]
    Client(#[from] ClientError),
    #[error("Server-side error: {0}")]
    Server(String),
}

type Result<T> = std::result::Result<T, RequestError>;

impl TryFrom<HeaderMap> for SignatureHeaders { //FIXME: I need the other way round!
    type Error = RequestError;

    fn try_from(value: HeaderMap) -> Result<Self, Self::Error> {
        let body_digest = match value.get(BODY_DIGEST_HEADER) {
            Some(digest) => Some(digest.to_str()?.split_once('=').ok_or(ClientError::MissingRequiredHeader((BODY_DIGEST_HEADER)))?.1),
            None => None,
        };

        Ok(Self::new( //FIXME: use array or better structure to reduce code redundancy
            value.get(PUBKEY_HEADER).ok_or(ClientError::MissingRequiredHeader((PUBKEY_HEADER)))?,
            value.get(CONTENT_LENGTH_HEADER).ok_or(ClientError::MissingRequiredHeader((CONTENT_LENGTH_HEADER)))?,
            value.get(DATE_HEADER).ok_or(ClientError::MissingRequiredHeader((DATE_HEADER)))?,
            body_digeset,
            value.get(SIGNATURE_HEADER).ok_or(ClientError::MissingRequiredHeader((SIGNATURE_HEADER)))?,
        ))
    }
}

enum Request<T: Serialize> {
    Get,
    Post(Option<T>)
}

/// Submit a signed json encoded request to the provided enpoint
async fn submit_request<T>(
    client: &Client,
    coordinator_address: &mut Url,
    endpoint: &str,
    keypair: &KeyPair,
    request: &Request,
) -> Result<Response>
where
    T: Serialize,
{
    coordinator_address.set_path(endpoint);

    let req = match request {
        Request::Get => client.get(coordinator_address.to_owned()),
        Request::Post(body) => {
            match body {
                Some(b) => client.post(coordinator_address.to_owned()).json(b),
                None => client.post(coordinator_address.to_owned()),
            }
        },
    };

    // Generate headers
    let headers = SignatureHeaders::new(keypair.pubkey(), content_length, date, body_digest, signature); //FIXME:

    // Sign the request
    let sig = headers.sign(keypair.sigkey()).map_err(|_| ClientError::SigningError)?;
    let response = req.headers(headers).send().await?;

    if response.status().is_success() {
        Ok(response)
    } else {
        Err(RequestError::Server(response.text().await?))
    }
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to join the queue of contributors.
pub async fn post_join_queue(client: &Client, coordinator_address: &mut Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<String>(
        client,
        coordinator_address,
        "contributor/join_queue",
        keypair,
        None,
        &Method::POST,
    )
    .await?;

    Ok(())
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to lock the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn post_lock_chunk(
    client: &Client,
    coordinator_address: &mut Url,
    keypair: &KeyPair,
) -> Result<LockedLocators> {
    let response = submit_request::<String>(
        client,
        coordinator_address,
        "contributor/lock_chunk",
        keypair,
        None,
        &Method::POST,
    )
    .await?;

    Ok(response.json::<LockedLocators>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to get the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn get_chunk(
    client: &Client,
    coordinator_address: &mut Url,
    keypair: &KeyPair,
    request_body: &LockedLocators,
) -> Result<Task> {
    let response = submit_request(
        client,
        coordinator_address,
        "download/chunk",
        keypair,
        Some(request_body),
        &Method::GET,
    )
    .await?;

    Ok(response.json::<Task>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to get the next challenge.
pub async fn get_challenge(
    client: &Client,
    coordinator_address: &mut Url,
    keypair: &KeyPair,
    request_body: &LockedLocators,
) -> Result<Vec<u8>> {
    let response = submit_request(
        client,
        coordinator_address,
        "contributor/challenge",
        keypair,
        Some(request_body),
        &Method::GET,
    )
    .await?;

    Ok(response.json::<Vec<u8>>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to upload a contribution.
pub async fn post_chunk(
    client: &Client,
    coordinator_address: &mut Url,
    keypair: &KeyPair,
    request_body: &PostChunkRequest,
) -> Result<()> {
    submit_request(
        client,
        coordinator_address,
        "upload/chunk",
        keypair,
        Some(request_body),
        &Method::POST,
    )
    .await?;

    Ok(())
}

/// Send a request to notify the [Coordinator](`phase1-coordinator::Coordinator`) of an uploaded contribution.
pub async fn post_contribute_chunk(
    client: &Client,
    coordinator_address: &mut Url,
    keypair: &KeyPair,
    request_body: u64,
) -> Result<ContributionLocator> {
    let response = submit_request(
        client,
        coordinator_address,
        "contributor/contribute_chunk",
        keypair,
        Some(request_body),
        &Method::POST,
    )
    .await?;

    Ok(response.json::<ContributionLocator>().await?)
}

/// Let the [Coordinator](`phase1-coordinator::Coordinator`) know that the contributor is still alive.
pub async fn post_heartbeat(client: &Client, coordinator_address: &mut Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<String>(
        client,
        coordinator_address,
        "contributor/heartbeat",
        keypair,
        None,
        &Method::POST,
    )
    .await?;

    Ok(())
}

/// Get pending tasks of the contributor.
pub async fn get_tasks_left(
    client: &Client,
    coordinator_address: &mut Url,
    keypair: &KeyPair,
) -> Result<LinkedList<Task>> {
    let response = submit_request::<String>(
        client,
        coordinator_address,
        "contributor/get_tasks_left",
        keypair,
        None,
        &Method::GET,
    )
    .await?;

    Ok(response.json::<LinkedList<Task>>().await?)
}

/// Request an update of the [Coordinator](`phase1-coordinator::Coordinator`) state.
#[cfg(debug_assertions)]
pub async fn get_update(client: &Client, coordinator_address: &mut Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/update", keypair, None, &Method::GET).await?;

    Ok(())
}

/// Stop the [Coordinator](`phase1-coordinator::Coordinator`).
pub async fn get_stop_coordinator(client: &Client, coordinator_address: &mut Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/stop", keypair, None, &Method::GET).await?;

    Ok(())
}

/// Verify the pending contributions.
#[cfg(debug_assertions)]
pub async fn get_verify_chunks(client: &Client, coordinator_address: &mut Url, keypair: &KeyPair) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/verify", keypair, None, &Method::GET).await?;

    Ok(())
}

/// Get Contributor queue status.
pub async fn get_contributor_queue_status(
    client: &Client,
    coordinator_address: &mut Url,
    keypair: &KeyPair,
) -> Result<ContributorStatus> {
    let response = submit_request::<()>(
        client,
        coordinator_address,
        "contributor/queue_status",
        keypair,
        None,
        &Method::GET,
    )
    .await?;

    Ok(response.json::<ContributorStatus>().await?)
}

/// Send [`ContributionInfo`] to the Coordinator.
pub async fn post_contribution_info(
    client: &Client,
    coordinator_address: &mut Url,
    keypair: &KeyPair,
    request_body: &ContributionInfo,
) -> Result<()> {
    submit_request::<ContributionInfo>(
        client,
        coordinator_address,
        "contributor/contribution_info",
        keypair,
        Some(request_body),
        &Method::POST,
    )
    .await?;

    Ok(())
}

/// Retrieve the list of contributions
pub async fn get_contributions_info(
    client: &Client,
    coordinator_address: &mut Url,
) -> Result<Vec<TrimmedContributionInfo>> {
    coordinator_address.set_path("/contribution_info");
    // FIXME: manage accept-encoding header with compression only in production build (create a feature aws)
    let req = client.get(coordinator_address.to_owned());
    let response = req.send().await?;

    if response.status().is_success() {
        Ok(response.json::<Vec<TrimmedContributionInfo>>().await?)
    } else {
        Err(RequestError::Server(response.text().await?))
    }
}
