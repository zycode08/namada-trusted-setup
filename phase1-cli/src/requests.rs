//! Requests sent to the [Coordinator](`phase1-coordinator::Coordinator`) server.

use phase1_coordinator::{
    authentication::KeyPair,
    objects::{ContributionInfo, TrimmedContributionInfo},
    rest::SignedRequest,
};
use reqwest::{Client, Method, Response, Url};
use serde::Serialize;
use std::collections::LinkedList;
use thiserror::Error;

use crate::{ContributionLocator, ContributorStatus, LockedLocators, PostChunkRequest, Task};

/// Error returned from a request. Could be due to a Client or Server error.
#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Client-side error: {0}")]
    Client(#[from] reqwest::Error),
    #[error("Server-side error: {0}")]
    Server(String),
}

type Result<T> = std::result::Result<T, RequestError>;

/// Submit a json encoded [`SignedRequest`] to the provided enpoint
async fn submit_request<T>(
    client: &Client,
    coordinator_address: &mut Url,
    endpoint: &str,
    keypair: &KeyPair,
    request_body: Option<T>,
    request: &Method,
) -> Result<Response>
where
    T: Serialize,
{
    coordinator_address.set_path(endpoint);

    let req = match request {
        &Method::GET => client.get(coordinator_address.to_owned()),
        &Method::POST => client.post(coordinator_address.to_owned()),
        _ => panic!("Invalid request type"),
    };

    // Sign the request
    let body = SignedRequest::try_sign(keypair, request_body).map_err(|e| RequestError::Server(format!("{}", e)))?;
    let response = req.json(&body).send().await?;

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
    request_body: ContributionInfo,
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
