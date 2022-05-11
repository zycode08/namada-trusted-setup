//! Requests sent to the [Coordinator](`phase1-coordinator::Coordinator`) server.

use reqwest::{Client, Method, Response, Url};
use serde::Serialize;
use std::collections::LinkedList;
use thiserror::Error;

use crate::{
    ContributeChunkRequest,
    ContributionLocator,
    ContributorStatus,
    GetChunkRequest,
    LockedLocators,
    PostChunkRequest,
    Task,
};

/// Error returned from a request. Could be due to a Client or Server error.
#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Client-side error: {0}")]
    Client(#[from] reqwest::Error),
    #[error("Server-side error: {0}")]
    Server(String),
}

type Result<T> = std::result::Result<T, RequestError>;

async fn submit_request<T>(
    client: &Client,
    coordinator_address: &mut Url,
    endpoint: &str,
    request_body: Option<&T>,
    request: &Method,
) -> Result<Response>
where
    T: Serialize + ?Sized,
{
    coordinator_address.set_path(endpoint);

    let req = match request {
        &Method::GET => client.get(coordinator_address.to_owned()),
        &Method::POST => client.post(coordinator_address.to_owned()),
        _ => panic!("Invalid request type"),
    };

    let req = match request_body {
        Some(body) => req.json(body),
        None => req,
    };

    let response = req.send().await?;

    if response.status().is_success() {
        Ok(response)
    } else {
        Err(RequestError::Server(response.text().await?))
    }
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to join the queue of contributors.
pub async fn post_join_queue<T>(client: &Client, coordinator_address: &mut Url, request_body: T) -> Result<()>
where
    T: Into<String>,
{
    submit_request::<String>(
        client,
        coordinator_address,
        "contributor/join_queue",
        Some(&request_body.into()),
        &Method::POST,
    )
    .await?;

    Ok(())
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to lock the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn post_lock_chunk<T>(
    client: &Client,
    coordinator_address: &mut Url,
    request_body: T,
) -> Result<LockedLocators>
where
    T: Into<String>,
{
    let response = submit_request::<String>(
        client,
        coordinator_address,
        "contributor/lock_chunk",
        Some(&request_body.into()),
        &Method::POST,
    )
    .await?;

    Ok(response.json::<LockedLocators>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to get the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn get_chunk(client: &Client, coordinator_address: &mut Url, request_body: &GetChunkRequest) -> Result<Task> {
    let response = submit_request(
        client,
        coordinator_address,
        "download/chunk",
        Some(request_body),
        &Method::GET,
    )
    .await?;

    Ok(response.json::<Task>().await?)
}

pub async fn get_challenge(
    client: &Client,
    coordinator_address: &mut Url,
    request_body: &LockedLocators,
) -> Result<Vec<u8>> {
    let response = submit_request(
        client,
        coordinator_address,
        "contributor/challenge",
        Some(request_body),
        &Method::GET,
    )
    .await?;

    Ok(response.json::<Vec<u8>>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to upload a contribution.
pub async fn post_chunk(client: &Client, coordinator_address: &mut Url, request_body: &PostChunkRequest) -> Result<()> {
    submit_request(
        client,
        coordinator_address,
        "upload/chunk",
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
    request_body: &ContributeChunkRequest,
) -> Result<ContributionLocator> {
    let response = submit_request(
        client,
        coordinator_address,
        "contributor/contribute_chunk",
        Some(request_body),
        &Method::POST,
    )
    .await?;

    Ok(response.json::<ContributionLocator>().await?)
}

/// Let the [Coordinator](`phase1-coordinator::Coordinator`) know that the contributor is still alive.
pub async fn post_heartbeat<T>(client: &Client, coordinator_address: &mut Url, request_body: T) -> Result<()>
where
    T: Into<String>,
{
    submit_request::<String>(
        client,
        coordinator_address,
        "contributor/heartbeat",
        Some(&request_body.into()),
        &Method::POST,
    )
    .await?;

    Ok(())
}

/// Get pending tasks of the contributor.
pub async fn get_tasks_left<T>(
    client: &Client,
    coordinator_address: &mut Url,
    request_body: T,
) -> Result<LinkedList<Task>>
where
    T: Into<String>,
{
    let response = submit_request::<String>(
        client,
        coordinator_address,
        "contributor/get_tasks_left",
        Some(&request_body.into()),
        &Method::GET,
    )
    .await?;

    Ok(response.json::<LinkedList<Task>>().await?)
}

/// Request an update of the [Coordinator](`phase1-coordinator::Coordinator`) state.
pub async fn get_update(client: &Client, coordinator_address: &mut Url) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/update", None, &Method::GET).await?;

    Ok(())
}

/// Stop the [Coordinator](`phase1-coordinator::Coordinator`).
pub async fn get_stop_coordinator(client: &Client, coordinator_address: &mut Url) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/stop", None, &Method::GET).await?;

    Ok(())
}

/// Verify the pending contributions.
pub async fn get_verify_chunks(client: &Client, coordinator_address: &mut Url) -> Result<()> {
    submit_request::<()>(client, coordinator_address, "/verify", None, &Method::GET).await?;

    Ok(())
}

/// Get Contributor queue status.
pub async fn get_contributor_queue_status(
    client: &Client,
    coordinator_address: &mut Url,
    request_body: &String,
) -> Result<ContributorStatus> {
    let response = submit_request(
        client,
        coordinator_address,
        "contributor/queue_status",
        Some(request_body),
        &Method::GET,
    )
    .await?;

    Ok(response.json::<ContributorStatus>().await?)
}
