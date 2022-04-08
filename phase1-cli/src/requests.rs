//! Requests sent to the [Coordinator](`phase1-coordinator::Coordinator`) server.

use reqwest::{Client, Error, Method, Response, StatusCode, Url};
use std::collections::LinkedList;
use serde::Serialize;

use crate::{ContributeChunkRequest, ContributionLocator, GetChunkRequest, LockedLocators, PostChunkRequest, Task};


type Result<T> = std::result::Result<T, Error>;
type PubKey = str;


async fn submit_request<T>(client: &Client, coordinator_address: &str, endpoint: &str, request_body: &T, request: &Method) -> Result<Response>
where T: Serialize + ?Sized {
    let mut target = Url::parse(coordinator_address).expect("Invalid coordinator address");
    target.set_path(endpoint);

    match request {
        &Method::GET => client.get(target).json(request_body).send().await,
        &Method::POST => client.post(target).json(request_body).send().await,
        _ => panic!("Invalid request type")
    }
}


/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to join the queue of contributors.
pub async fn post_join_queue(client: &Client, coordinator_address: &str, request_body: &PubKey) -> Result<()> {
    submit_request(client, coordinator_address, "contributor/join_queue", request_body, &Method::POST).await?;

    Ok(())
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to lock the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn post_lock_chunk(client: &Client, coordinator_address: &str, request_body: &PubKey) -> Result<LockedLocators> {
    let response = submit_request(client, coordinator_address, "contributor/lock_chunk", request_body, &Method::POST).await?;

    Ok(response.json::<LockedLocators>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to get the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn get_chunk(client: &Client, coordinator_address: &str, request_body: &GetChunkRequest) -> Result<Task> {
    let response = submit_request(client, coordinator_address, "download/chunk", request_body, &Method::GET).await?;

    Ok(response.json::<Task>().await?)
}

/// Send a request to the [Coordinator](`phase1-coordinator::Coordinator`) to upload a contribution.
pub async fn post_chunk(client: &Client, coordinator_address: &str, request_body: &PostChunkRequest) -> Result<()> {
    submit_request(client, coordinator_address, "upload/chunk", request_body, &Method::POST).await?;

    Ok(())
}

/// Send a request to notify the [Coordinator](`phase1-coordinator::Coordinator`) of an uploaded contribution.
pub async fn post_contribute_chunk(client: &Client, coordinator_address: &str, request_body: &ContributeChunkRequest) -> Result<ContributionLocator> {
    let response = submit_request(client, coordinator_address, "contributor/contribute_chunk", request_body, &Method::POST).await?;

    Ok(response.json::<ContributionLocator>().await?)
}

/// Let the [Coordinator](`phase1-coordinator::Coordinator`) know that the contributor is still alive.
pub async fn post_heartbeat(client: &Client, coordinator_address: &str, request_body: &PubKey) -> Result<()> {
    submit_request(client, coordinator_address, "contributor/heartbeat", request_body, &Method::POST).await?;

    Ok(())
}

/// Get pending tasks of the contributor.
pub async fn get_tasks_left(client: &Client, coordinator_address: &str, request_body: &PubKey) -> Result<LinkedList<Task>> {
    let response = submit_request(client, coordinator_address, "contributor/get_tasks_left", request_body, &Method::GET).await?;

    Ok(response.json::<LinkedList<Task>>().await?)
}
