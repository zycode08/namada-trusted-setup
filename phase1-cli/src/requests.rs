//! Requests sent to the [Coordinator](phase1-coordinator::Coordinator) server.

use reqwest::{Client, Error, Request, Response, StatusCode, Url};
use std::net::SocketAddr;

type Result<T> = std::result::Result<T, Error>;

/// Send a request to the [Coordinator](phase1-coordinator::Coordinator) to join the queue of contributors.
pub async fn post_join_queue(client: &Client, coordinator_address: &SocketAddr, pubkey: &String) -> Result<()> {
    let mut target = Url::parse(coordinator_address);
    target.set_path("contributor/join_queue");
    client.post(target).json(pubkey).send().await?;

    Ok(())
}

/// Send a request to the [Coordinator](phase1-coordinator::Coordinator) to lock the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn post_lock_chunk(client: &Client, coordinator_address: &SocketAddr, pubkey: &String) -> Result<LockedLocators> {
    let mut target = Url::parse(coordinator_address);
    target.set_path("contributor/lock_chunk");
    let response = client.post(target).json(pubkey).send().await?;

    Ok(response.json::<LockedLocators>().await?)
}

/// Send a request to the [Coordinator](phase1-coordinator::Coordinator) to get the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn get_chunk(client: &Client, coordinator_address: &SocketAddr, request_body: &GetChunkRequest) -> Result<Task> {
    let mut target = Url::parse(coordinator_address);
    target.set_path("download/chunk");
    let response = client.get(target).json(request_body).send().await?;

    Ok(response.json::<Task>().await?)
}

/// Send a request to the [Coordinator](phase1-coordinator::Coordinator) to upload a contribution.
pub async fn post_chunk(client: &Client, coordinator_address: &SocketAddr, request_body: &PostChunkRequest) -> Result<()> {
    let mut target = Url::parse(coordinator_address);
    target.set_path("upload/chunk");
    client.post(target).json(request_body).send().await?;

    Ok(())
}

/// Send a request to notify the [Coordinator](phase1-coordinator::Coordinator) of an uploaded contribution.
pub async fn post_contribute_chunk(client: &Client, coordinator_address: &SocketAddr, request_body: &ContributeChunkRequest) -> Result<ContributionLocator> {
    let mut target = Url::parse(coordinator_address);
    target.set_path("contributor/contribute_chunk");
    let response = client.post(target).json(request_body).send().await?;

    Ok(response.json::<ContributionLocator>().await?)
}

/// Let the [Coordinator](phase1-coordinator::Coordinator) know that the contributor is still alive.
pub async fn post_heartbeat(client: &Client, coordinator_address: &SocketAddr, pubkey: &String) -> Result<()> {
    let mut target = Url::parse(coordinator_address);
    target.set_path("contributor/heartbeat");
    client.post(target).json(pubkey).send().await?;

    Ok(())
}

/// Get pending tasks of the contributor.
pub async fn get_tasks_left(client: &Client, coordinator_address: &SocketAddr, pubkey: &String) -> Result<LinkedList<Task>> {
    let mut target = Url::parse(coordinator_address);
    target.set_path("contributor/get_tasks_left");
    let response = client.get(target).json(pubkey).send().await?;

    Ok(response.json::<LinkedList<Task>>().await?)
}
