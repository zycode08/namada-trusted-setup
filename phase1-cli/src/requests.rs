//! Requests sent to the [Coordinator](phase1-coordinator::Coordinator) server.

use reqwest::{Client, Error, Request, Response, Url};
use std::net::SocketAddr;

type Result = std::result::Result<Response, Error>;

// FIXME: use a macro to generate all the requests??

/// Send a request to the [Coordinator](phase1-coordinator::Coordinator) to join the queue of contributors.
pub async fn post_join_queue(client: &Client, coordinator_address: &SocketAddr, pubkey: &String) -> Result {
    let mut target = Url::parse(coordinator_address);
    target.set_path("contributor/join_queue").;
    client.post(target).json(pubkey).send().await
}

/// Send a request to the [Coordinator](phase1-coordinator::Coordinator) to lock the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn post_lock_chunk(client: &Client, coordinator_address: &SocketAddr, pubkey: &String) -> Result {
    let mut target = Url::parse(coordinator_address);
    target.set_path("contributor/lock_chunk").;
    client.post(target).json(pubkey).send().await
}

/// Send a request to the [Coordinator](phase1-coordinator::Coordinator) to get the next [Chunk](`phase1-coordinator::objects::Chunk`).
pub async fn get_chunk(client: &Client, coordinator_address: &SocketAddr, request_body: &ChunkRequest) -> Result {
    let mut target = Url::parse(coordinator_address);
    target.set_path("/download/chunk").;
    client.get(target).json(request_body).send().await
}

// TODO:
// contribute
// heartbeat
// get_tasks_left