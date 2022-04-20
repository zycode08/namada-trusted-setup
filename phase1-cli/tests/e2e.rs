use std::{net::IpAddr, sync::Arc};

use phase1::{ContributionMode, ProvingSystem};
use phase1_coordinator::{
    authentication::{Dummy, Signature},
    environment::{CurveKind, Parameters, Settings, Testing},
    objects::{LockedLocators, Task},
    rest::{self, ContributeChunkRequest, GetChunkRequest, PostChunkRequest},
    storage::{ContributionLocator, ContributionSignatureLocator},
    testing::coordinator,
    ContributionFileSignature,
    ContributionState,
    Coordinator,
    Participant,
};
use rocket::{routes, Error};

use phase1_cli::requests;
use reqwest::{Client, Url};

use tokio::{
    sync::RwLock,
    task::JoinHandle,
    time::{self, Duration},
};

// NOTE: these tests must be run with --test-threads=1 due to the disk storage
//	being stored at the same path for all the test instances causing a conflict.
//	It could be possible to define a separate location (base_dir) for every test
//	but it's simpler to just run the tests sequentially.

const COORDINATOR_ADDRESS: &str = "http://127.0.0.1:8000";
const CONTRIBUTOR_1_PUBLIC_KEY: &str = "abc";
const CONTRIBUTOR_2_PUBLIC_KEY: &str = "def";
const UNKNOWN_CONTRIBUTOR_PUBLIC_KEY: &str = "jjjj";
const CONTRIBUTOR_1_IP: &str = "0.0.0.1";
const CONTRIBUTOR_2_IP: &str = "0.0.0.2";
const CONTRIBUTION_SIZE: usize = 4576;
const ROUND_HEIGHT: u64 = 1;

/// Launch the rocket server for testing with the proper configuration as a separate async Task.
async fn spawn_rocket_server() -> JoinHandle<Result<(), Error>> {
    let parameters = Parameters::Custom(Settings::new(
        ContributionMode::Chunked,
        ProvingSystem::Groth16,
        CurveKind::Bls12_377,
        6,  /* power */
        16, /* batch_size */
        16, /* chunk_size */
    ));

    // Reset storage to prevent state conflicts between tests and initialize test environment
    let environment = coordinator::initialize_test_environment(&Testing::from(parameters).into());

    // Instantiate the coordinator
    let mut coordinator = Coordinator::new(environment, Arc::new(Dummy)).unwrap();

    let contributor1 = Participant::new_contributor(CONTRIBUTOR_1_PUBLIC_KEY);
    let contributor2 = Participant::new_contributor(CONTRIBUTOR_2_PUBLIC_KEY);

    let contributor1_ip = IpAddr::V4(CONTRIBUTOR_1_IP.parse().unwrap());
    let contributor2_ip = IpAddr::V4(CONTRIBUTOR_2_IP.parse().unwrap());

    coordinator.initialize().unwrap();

    coordinator
        .add_to_queue(contributor1, Some(contributor1_ip), 10)
        .unwrap();
    coordinator
        .add_to_queue(contributor2.clone(), Some(contributor2_ip), 9)
        .unwrap();
    coordinator.update().unwrap();

    coordinator.try_lock(&contributor2).unwrap();

    let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(coordinator));

    let build = rocket::build()
        .mount("/", routes![
            rest::join_queue,
            rest::lock_chunk,
            rest::get_chunk,
            rest::post_contribution_chunk,
            rest::contribute_chunk,
            rest::update_coordinator,
            rest::heartbeat,
            rest::get_tasks_left,
            rest::stop_coordinator,
            rest::verify_chunk
        ])
        .manage(coordinator);

    let ignite = build.ignite().await.unwrap();
    tokio::spawn(ignite.launch())
}

#[tokio::test]
async fn test_stop_coordinator() {
    let client = Client::new();
    // Spawn the server and wait for its startup
    let handle = spawn_rocket_server().await;
    time::sleep(Duration::from_millis(1000)).await;

    // Shut the server down
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::get_stop_coordinator(&client, &mut url).await;
    assert!(response.is_ok());

    // Try sending another request (server should be unreachable)
    let response = requests::get_stop_coordinator(&client, &mut url).await;

    match response {
        Ok(_) => panic!("Expected error"),
        Err(e) => match e {
            requests::RequestError::Client(_) => (),
            requests::RequestError::Server(_) => panic!("Expected client-side error"),
        },
    }

    // Drop the server
    handle.abort();
}

#[tokio::test]
async fn test_heartbeat() {
    let client = Client::new();
    // Spawn the server and wait for its startup
    let handle = spawn_rocket_server().await;
    time::sleep(Duration::from_millis(1000)).await;

    // Non-existing contributor key
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::post_heartbeat(&client, &mut url, &String::from(UNKNOWN_CONTRIBUTOR_PUBLIC_KEY)).await;
    assert!(response.is_err());

    // Ok
    requests::post_heartbeat(&client, &mut url, &String::from(CONTRIBUTOR_1_PUBLIC_KEY))
        .await
        .unwrap();

    // Drop the server
    handle.abort();
}

#[tokio::test]
async fn test_update_coordinator() {
    let client = Client::new();
    // Spawn the server and wait for its startup
    let handle = spawn_rocket_server().await;
    time::sleep(Duration::from_millis(1000)).await;

    // Ok
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    requests::get_update(&client, &mut url).await.unwrap();

    // Drop the server
    handle.abort();
}

#[tokio::test]
async fn test_get_tasks_left() {
    let client = Client::new();
    // Spawn the server and wait for its startup
    let handle = spawn_rocket_server().await;
    time::sleep(Duration::from_millis(1000)).await;

    // Non-existing contributor key
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::get_tasks_left(&client, &mut url, &String::from(UNKNOWN_CONTRIBUTOR_PUBLIC_KEY)).await;
    assert!(response.is_err());

    // Ok no tasks left
    let response = requests::get_tasks_left(&client, &mut url, &String::from(CONTRIBUTOR_1_PUBLIC_KEY))
        .await
        .unwrap();
    assert!(response.is_empty());

    // Ok tasks left
    let response = requests::get_tasks_left(&client, &mut url, &String::from(CONTRIBUTOR_2_PUBLIC_KEY))
        .await
        .unwrap();
    assert_eq!(response.len(), 1);

    // Drop the server
    handle.abort();
}

#[tokio::test]
async fn test_join_queue() {
    let client = Client::new();
    // Spawn the server and wait for its startup
    let handle = spawn_rocket_server().await;
    time::sleep(Duration::from_millis(1000)).await;

    // Ok request
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    requests::post_join_queue(&client, &mut url, &String::from(CONTRIBUTOR_1_PUBLIC_KEY))
        .await
        .unwrap();

    // Wrong request, already existing contributor
    let response = requests::post_join_queue(&client, &mut url, &String::from(CONTRIBUTOR_1_PUBLIC_KEY)).await;
    assert!(response.is_err());

    // Drop the server
    handle.abort();
}

/// Test wrong usage of contribute_chunk.
#[tokio::test]
async fn test_wrong_contribute_chunk() {
    let client = Client::new();
    // Spawn the server and wait for its startup
    let handle = spawn_rocket_server().await;
    time::sleep(Duration::from_millis(1000)).await;

    // Non-existing contributor key
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let contribute_request = ContributeChunkRequest::new(String::from(UNKNOWN_CONTRIBUTOR_PUBLIC_KEY), 0);

    let response = requests::post_contribute_chunk(&client, &mut url, &contribute_request).await;
    assert!(response.is_err());

    // Drop the server
    handle.abort();
}

/// To test a full contribution we need to test the 4 involved endpoints
/// (lock_chunk, get_chunk, post_contribution_chunk, contribute_chunk) sequentially.
#[tokio::test]
async fn test_contribution() {
    use phase1_coordinator::authentication::Dummy;
    use setup_utils::calculate_hash;

    let client = Client::new();
    // Spawn the server and wait for its startup
    let handle = spawn_rocket_server().await;
    time::sleep(Duration::from_millis(1000)).await;

    // Lock chunk
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::post_lock_chunk(&client, &mut url, &String::from(CONTRIBUTOR_1_PUBLIC_KEY)).await;
    let locked_locators: LockedLocators = response.unwrap();

    // Download chunk
    let chunk_request = GetChunkRequest::new(String::from(CONTRIBUTOR_1_PUBLIC_KEY), locked_locators);

    let response = requests::get_chunk(&client, &mut url, &chunk_request).await;
    let task: Task = response.unwrap();

    // Upload chunk
    let contribution_locator = ContributionLocator::new(ROUND_HEIGHT, task.chunk_id(), task.contribution_id(), false);

    let mut contribution: Vec<u8> = Vec::with_capacity(CONTRIBUTION_SIZE);

    // Set bytes 0..64 of contribution to be the hash of the challenge (hardcoded for now)
    let challenge_hash: [u8; 64] = [
        158, 167, 167, 94, 234, 132, 233, 197, 1, 148, 182, 205, 36, 136, 75, 54, 202, 188, 135, 189, 177, 222, 187,
        165, 159, 128, 163, 15, 86, 185, 122, 72, 126, 37, 93, 199, 216, 101, 191, 240, 140, 245, 71, 217, 225, 170,
        47, 76, 74, 27, 38, 64, 190, 181, 33, 94, 137, 255, 187, 144, 45, 114, 74, 232,
    ];
    contribution.extend_from_slice(&challenge_hash);

    // Fill the rest of contribution with random bytes
    let random: Vec<u8> = (64..CONTRIBUTION_SIZE).map(|_| rand::random::<u8>()).collect();
    contribution.extend_from_slice(&random);

    let contribution_file_signature_locator =
        ContributionSignatureLocator::new(ROUND_HEIGHT, task.chunk_id(), task.contribution_id(), false);

    let response_hash = calculate_hash(contribution.as_ref());

    let contribution_state = ContributionState::new(challenge_hash.to_vec(), response_hash.to_vec(), None).unwrap();

    let signature = Dummy
        .sign(
            String::from("private_key").as_str(),
            &contribution_state.signature_message().unwrap(),
        )
        .unwrap();

    let contribution_file_signature = ContributionFileSignature::new(signature, contribution_state).unwrap();

    let post_chunk = PostChunkRequest::new(
        contribution_locator,
        contribution,
        contribution_file_signature_locator,
        contribution_file_signature,
    );

    requests::post_chunk(&client, &mut url, &post_chunk).await.unwrap();

    // Contribute
    let contribute_request = ContributeChunkRequest::new(String::from(CONTRIBUTOR_1_PUBLIC_KEY), task.chunk_id());

    requests::post_contribute_chunk(&client, &mut url, &contribute_request)
        .await
        .unwrap();

    // Drop the server
    handle.abort();
}
