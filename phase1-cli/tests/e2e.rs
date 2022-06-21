// NOTE: these tests must be run with --test-threads=1 due to the disk storage
//	being stored at the same path for all the test instances causing a conflict.
//	It could be possible to define a separate location (base_dir) for every test
//	but it's simpler to just run the tests sequentially.
//  NOTE: these test require the phase1radix files to be placed in the phase1-cli folder

use std::{io::Write, net::IpAddr, sync::Arc};

use phase1_coordinator::{
    authentication::{KeyPair, Production, Signature},
    commands::{Computation, RandomSource},
    environment::Testing,
    objects::{ContributionInfo, LockedLocators, Task},
    rest::{self, PostChunkRequest},
    storage::{ContributionLocator, ContributionSignatureLocator, Object},
    testing::coordinator,
    ContributionFileSignature,
    ContributionState,
    Coordinator,
    Participant,
};
use rocket::{
    routes,
    tokio::{
        self,
        sync::RwLock,
        task::JoinHandle,
        time::{self, Duration},
    },
    Error,
    Ignite,
    Rocket,
};

use phase1_cli::requests;
use reqwest::{Client, Url};

const COORDINATOR_ADDRESS: &str = "http://127.0.0.1:8000";
const ROUND_HEIGHT: u64 = 1;

struct TestParticipant {
    _inner: Participant,
    _address: IpAddr,
    keypair: KeyPair,
    locked_locators: Option<LockedLocators>,
}

struct TestCtx {
    contributors: Vec<TestParticipant>,
    unknown_participant: TestParticipant,
    coordinator: TestParticipant,
}

/// Launch the rocket server for testing with the proper configuration as a separate async Task.
async fn test_prelude() -> (TestCtx, JoinHandle<Result<Rocket<Ignite>, Error>>) {
    // Reset storage to prevent state conflicts between tests and initialize test environment
    let environment = coordinator::initialize_test_environment(&Testing::default().into());

    // Instantiate the coordinator
    let mut coordinator = Coordinator::new(environment, Arc::new(Production)).unwrap();

    let keypair1 = KeyPair::new();
    let keypair2 = KeyPair::new();
    let keypair3 = KeyPair::new();

    let contributor1 = Participant::new_contributor(keypair1.pubkey().as_ref());
    let contributor2 = Participant::new_contributor(keypair2.pubkey().as_ref());
    let unknown_contributor = Participant::new_contributor(keypair3.pubkey().as_ref());

    let coordinator_ip = IpAddr::V4("0.0.0.0".parse().unwrap());
    let contributor1_ip = IpAddr::V4("0.0.0.1".parse().unwrap());
    let contributor2_ip = IpAddr::V4("0.0.0.2".parse().unwrap());
    let unknown_contributor_ip = IpAddr::V4("0.0.0.3".parse().unwrap());

    coordinator.initialize().unwrap();
    let coordinator_keypair = KeyPair::custom_new(
        coordinator.environment().default_verifier_signing_key(),
        coordinator.environment().coordinator_verifiers()[0].address(),
    );

    let coord_verifier = TestParticipant {
        _inner: coordinator.environment().coordinator_verifiers()[0].clone(),
        _address: coordinator_ip,
        keypair: coordinator_keypair,
        locked_locators: None,
    };

    coordinator
        .add_to_queue(contributor1.clone(), Some(contributor1_ip), 10)
        .unwrap();
    coordinator
        .add_to_queue(contributor2.clone(), Some(contributor2_ip), 9)
        .unwrap();
    coordinator.update().unwrap();

    let (_, locked_locators) = coordinator.try_lock(&contributor1).unwrap();

    let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(coordinator));

    let build = rocket::build()
        .mount("/", routes![
            rest::join_queue,
            rest::lock_chunk,
            rest::get_chunk,
            rest::get_challenge,
            rest::post_contribution_chunk,
            rest::contribute_chunk,
            rest::update_coordinator,
            rest::heartbeat,
            rest::get_tasks_left,
            rest::stop_coordinator,
            rest::verify_chunks,
            rest::get_contributor_queue_status,
            rest::post_contribution_info,
            rest::get_contributions_info,
            rest::get_healthcheck
        ])
        .manage(coordinator);

    let ignite = build.ignite().await.unwrap();
    let handle = tokio::spawn(ignite.launch());

    let test_participant1 = TestParticipant {
        _inner: contributor1,
        _address: contributor1_ip,
        keypair: keypair1,
        locked_locators: Some(locked_locators),
    };
    let test_participant2 = TestParticipant {
        _inner: contributor2,
        _address: contributor2_ip,
        keypair: keypair2,
        locked_locators: None,
    };
    let unknown_participant = TestParticipant {
        _inner: unknown_contributor,
        _address: unknown_contributor_ip,
        keypair: keypair3,
        locked_locators: None,
    };

    let ctx = TestCtx {
        contributors: vec![test_participant1, test_participant2],
        unknown_participant,
        coordinator: coord_verifier,
    };

    (ctx, handle)
}

#[tokio::test]
async fn test_stop_coordinator() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    // Wrong, request from non-coordinator participant
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::get_stop_coordinator(&client, &mut url, &ctx.contributors[0].keypair).await;
    assert!(response.is_err());

    // Shut the server down
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::get_stop_coordinator(&client, &mut url, &ctx.coordinator.keypair).await;
    assert!(response.is_ok());

    // Try sending another request (server should be unreachable)
    let response = requests::get_stop_coordinator(&client, &mut url, &ctx.coordinator.keypair).await;

    match response {
        Ok(_) => panic!("Expected error"),
        Err(e) => match e {
            requests::RequestError::Client(_) => (),
            requests::RequestError::Server(_) => panic!("Expected client-side error"),
        },
    }

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn test_get_contributor_queue_status() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    // Non-existing contributor key
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::get_contributor_queue_status(&client, &mut url, &ctx.unknown_participant.keypair).await;
    match response.unwrap() {
        rest::ContributorStatus::Other => (),
        _ => panic!("Wrong ContributorStatus"),
    }

    // Ok
    let response = requests::get_contributor_queue_status(&client, &mut url, &ctx.contributors[0].keypair).await;
    match response.unwrap() {
        rest::ContributorStatus::Round => (),
        _ => panic!("Wrong ContributorStatus"),
    }

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn test_heartbeat() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    // Non-existing contributor key
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::post_heartbeat(&client, &mut url, &ctx.unknown_participant.keypair).await;
    assert!(response.is_err());

    // Ok
    requests::post_heartbeat(&client, &mut url, &ctx.contributors[0].keypair)
        .await
        .unwrap();

    // Drop the server
    handle.abort();
}

#[tokio::test]
async fn test_update_coordinator() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    // Wrong, request from non-coordinator
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    assert!(
        requests::get_update(&client, &mut url, &ctx.contributors[0].keypair)
            .await
            .is_err()
    );

    // Ok
    requests::get_update(&client, &mut url, &ctx.coordinator.keypair)
        .await
        .unwrap();

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn test_get_tasks_left() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    // Non-existing contributor key
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::get_tasks_left(&client, &mut url, &ctx.unknown_participant.keypair).await;
    assert!(response.is_err());

    // Ok tasks left
    let response = requests::get_tasks_left(&client, &mut url, &ctx.contributors[0].keypair)
        .await
        .unwrap();
    assert_eq!(response.len(), 1);

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn test_join_queue() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    // Ok request
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    requests::post_join_queue(&client, &mut url, &ctx.contributors[0].keypair)
        .await
        .unwrap();

    // Wrong request, already existing contributor
    let response = requests::post_join_queue(&client, &mut url, &ctx.contributors[0].keypair).await;
    assert!(response.is_err());

    // Drop the server
    handle.abort()
}

/// Test wrong usage of contribute_chunk.
#[tokio::test]
async fn test_wrong_contribute_chunk() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    // Non-existing contributor key
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::post_contribute_chunk(&client, &mut url, &ctx.unknown_participant.keypair, 0).await;
    assert!(response.is_err());

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn test_wrong_post_contribution_info() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    let contrib_info = ContributionInfo::default();

    // Non-existing contributor key
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();
    let response = requests::post_contribution_info(
        &client,
        &mut url,
        &ctx.unknown_participant.keypair,
        contrib_info.clone(),
    )
    .await;
    assert!(response.is_err());

    // Non-current-contributor participant
    let response =
        requests::post_contribution_info(&client, &mut url, &ctx.contributors[1].keypair, contrib_info).await;
    assert!(response.is_err());

    // Drop the server
    handle.abort()
}

/// To test a full contribution we need to test the 7 involved endpoints sequentially:
///
/// - get_chunk
/// - get_challenge
/// - post_contribution_chunk
/// - contribute_chunk
/// - verify_chunk
/// - post_contributor_info
/// - get_contributions_info
///
#[tokio::test]
async fn test_contribution() {
    use rand::Rng;
    use setup_utils::calculate_hash;

    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_millis(1000)).await;

    // Download chunk
    let mut url = Url::parse(COORDINATOR_ADDRESS).unwrap();

    let response = requests::get_chunk(
        &client,
        &mut url,
        &ctx.contributors[0].keypair,
        ctx.contributors[0].locked_locators.as_ref().unwrap(),
    )
    .await;
    let task: Task = response.unwrap();

    // Get challenge
    let challenge = requests::get_challenge(
        &client,
        &mut url,
        &ctx.contributors[0].keypair,
        ctx.contributors[0].locked_locators.as_ref().unwrap(),
    )
    .await
    .unwrap();

    // Upload chunk
    let contribution_locator = ContributionLocator::new(ROUND_HEIGHT, task.chunk_id(), task.contribution_id(), false);

    let challenge_hash = calculate_hash(challenge.as_ref());

    let mut contribution: Vec<u8> = Vec::new();
    contribution.write_all(challenge_hash.as_slice()).unwrap();
    let seed = RandomSource::Seed(rand::thread_rng().gen::<[u8; 32]>());
    Computation::contribute_test_masp(&challenge, &mut contribution, &seed);

    // Initial contribution size is 2332 but the Coordinator expect ANOMA_BASE_FILE_SIZE. Extend to this size with trailing 0s
    let contrib_size = Object::anoma_contribution_file_size(ROUND_HEIGHT, task.contribution_id());
    contribution.resize(contrib_size as usize, 0);

    let contribution_file_signature_locator =
        ContributionSignatureLocator::new(ROUND_HEIGHT, task.chunk_id(), task.contribution_id(), false);

    let response_hash = calculate_hash(contribution.as_ref());

    let contribution_state = ContributionState::new(challenge_hash.to_vec(), response_hash.to_vec(), None).unwrap();

    let sigkey = ctx.contributors[0].keypair.sigkey();
    let signature = Production
        .sign(sigkey, &contribution_state.signature_message().unwrap())
        .unwrap();

    let contribution_file_signature = ContributionFileSignature::new(signature, contribution_state).unwrap();

    let post_chunk = PostChunkRequest::new(
        contribution_locator,
        contribution,
        contribution_file_signature_locator,
        contribution_file_signature,
    );

    requests::post_chunk(&client, &mut url, &ctx.contributors[0].keypair, &post_chunk)
        .await
        .unwrap();

    // Contribute
    requests::post_contribute_chunk(&client, &mut url, &ctx.contributors[0].keypair, task.chunk_id())
        .await
        .unwrap();

    // Verify chunk
    requests::get_verify_chunks(&client, &mut url, &ctx.coordinator.keypair)
        .await
        .unwrap();

    // Post contribution info
    let mut contrib_info = ContributionInfo::default();
    contrib_info.full_name = Some(String::from("Test Name"));
    contrib_info.email = Some(String::from("test@mail.dev"));
    contrib_info.public_key = ctx.contributors[0].keypair.pubkey().to_owned();
    contrib_info.ceremony_round = ctx.contributors[0]
        .locked_locators
        .as_ref()
        .unwrap()
        .current_contribution()
        .round_height();
    contrib_info.try_sign(&ctx.contributors[0].keypair).unwrap();

    requests::post_contribution_info(&client, &mut url, &ctx.contributors[0].keypair, contrib_info)
        .await
        .unwrap();

    // Get contributions info
    let summary = requests::get_contributions_info(&client, &mut url)
        .await
        .unwrap();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].public_key(), ctx.contributors[0].keypair.pubkey());
    assert!(!summary[0].is_another_machine());
    assert!(!summary[0].is_own_seed_of_randomness());
    assert_eq!(summary[0].ceremony_round(), 1);

    // Drop the server
    handle.abort()
}
