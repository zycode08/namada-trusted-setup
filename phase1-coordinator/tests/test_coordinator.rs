// NOTE: these tests must be run with --test-threads=1 due to the disk storage
//	being stored at the same path for all the test instances causing a conflict.
//	It could be possible to define a separate location (base_dir) for every test
//	but it's simpler to just run the tests sequentially.
//  NOTE: these tests require the phase1radix files to be placed in the phase1-coordinator folder

use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use blake2::Digest;
use phase1_coordinator::{
    authentication::{KeyPair, Production, Signature},
    commands::{Computation, RandomSource},
    environment::Testing,
    objects::{ContributionInfo, LockedLocators, Task, TrimmedContributionInfo},
    rest::{
        self,
        ContributorStatus,
        PostChunkRequest,
        BODY_DIGEST_HEADER,
        CONTENT_LENGTH_HEADER,
        PUBKEY_HEADER,
        SIGNATURE_HEADER,
    },
    storage::{ContributionLocator, ContributionSignatureLocator, Object},
    testing::coordinator,
    ContributionFileSignature,
    ContributionState,
    Coordinator,
    Participant,
};
use rocket::{
    fs::FileServer,
    http::{ContentType, Header, Status},
    local::blocking::{Client, LocalRequest},
    routes,
    tokio::sync::RwLock,
    Build,
    Rocket,
};
use serde::Serialize;
use sha2::Sha256;
use tempfile::NamedTempFile;

const ROUND_HEIGHT: u64 = 1;

struct TestParticipant {
    _inner: Participant,
    address: IpAddr,
    keypair: KeyPair,
    locked_locators: Option<LockedLocators>,
}

struct TestCtx {
    rocket: Rocket<Build>,
    contributors: Vec<TestParticipant>,
    unknown_participant: TestParticipant,
    coordinator: TestParticipant,
}

/// Build the rocket server for testing with the proper configuration.
fn build_context() -> TestCtx {
    // Reset storage to prevent state conflicts between tests and initialize test environment
    let environment = coordinator::initialize_test_environment(&Testing::default().into());

    // Instantiate the coordinator
    let mut coordinator = Coordinator::new(environment, Arc::new(Production)).unwrap();

    let keypair1 = KeyPair::new();
    let keypair2 = KeyPair::new();
    let keypair3 = KeyPair::new();

    let contributor1 = Participant::new_contributor(keypair1.pubkey());
    let contributor2 = Participant::new_contributor(keypair2.pubkey());
    let unknown_contributor = Participant::new_contributor(keypair3.pubkey());

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
        address: coordinator_ip,
        keypair: coordinator_keypair,
        locked_locators: None,
    };

    coordinator
        .add_to_queue(contributor1.clone(), Some(contributor1_ip.clone()), 10)
        .unwrap();
    coordinator.update().unwrap();

    let (_, locked_locators) = coordinator.try_lock(&contributor1).unwrap();

    let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(coordinator));

    let rocket = rocket::build()
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
        ])
        .manage(coordinator);

    // Create participants
    let test_participant1 = TestParticipant {
        _inner: contributor1,
        address: contributor1_ip,
        keypair: keypair1,
        locked_locators: Some(locked_locators),
    };
    let test_participant2 = TestParticipant {
        _inner: contributor2,
        address: contributor2_ip,
        keypair: keypair2,
        locked_locators: None,
    };
    let unknown_participant = TestParticipant {
        _inner: unknown_contributor,
        address: unknown_contributor_ip,
        keypair: keypair3,
        locked_locators: None,
    };

    TestCtx {
        rocket,
        contributors: vec![test_participant1, test_participant2],
        unknown_participant,
        coordinator: coord_verifier,
    }
}

// FIXME: reduce code duplication

/// Add headers and optional body to the request
fn set_request<'a, T>(mut req: LocalRequest<'a>, keypair: &'a KeyPair, body: Option<&T>) -> LocalRequest<'a>
where
    T: Serialize,
{
    let mut msg = keypair.pubkey().to_owned();
    req.add_header(Header::new(PUBKEY_HEADER, keypair.pubkey().to_owned()));

    if let Some(body) = body {
        // Body digest
        let json_body = serde_json::to_string(body).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&json_body);
        let digest = base64::encode(hasher.finalize());
        msg = format!("{}{}{}", msg, json_body.len(), &digest);
        req.add_header(Header::new(BODY_DIGEST_HEADER, format!("sha-256={}", digest)));

        // Body length
        req.add_header(Header::new(CONTENT_LENGTH_HEADER, json_body.len().to_string()));

        // Attach json serialized body
        req.add_header(ContentType::JSON);
        req = req.body(&json_body);
    }

    // Sign request
    let signature = Production.sign(keypair.sigkey(), &msg).unwrap();
    req.add_header(Header::new(SIGNATURE_HEADER, signature));

    req
}

#[test]
fn test_stop_coordinator() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong, request from non-coordinator participant
    let mut req = client.get("/stop");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Shut the server down
    req = client.get("/stop");
    req = set_request::<()>(req, &ctx.coordinator.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());
}

#[test]
fn test_get_contributor_queue_status() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Non-existing contributor key
    let mut req = client.get("/contributor/queue_status");
    req = set_request::<()>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    match response.into_json::<ContributorStatus>().unwrap() {
        ContributorStatus::Other => (),
        _ => panic!("Wrong ContributorStatus"),
    }

    // Ok
    req = client.get("/contributor/queue_status");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    match response.into_json::<ContributorStatus>().unwrap() {
        ContributorStatus::Round => (),
        _ => panic!("Wrong ContributorStatus"),
    }
}

#[test]
fn test_heartbeat() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Non-existing contributor key
    let mut req = client.post("/contributor/heartbeat");
    req = set_request::<()>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());

    // Ok
    req = client.post("/contributor/heartbeat");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());
}

#[test]
fn test_update_coordinator() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong, request comes from normal contributor
    let mut req = client.get("/update");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Ok, request comes from coordinator itself
    req = client.get("/update");
    req = set_request::<()>(req, &ctx.coordinator.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());
}

#[test]
fn test_get_tasks_left() {
    use std::collections::LinkedList;

    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Non-existing contributor key
    let mut req = client.get("/contributor/get_tasks_left");
    req = set_request::<()>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());

    // Ok tasks left
    req = client.get("/contributor/get_tasks_left");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());
    let list: LinkedList<Task> = response.into_json().unwrap();
    assert_eq!(list.len(), 1);
}

#[test]
fn test_join_queue() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    let socket_address = SocketAddr::new(ctx.unknown_participant.address, 8080);

    // Ok request
    let mut req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<()>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());

    // Wrong request, IP already in queue
    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<()>(req, &ctx.contributors[1].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());

    // Wrong request, already existing contributor
    let socket_address = SocketAddr::new(IpAddr::V4("0.0.0.4".parse().unwrap()), 8080);
    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<()>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());
}

/// Test wrong usage of lock_chunk.
#[test]
fn test_wrong_lock_chunk() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, unknown participant
    let mut req = client.get("/contributor/lock_chunk");
    req = set_request::<u8>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());
}

/// Test wrong usage of get_chunk.
#[test]
fn test_wrong_get_chunk() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let mut req = client
        .post("/download/chunk")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());

    // Wrong request json body format
    req = client.post("/download/chunk");
    req = set_request::<String>(
        req,
        &ctx.contributors[0].keypair,
        Some(&String::from("Unexpected string")),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::UnprocessableEntity);
    assert!(response.body().is_some());
}

/// Test wrong usage of get_challenge.
#[test]
fn test_wrong_get_challenge() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let req = client
        .post("/contributor/challenge")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());
}

/// Test wrong usage of post_contribution_chunk.
#[test]
fn test_wrong_post_contribution_chunk() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let mut req = client
        .post("/upload/chunk")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());

    // Wrong request json body format
    req = client.post("/upload/chunk");
    req = set_request(
        req,
        &ctx.contributors[0].keypair,
        Some(&String::from("Unexpected string")),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::UnprocessableEntity);
    assert!(response.body().is_some());
}

/// Test wrong usage of contribute_chunk.
#[test]
fn test_wrong_contribute_chunk() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let mut req = client
        .post("/contributor/contribute_chunk")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());

    // Wrong request json body format
    req = client.post("/contributor/contribute_chunk");
    req = set_request(
        req,
        &ctx.unknown_participant.keypair,
        Some(&String::from("Unexpected string")),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::UnprocessableEntity);
    assert!(response.body().is_some());

    // Non-existing contributor key
    req = client.post("/contributor/contribute_chunk");
    req = set_request::<i32>(req, &ctx.unknown_participant.keypair, Some(&0));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());
}

#[test]
fn test_wrong_verify() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong, request from non-coordinator participant
    let mut req = client.get("/verify");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
}

#[test]
fn test_wrong_post_contribution_info() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let mut req = client
        .post("/contributor/contribution_info")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());

    // Wrong request json body format
    req = client.post("/contributor/contribution_info");
    req = set_request::<String>(
        req,
        &ctx.contributors[0].keypair,
        Some(&String::from("Unexpected string")),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::UnprocessableEntity);
    assert!(response.body().is_some());

    // Non-existing contributor key
    let contrib_info = ContributionInfo::default();
    req = client.post("/contributor/contribution_info");
    req = set_request::<ContributionInfo>(req, &ctx.unknown_participant.keypair, Some(&contrib_info));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Non-current-contributor participant
    let mut contrib_info = ContributionInfo::default();
    contrib_info.public_key = ctx.contributors[1].keypair.pubkey().to_owned();
    req = client.post("/contributor/contribution_info");
    req = set_request::<ContributionInfo>(req, &ctx.contributors[1].keypair, Some(&contrib_info));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
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
/// - join_queue with already contributed Ip
///
#[test]
fn test_contribution() {
    use setup_utils::calculate_hash;

    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Download chunk
    let locked_locators = ctx.contributors[0].locked_locators.as_ref().unwrap();
    let mut req = client.post("/download/chunk");
    req = set_request::<LockedLocators>(req, &ctx.contributors[0].keypair, Some(locked_locators));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());
    let task: Task = response.into_json().unwrap();

    // Get challenge
    req = client.post("/contributor/challenge");
    req = set_request::<LockedLocators>(req, &ctx.contributors[0].keypair, Some(locked_locators));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());
    let challenge: Vec<u8> = response.into_json().unwrap();

    // Upload chunk
    let contribution_locator = ContributionLocator::new(ROUND_HEIGHT, task.chunk_id(), task.contribution_id(), false);
    let challenge_hash = calculate_hash(challenge.as_ref());

    let mut contribution: Vec<u8> = Vec::new();
    contribution.write_all(challenge_hash.as_slice()).unwrap();
    let entropy = RandomSource::Entropy(String::from("entropy"));
    Computation::contribute_test_masp(&challenge, &mut contribution, &entropy);

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

    req = client.post("/upload/chunk");
    req = set_request::<PostChunkRequest>(req, &ctx.contributors[0].keypair, Some(&post_chunk));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());

    // Contribute
    req = client.post("/contributor/contribute_chunk");
    req = set_request::<u64>(req, &ctx.contributors[0].keypair, Some(&task.chunk_id()));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());

    // Verify chunk
    req = client.get("/verify");
    req = set_request::<()>(req, &ctx.coordinator.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());

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

    req = client.post("/contributor/contribution_info");
    req = set_request::<ContributionInfo>(req, &ctx.contributors[0].keypair, Some(&contrib_info));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());

    // Get contributions info
    req = client.get("/contribution_info");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());

    let summary: Vec<TrimmedContributionInfo> = response.into_json().unwrap();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].public_key(), ctx.contributors[0].keypair.pubkey());
    assert!(!summary[0].is_another_machine());
    assert!(!summary[0].is_own_seed_of_randomness());
    assert_eq!(summary[0].ceremony_round(), 1);

    // Join queue with already contributed Ip
    let socket_address = SocketAddr::new(ctx.contributors[0].address, 8080);

    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<()>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());
}
