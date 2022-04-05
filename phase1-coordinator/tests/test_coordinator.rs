use std::{sync::Arc, net::{IpAddr, SocketAddr}};

use futures::{executor::block_on, FutureExt};
use once_cell::sync::Lazy;
use phase1::{ContributionMode, ProvingSystem};
use phase1_coordinator::{rest::{self, ContributeChunkRequest, PostChunkRequest, ChunkRequest}, testing::coordinator, environment::{Parameters, Settings, CurveKind, Development, Testing}, Coordinator, Participant, authentication::Dummy, objects::{LockedLocators, Task}, storage::{ContributionLocator, ContributionSignatureLocator, Object, Locator}, ContributionState, ContributionFileSignature};
use rocket::{main, routes, local::blocking::Client, http::{ContentType, Status}, Rocket, Build};
use time::macros::datetime;
use tokio::sync::RwLock;
use phase1_coordinator::authentication::Signature;

// TODO: format files

// NOTE: these tests must be run with --test-threads=1 due to the disk storage
//	being stored at the same path for all the test instances causing a conflict.
//	It could be possible to define a separate location (base_dir) for every test
//	but it's simpler to just run the tests sequentially.

const CONTRIBUTOR_1_PUBLIC_KEY: &str = "abc";
const CONTRIBUTOR_2_PUBLIC_KEY: &str = "def";
const UNKNOWN_CONTRIBUTOR_PUBLIC_KEY: &str = "jjjj";
const CONTRIBUTOR_1_IP: &str = "0.0.0.1";
const CONTRIBUTOR_2_IP: &str = "0.0.0.2";
const UNKNOWN_CONTRIBUTOR_IP: &str = "0.0.0.3";
const CONTRIBUTION_SIZE: usize = 4576;
const ROUND_HEIGHT: u64 = 1;

/// Build the rocket server for testing with the proper configuration.
fn build_rocket() -> Rocket<Build> {
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
	let number_of_chunks = environment.number_of_chunks() as usize;
	
	// Instantiate the coordinator
	let mut coordinator = Coordinator::new(environment, Arc::new(Dummy)).unwrap();

	let contributor1 = Participant::new_contributor(CONTRIBUTOR_1_PUBLIC_KEY);
	let contributor2 = Participant::new_contributor(CONTRIBUTOR_2_PUBLIC_KEY);

	let contributor1_ip = IpAddr::V4(CONTRIBUTOR_1_IP.parse().unwrap());
	let contributor2_ip = IpAddr::V4(CONTRIBUTOR_2_IP.parse().unwrap());

	coordinator.initialize().unwrap();

	coordinator.add_to_queue(contributor1, Some(contributor1_ip), 10).unwrap();
	coordinator.add_to_queue(contributor2.clone(), Some(contributor2_ip), 9).unwrap();
	coordinator.update();

	coordinator.try_lock(&contributor2).unwrap();

	let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(
		coordinator,
	));

	rocket::build()
		.mount("/", routes![rest::join_queue, rest::lock_chunk, rest::get_chunk, rest::post_contribution_chunk, rest::contribute_chunk, rest::update_coordinator, rest::heartbeat, rest::get_tasks_left])
		.manage(coordinator)
}

#[test]
fn test_heartbeat() {
	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");

	// Wrong reuqest, non-json body
	let mut req = client.post("/contributor/heartbeat");
	req = req.header(ContentType::Text).body("Wrong parameter type");
	let response = req.dispatch();
	assert_eq!(response.status(), Status::NotFound);
	assert!(response.body().is_some());

	// Wrong request body format
	let mut req = client.post("/contributor/heartbeat");
	req = req.json(&1);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::UnprocessableEntity);
	assert!(response.body().is_some());

	// Non-existing contributor key
	let mut req = client.post("/contributor/heartbeat");
	req = req.json(&String::from(UNKNOWN_CONTRIBUTOR_PUBLIC_KEY));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::InternalServerError);
	assert!(response.body().is_some());

	// Ok
	let mut req = client.post("/contributor/heartbeat");
	req = req.json(&String::from(CONTRIBUTOR_1_PUBLIC_KEY));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_none());
}

#[test]
fn test_update_coordinator() {
	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");

	// Non-empty body, Ok ignore the body
	let mut req = client.get("/update");
	req = req.json(&String::from("unexpected body"));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_none());

	// Ok
	let mut req = client.get("/update");
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_none());
}

#[test]
fn test_get_tasks_left() {
	use std::collections::LinkedList;

	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");

	// Wrong reuqest, non-json body
	let mut req = client.get("/contributor/get_tasks_left");
	req = req.header(ContentType::Text).body("Wrong parameter type");
	let response = req.dispatch();
	assert_eq!(response.status(), Status::BadRequest);
	assert!(response.body().is_some());

	// Wrong request json body format
	let mut req = client.get("/contributor/get_tasks_left");
	req = req.json(&true);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::UnprocessableEntity);
	assert!(response.body().is_some());

	// Non-existing contributor key
	let mut req = client.get("/contributor/get_tasks_left");
	req = req.json(&String::from(UNKNOWN_CONTRIBUTOR_PUBLIC_KEY));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::InternalServerError);
	assert!(response.body().is_some());

	// Ok no tasks left
	let mut req = client.get("/contributor/get_tasks_left");
	req = req.json(&String::from(CONTRIBUTOR_1_PUBLIC_KEY));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_some());
	let list: LinkedList<Task> = response.into_json().unwrap();
	assert_eq!(list.len(), 0);

	// Ok tasks left
	let mut req = client.get("/contributor/get_tasks_left");
	req = req.json(&String::from(CONTRIBUTOR_2_PUBLIC_KEY));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_some());
	let list: LinkedList<Task> = response.into_json().unwrap();
	assert_eq!(list.len(), 1);
}

#[test]
fn test_join_queue() {
	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");
	let socket_address = SocketAddr::new(IpAddr::V4(CONTRIBUTOR_1_IP.parse().unwrap()), 8080);

	// Wrong request, non-json body
	let mut req = client.post("/contributor/join_queue");
	req = req.header(ContentType::Text).body("Wrong parameter type").remote(socket_address);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::NotFound);
	assert!(response.body().is_some());

	// Wrong request json body format
	let mut req = client.post("/contributor/join_queue");
	req = req.json(&1u8).remote(socket_address);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::UnprocessableEntity);
	assert!(response.body().is_some());

	// Ok request
	let mut req = client.post("/contributor/join_queue");
	req = req.json(&String::from(CONTRIBUTOR_1_PUBLIC_KEY)).remote(socket_address);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_none());

	// Ok request, different contributor, same ip
	let mut req = client.post("/contributor/join_queue");
	req = req.json(&String::from(UNKNOWN_CONTRIBUTOR_IP)).remote(socket_address);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_none());

	// Wrong request, already existing contributor
	let mut req = client.post("/contributor/join_queue");
	req = req.json(&String::from(CONTRIBUTOR_1_PUBLIC_KEY)).remote(socket_address);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::InternalServerError);
	assert!(response.body().is_some());
}

/// Test wrong usge of lock_chunk.
#[test]
fn test_wrong_lock_chunk() {
	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");

	// Wrong request, non-json body
	let mut req = client.post("/contributor/lock_chunk");
	req = req.header(ContentType::Text).body("Wrong parameter type");
	let response = req.dispatch();
	assert_eq!(response.status(), Status::NotFound);
	assert!(response.body().is_some());

	// Wrong request json body format
	let mut req = client.post("/contributor/lock_chunk");
	req = req.json(&1);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::UnprocessableEntity);
	assert!(response.body().is_some());
}

/// Test wrong usage of get_chunk.
#[test]
fn test_wrong_get_chunk() {
	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");

	// Wrong request, non-json body
	let mut req = client.get("/download/chunk");
	req = req.header(ContentType::Text).body("Wrong parameter type");
	let response = req.dispatch();
	assert_eq!(response.status(), Status::BadRequest);
	assert!(response.body().is_some());

	// Wrong request json body format
	let mut req = client.get("/download/chunk");
	req = req.json(&String::from("Unexpected string"));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::UnprocessableEntity);
	assert!(response.body().is_some());
}

/// Test wrong usage of post_contribution_chunk.
#[test]
fn test_wrong_post_contribution_chunk() {
	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");

	// Wrong request, non-json body
	let mut req = client.post("/upload/chunk");
	req = req.header(ContentType::Text).body("Wrong parameter type");
	let response = req.dispatch();
	assert_eq!(response.status(), Status::NotFound);
	assert!(response.body().is_some());

	// Wrong request json body format
	let mut req = client.post("/upload/chunk");
	req = req.json(&String::from("Unexpected string"));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::UnprocessableEntity);
	assert!(response.body().is_some());
}

/// Test wrong usage of contribute_chunk.
#[test]
fn test_wrong_contribute_chunk() {
	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");

	// Wrong request, non-json body
	let mut req = client.post("/contributor/contribute_chunk");
	req = req.header(ContentType::Text).body("Wrong parameter type");
	let response = req.dispatch();
	assert_eq!(response.status(), Status::NotFound);
	assert!(response.body().is_some());

	// Wrong request json body format
	let mut req = client.post("/contributor/contribute_chunk");
	req = req.json(&String::from("Unexpected string"));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::UnprocessableEntity);
	assert!(response.body().is_some());

	// Non-existing contributor key
	let contribute_request = ContributeChunkRequest {
		pubkey: String::from(UNKNOWN_CONTRIBUTOR_PUBLIC_KEY),
		chunk_id: 0
	};
	let mut req = client.post("/contributor/contribute_chunk");
	req = req.json(&contribute_request);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::InternalServerError);
	assert!(response.body().is_some());
}

/// To test a full contribution we need to test the 4 involved endpoints 
/// (lock_chunk, get_chunk, post_contribution_chunk, contribute_chunk) sequentially.
#[test]
fn test_contribution() {
	use phase1_coordinator::authentication::Dummy;
	use setup_utils::calculate_hash; 
	use futures::executor::block_on;

	let rocket = build_rocket();
	let coordinator: Arc<RwLock<Coordinator>> = rocket.state::<Arc<RwLock<Coordinator>>>().unwrap().to_owned();
	let client = Client::tracked(rocket).expect("Invalid rocket instance");

	// Lock chunk
	let mut req = client.post("/contributor/lock_chunk");
	req = req.json(&String::from(CONTRIBUTOR_1_PUBLIC_KEY));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_some());
	let locked_locators: LockedLocators = response.into_json().unwrap();

	// Download chunk
	let chunk_request = ChunkRequest {
		pubkey: String::from(CONTRIBUTOR_1_PUBLIC_KEY),
		locked_locators
	};
	let mut req = client.get("/download/chunk");
	req = req.json(&chunk_request);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_some());
	let task: Task = response.into_json().unwrap();

	// Upload chunk
	let contribution_locator = ContributionLocator::new(
		ROUND_HEIGHT,
		task.chunk_id(),
		task.contribution_id(),
		false
	);

	let mut contribution: Vec<u8> = Vec::with_capacity(CONTRIBUTION_SIZE);

	// Set bytes 0..64 of contribution to be the hash of the challenge (hardcoded for now)
	let challenge_hash: [u8; 64] = [158, 167, 167, 94, 234, 132, 233, 197, 1, 148, 182, 205, 36, 136, 75, 54, 202, 188, 135, 189, 177, 222, 187, 165, 159, 128, 163, 15, 86, 185, 122, 72, 126, 37, 93, 199, 216, 101, 191, 240, 140, 245, 71, 217, 225, 170, 47, 76, 74, 27, 38, 64, 190, 181, 33, 94, 137, 255, 187, 144, 45, 114, 74, 232
	];
	contribution.extend_from_slice(&challenge_hash);
	// Fill the rest of contribution with random bytes
	let random: Vec<u8> = (64..CONTRIBUTION_SIZE).map(|_| {rand::random::<u8>() }).collect();
	contribution.extend_from_slice(&random);

	let contribution_file_signature_locator = ContributionSignatureLocator::new(
		ROUND_HEIGHT,
		task.chunk_id(),
		task.contribution_id(),
		false
	);

	let response_hash = calculate_hash(contribution.as_ref());
	
	let contribution_state = ContributionState::new(
		challenge_hash.to_vec(),
		response_hash.to_vec(),
		None
	).unwrap();


	let signature = Dummy.sign(String::from("private_key").as_str(), &contribution_state.signature_message().unwrap()).unwrap();

	let contribution_file_signature = ContributionFileSignature::new(
		signature,
		contribution_state
	).unwrap();

	let post_chunk = PostChunkRequest {
		contribution_locator,
		contribution,
		contribution_file_signature_locator,
		contribution_file_signature,
	};

	let mut req = client.post("/upload/chunk");
	req = req.json(&post_chunk);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_none());

	// Contribute
	let contribute_request = ContributeChunkRequest {
		pubkey: String::from(CONTRIBUTOR_1_PUBLIC_KEY),
		chunk_id: task.chunk_id()
	};

	let mut req = client.post("/contributor/contribute_chunk");
	req = req.json(&contribute_request);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_some());
}
