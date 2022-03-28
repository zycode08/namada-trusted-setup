use std::sync::Arc;

use futures::executor::block_on;
use phase1::{ContributionMode, ProvingSystem};
use phase1_coordinator::{rest, environment::{Parameters, Settings, CurveKind, Development}, Coordinator, Participant, authentication::Dummy};
use rocket::{main, routes, local::blocking::Client, http::{ContentType, Status}, Rocket, Build};
use tokio::sync::RwLock;

/// Build the rocket server for testing with the proper configuration.
fn build_rocket() -> Rocket<Build> {
	let parameters = Parameters::Custom(Settings::new( //TODO: check these
		ContributionMode::Full,
		ProvingSystem::Groth16,
		CurveKind::Bls12_377,
		6,  /* power */
		16, /* batch_size */
		16, /* chunk_size */
	));

	let environment: Development = Development::from(parameters);

	// Instantiate the coordinator
	let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(
		Coordinator::new(environment.into(), Arc::new(Dummy)).unwrap(), //FIXME: proper signature?
	));

	let coordinator_copy = coordinator.clone();
	let mut cor = block_on(coordinator_copy.write());
	cor.add_to_queue(Participant::new_contributor("abcdef"), None, 10);
	cor.initialize().unwrap();

	rocket::build()
		.mount("/", routes![rest::join_queue, rest::lock_chunk, rest::get_chunk, rest::post_contribution_chunk, rest::contribute_chunk, rest::update_coordinator, rest::heartbeat, rest::get_tasks_left])// FIXME: imports these routes from server.rs
		.manage(coordinator)
}


// TODO: test passing wrong parameters to the requests

#[test]
fn test_heartbeat() {
	let client = Client::tracked(build_rocket()).expect("Invalid rocket instance");
	
	// Non-existing contributor key
	let mut req = client.post("/contributor/heartbeat");
	req = req.json(&String::from("jjjj"));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::InternalServerError);
	assert!(response.body().is_some());

	// Wrong request body format
	let mut req = client.post("/contributor/heartbeat");
	req = req.json(&1);
	let response = req.dispatch();
	assert_eq!(response.status(), Status::UnprocessableEntity);
	assert!(response.body().is_some());

	// Ok
	let mut req = client.post("/contributor/heartbeat");
	req = req.json(&String::from("abcdef"));
	let response = req.dispatch();
	assert_eq!(response.status(), Status::Ok);
	assert!(response.body().is_none());
}

#[test]
fn test_update_coordinator() {
	todo!();
}

#[test]
fn test_get_tasks_left() {
	todo!();
}

#[test]
fn test_contribute_chunk() {
	todo!();
}

#[test]
fn test_post_contribution_chunk() {
	todo!();
}

fn test_get_chunk() {
	todo!();
}

fn test_lock_chunk() {
	todo!();
}

fn test_join_queue() {
	todo!();
}
