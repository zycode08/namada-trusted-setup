use phase1_coordinator::{
    authentication::Dummy,
    environment::{Development, Production, Parameters, Settings, CurveKind, ContributionMode, ProvingSystem},
    Coordinator,
    rest
};

use rocket::{self, routes};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Rocket main function using the [`tokio`] runtime
#[rocket::main]
pub async fn main() {
	// Set the environment

	// These parameters are to be exposed publicly to the REST API
	let parameters = Parameters::Custom(Settings::new( //TODO: update these
		ContributionMode::Full,
		ProvingSystem::Groth16,
		CurveKind::Bls12_377,
		6,  /* power */
		16, /* batch_size */
		16, /* chunk_size */
	));

    #[cfg(debug_assertions)]
	let environment: Development = Development::from(parameters);

    #[cfg(not(debug_assertions))]
	let environment: Production = Production::from(parameters);

	// Instantiate the coordinator
	let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(
		Coordinator::new(environment.into(), Arc::new(Dummy)).unwrap(), //TODO: proper signature
	));

    coordinator.write().await.initialize().unwrap();

    // Launch Rocket REST server
	let build_rocket = rocket::build()
		.mount("/", routes![rest::join_queue, rest::lock_chunk, rest::get_chunk, rest::post_contribution_chunk, rest::contribute_chunk, rest::update_coordinator, rest::heartbeat, rest::get_tasks_left])
		.manage(coordinator);

    
	let ignite_rocket = match build_rocket.ignite().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Coordinator server didn't ignite: {}", e);
            return;
        }
    };

	if let Err(e) = ignite_rocket.launch().await {
		eprintln!("Coordinator server didn't launch: {}", e);
        return;
	};
}
