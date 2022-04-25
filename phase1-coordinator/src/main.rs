use phase1_coordinator::{
    authentication::Production as ProductionSig,
    environment::{ContributionMode, CurveKind, Parameters, Production, ProvingSystem, Settings, Testing},
    rest,
    Coordinator,
};

use rocket::{self, routes};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Rocket main function using the [`tokio`] runtime
#[rocket::main]
pub async fn main() {
    tracing_subscriber::fmt::init();
    // Set the environment
    let parameters = Parameters::Custom(Settings::new(
        //FIXME: update these
        ContributionMode::Full,
        ProvingSystem::Groth16,
        CurveKind::Bls12_381,
        6,  /* power */
        16, /* batch_size */
        16, /* chunk_size */
    ));

    #[cfg(debug_assertions)]
    let environment: Testing = {
        phase1_coordinator::testing::clear_test_storage(&Testing::from(parameters.clone()).into());
        Testing::from(parameters)
    };

    #[cfg(not(debug_assertions))]
    let environment: Production = Production::from(parameters);

    // Instantiate and start the coordinator
    let mut coordinator =
        Coordinator::new(environment.into(), Arc::new(ProductionSig)).expect("Failed to instantiate coordinator");
    coordinator.initialize().expect("Initialization of coordinator failed!");

    let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(coordinator));

    // Launch Rocket REST server
    let build_rocket = rocket::build()
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
            rest::verify_chunks
        ])
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
    };
}
