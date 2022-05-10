use phase1_coordinator::{authentication::Production as ProductionSig, environment::Parameters, rest, Coordinator};

#[cfg(debug_assertions)]
use phase1_coordinator::environment::Testing;

#[cfg(not(debug_assertions))]
use phase1_coordinator::environment::Production;

use rocket::{self, routes};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Rocket main function using the [`tokio`] runtime
#[rocket::main]
pub async fn main() {
    tracing_subscriber::fmt::init();

    // Set the environment
    let parameters = Parameters::TestAnoma {
        number_of_chunks: 1,
        power: 6,
        batch_size: 16,
    };

    #[cfg(debug_assertions)]
    let environment: Testing = {
        phase1_coordinator::testing::clear_test_storage(&Testing::from(parameters.clone()).into());
        Testing::from(parameters)
    };

    #[cfg(not(debug_assertions))]
    let environment: Production = Production::from(parameters);

    // Instantiate and start the coordinator
    let coordinator =
        Coordinator::new(environment.into(), Arc::new(ProductionSig)).expect("Failed to instantiate coordinator");
    let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(coordinator));

    let mut write_lock = coordinator.clone().write_owned().await;

    tokio::task::spawn_blocking(move || write_lock.initialize().expect("Initialization of coordinator failed!"))
        .await
        .expect("Initialization task panicked");

    // Launch Rocket REST server
    let build_rocket = rocket::build()
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
        ])
        .manage(coordinator);

    let ignite_rocket = match build_rocket.ignite().await {
        Ok(v) => v,
        Err(e) => {
            panic!("Coordinator server didn't ignite: {}", e);
        }
    };

    if let Err(e) = ignite_rocket.launch().await {
        panic!("Coordinator server didn't launch: {}", e);
    };
}
