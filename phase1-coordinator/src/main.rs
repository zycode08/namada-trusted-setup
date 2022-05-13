use phase1_coordinator::{
    authentication::Production as ProductionSig,
    environment::Parameters,
    rest::{self, UPDATE_TIME},
    Coordinator,
};

#[cfg(debug_assertions)]
use phase1_coordinator::environment::Testing;

#[cfg(not(debug_assertions))]
use phase1_coordinator::environment::Production;

use rocket::{
    self,
    routes,
    tokio::{self, sync::RwLock},
};

use anyhow::Result;
use std::sync::Arc;

use tracing::{error, info};

/// Constantly updates the [`Coordinator`] periodically
async fn update_coordinator(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        rest::perform_coordinator_update(coordinator.clone()).await?;

        tokio::time::sleep(UPDATE_TIME).await;
    }
}

/// Constantly verifies the pending contributions
async fn verify_contributions(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        rest::perform_verify_chunks(coordinator.clone()).await?;

        tokio::time::sleep(UPDATE_TIME).await;
    }
}

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
    let up_coordinator = coordinator.clone();
    let verify_coordinator = coordinator.clone();

    let mut write_lock = coordinator.clone().write_owned().await;

    tokio::task::spawn_blocking(move || write_lock.initialize().expect("Initialization of coordinator failed!"))
        .await
        .expect("Initialization task panicked");

    // Build Rocket REST server
    #[cfg(debug_assertions)]
    let routes = routes![
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
        rest::get_contributor_queue_status
    ];

    #[cfg(not(debug_assertions))]
    let routes = routes![
        rest::join_queue,
        rest::lock_chunk,
        rest::get_chunk,
        rest::get_challenge,
        rest::post_contribution_chunk,
        rest::contribute_chunk,
        rest::heartbeat,
        rest::get_tasks_left,
        rest::stop_coordinator,
        rest::get_contributor_queue_status
    ];

    let build_rocket = rocket::build().mount("/", routes).manage(coordinator);
    let ignite_rocket = build_rocket.ignite().await.expect("Coordinator server didn't ignite");

    // Spawn task to update the coordinator periodically
    let update_handle = rocket::tokio::spawn(update_coordinator(up_coordinator));

    // Spawn task to verify the contributions periodically
    let verify_handle = rocket::tokio::spawn(verify_contributions(verify_coordinator));

    // Spawn Rocket server task
    let rocket_handle = rocket::tokio::spawn(ignite_rocket.launch());

    tokio::select! {
        update_result = update_handle => {
            match update_result.expect("Update task panicked") {
                Ok(()) => info!("Update task completed"),
                Err(e) => error!("Update of Coordinator failed: {}", e),
            }
        },
        verify_result = verify_handle => {
            match verify_result.expect("Verify task panicked") {
                Ok(()) => info!("Verify task completed"),
                Err(e) => error!("Verify of Coordinator failed: {}", e),
            }
        },
        rocket_result = rocket_handle => {
            match rocket_result.expect("Rocket task panicked") {
                Ok(_) => info!("Rocket task completed"),
                Err(e) => error!("Rocket failed: {}", e)
            }
        }
    }
}
