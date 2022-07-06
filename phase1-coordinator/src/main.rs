use phase1_coordinator::{
    authentication::Production as ProductionSig,
    io,
    rest::{self, UPDATE_TIME},
    Coordinator,
};

#[cfg(debug_assertions)]
use phase1_coordinator::environment::Testing;

#[cfg(not(debug_assertions))]
use phase1_coordinator::environment::Production;

use rocket::{
    self,
    fs::FileServer,
    routes,
    tokio::{self, sync::RwLock},
};

use anyhow::Result;
use std::sync::Arc;

use tracing::{error, info};

/// Periodically updates the [`Coordinator`]
async fn update_coordinator(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        tokio::time::sleep(UPDATE_TIME).await;

        rest::perform_coordinator_update(coordinator.clone()).await?;
    }
}

/// Periodically verifies the pending contributions
async fn verify_contributions(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        tokio::time::sleep(UPDATE_TIME).await;

        rest::perform_verify_chunks(coordinator.clone()).await?;
    }
}

/// Rocket main function using the [`tokio`] runtime
#[rocket::main]
pub async fn main() {
    let tracing_enable_color = std::env::var("RUST_LOG_COLOR").is_ok();
    tracing_subscriber::fmt().with_ansi(tracing_enable_color).init();

    // Get healthcheck file path
    let health_path = std::env::var("HEALTH_PATH").expect("Missing env variable HEALTH_PATH");

    // Get healthcheck file path
    let health_path = std::env::var("HEALTH_PATH").expect("Missing env variable HEALTH_PATH");

    // Set the environment
    let keypair = tokio::task::spawn_blocking(|| io::generate_keypair(false))
        .await
        .unwrap()
        .expect("Error while generating the keypair");

    #[cfg(debug_assertions)]
    let environment: Testing = {
        phase1_coordinator::testing::clear_test_storage(&Testing::default().into());
        Testing::new(&keypair)
    };

    #[cfg(not(debug_assertions))]
    let environment: Production = { Production::new(&keypair) };

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

    // FIXME: update endpoints
    // Build Rocket REST server
    #[cfg(debug_assertions)]
    let routes = routes![
        rest::join_queue,
        rest::lock_chunk,
        rest::get_challenge_url,
        rest::get_contribution_url,
        rest::contribute_chunk,
        rest::update_coordinator,
        rest::heartbeat,
        rest::stop_coordinator,
        rest::verify_chunks,
        rest::get_contributor_queue_status,
        rest::post_contribution_info,
        rest::get_contributions_info,
    ];

    #[cfg(not(debug_assertions))]
    let routes = routes![
        rest::join_queue,
        rest::lock_chunk,
        rest::get_challenge_url,
        rest::get_contribution_url,
        rest::contribute_chunk,
        rest::heartbeat,
        rest::stop_coordinator,
        rest::get_contributor_queue_status,
        rest::post_contribution_info,
        rest::get_contributions_info,
    ];

    let build_rocket = rocket::build()
        .mount("/", routes)
        .mount("/healthcheck", FileServer::from(health_path))
        .manage(coordinator);
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
