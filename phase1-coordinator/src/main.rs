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

        info!("Updating coordinator...");
        rest::perform_coordinator_update(coordinator.clone()).await?;
        info!("Update of coordinator completed, {:#?} to the next update of the coordinator...", UPDATE_TIME);
    }
}

/// Periodically verifies the pending contributions
async fn verify_contributions(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        tokio::time::sleep(UPDATE_TIME).await;

        info!("Verifying contributions...");
        let start = std::time::Instant::now();
        if let Err(e) = rest::perform_verify_chunks(coordinator.clone()).await {
            error!("Error in the contributions' verification step: {}", e);
            // FIXME: remove the last contribution to verify that caused the error because the coordinator doesn't do that and it stalls. Also need to restart the round and drop the participant
        }
        info!("Verification of contributions completed in {:#?}. {:#?} to the next verification round...", start.elapsed(), UPDATE_TIME);
    }
}

/// Checks and prints the env variables of interest for the ceremony
fn print_env() {
    info!("AWS_S3_BUCKET: {}", std::env::var("AWS_S3_BUCKET").unwrap_or("MISSING".to_string()));
    info!("AWS_S3_ENDPOINT: {}", std::env::var("AWS_S3_ENDPOINT").unwrap_or("MISSING".to_string()));
    info!("NAMADA_MPC_IP_BAN: {}", std::env::var("NAMADA_MPC_IP_BAN").unwrap_or("MISSING".to_string()));
    info!("HEALTH_PATH: {}", std::env::var("HEALTH_PATH").unwrap_or("MISSING".to_string()));
}

/// Rocket main function using the [`tokio`] runtime
#[rocket::main]
pub async fn main() {
    let tracing_enable_color = std::env::var("RUST_LOG_COLOR").is_ok();
    tracing_subscriber::fmt().with_ansi(tracing_enable_color).init();
    print_env();

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
