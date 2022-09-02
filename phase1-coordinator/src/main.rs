use phase1_coordinator::{
    authentication::Production as ProductionSig,
    io,
    rest::{self, UPDATE_TIME},
    s3::S3Ctx,
    Coordinator,
};

#[cfg(debug_assertions)]
use phase1_coordinator::environment::Testing;

#[cfg(not(debug_assertions))]
use phase1_coordinator::environment::Production;

use rocket::{
    self,
    catchers,
    routes,
    tokio::{self, sync::RwLock},
};

use anyhow::Result;
use std::{io::Write, sync::Arc};

use tracing::{error, info};

/// Periodically updates the [`Coordinator`]
async fn update_coordinator(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        tokio::time::sleep(UPDATE_TIME).await;

        info!("Updating coordinator...");
        rest::perform_coordinator_update(coordinator.clone()).await?;
        info!(
            "Update of coordinator completed, {:#?} to the next update round...",
            UPDATE_TIME
        );
    }
}

/// Periodically verifies the pending contributions
async fn verify_contributions(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        tokio::time::sleep(UPDATE_TIME).await;

        info!("Verifying contributions...");
        let start = std::time::Instant::now();
        rest::perform_verify_chunks(coordinator.clone()).await?;
        info!(
            "Verification of contributions completed in {:#?}. {:#?} to the next verification round...",
            start.elapsed(),
            UPDATE_TIME
        );
    }
}

/// Checks and prints the env variables of interest for the ceremony
macro_rules! print_env {
    ($($env:expr),*) => {
        info!("ENV VARIABLES STATE:");
        $(info!(
            "{}: {}",
            $env,
            std::env::var($env).unwrap_or("MISSING".to_string())
        );)*
    };
}

/// Download tokens from S3, decompress and store them locally.
async fn download_tokens(tokens_path: &str) -> Result<()> {
    let s3_ctx = S3Ctx::new().await?;
    let mut zip_file = std::fs::File::options().read(true).write(true).open("tokens.zip")?;
    zip_file.write_all(&s3_ctx.get_tokens().await?)?;

    let mut zip = zip::ZipArchive::new(zip_file)?;
    zip.extract(tokens_path)?;

    Ok(())
}

/// Rocket main function using the [`tokio`] runtime
#[rocket::main]
pub async fn main() {
    let tracing_enable_color = std::env::var("RUST_LOG_COLOR").is_ok();
    tracing_subscriber::fmt().with_ansi(tracing_enable_color).init();
    print_env!(
        "AWS_S3_TEST",
        "AWS_S3_BUCKET",
        "AWS_S3_ENDPOINT",
        "NAMADA_MPC_IP_BAN",
        "NAMADA_MPC_TIMEOUT_SECONDS",
        "HEALTH_PATH",
        "NAMADA_TOKENS_PATH",
        "CEREMONY_START_TIMESTAMP",
        "NUMBER_OF_COHORTS",
        "TOKENS_FILE_PREFIX"
    );

    // Set the environment
    let tokens_path: String = std::env::var("NAMADA_TOKENS_PATH").unwrap_or_else(|_| "./tokens".to_string());
    let keypair = tokio::task::spawn_blocking(|| io::generate_keypair(true))
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

    // Download token file from S3, only if local folder is missing
    if std::fs::metadata(tokens_path.as_str()).is_err() {
        download_tokens(tokens_path.as_str())
            .await
            .expect("Error while retrieving tokens");
    }

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
        rest::get_healthcheck
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
        rest::get_healthcheck
    ];

    let build_rocket = rocket::build()
        .mount("/", routes)
        .manage(coordinator)
        .register("/", catchers![
            rest::invalid_signature,
            rest::unauthorized,
            rest::missing_required_header,
            rest::io_error,
            rest::unprocessable_entity,
            rest::mismatching_checksum,
            rest::invalid_header
        ]);
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
