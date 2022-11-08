use phase1_coordinator::{
    authentication::Production as ProductionSig,
    io::{self, KeyPairUser},
    rest,
    rest_utils::{self, ResponseError, TOKENS_PATH, TOKENS_ZIP_FILE, UPDATE_TIME},
    s3::{S3Ctx, REGION},
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
use rand::Rng;
use rusoto_ssm::{Ssm, SsmClient};
use std::{convert::TryInto, io::Write, sync::Arc};

use tracing::{error, info, warn};

/// Periodically updates the [`Coordinator`]
async fn update_coordinator(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        tokio::time::sleep(UPDATE_TIME).await;

        info!("Updating coordinator...");
        match rest_utils::perform_coordinator_update(coordinator.clone()).await {
            Ok(_) => info!(
                "Update of coordinator completed, {:#?} to the next update round...",
                UPDATE_TIME
            ),
            Err(e) => {
                if let ResponseError::CoordinatorError(phase1_coordinator::CoordinatorError::CeremonyIsOver) = e {
                    // Return Ok to initialize shutdown process in select! expression
                    return Ok(());
                } else {
                    return Err(e.into());
                }
            }
        }
    }
}

/// Periodically verifies the pending contributions. Pending contributions are added to the queue by the try_contribute function,
/// no need to call an update on the coordinator.
/// NOTE: a possible improvement could be to perform the verification when the try_contribute function gets called, allowing us to remove this task and
/// speed up the verification process. This would also allow us to immediately provide to a client the state of validity of its contribution. This improvement could
/// be possible because we only have one contribution per round and one verifier (the coordinator's one). To implement this logic though, it would require a major rework of the phase1_coordinator logic.
async fn verify_contributions(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        tokio::time::sleep(UPDATE_TIME).await;

        info!("Verifying contributions...");
        let start = std::time::Instant::now();
        rest_utils::perform_verify_chunks(coordinator.clone()).await?;
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
async fn download_tokens() -> Result<()> {
    let s3_ctx = S3Ctx::new().await?;
    let mut zip_file = std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(TOKENS_ZIP_FILE)?;
    zip_file.write_all(&s3_ctx.get_tokens().await?)?;

    let mut zip = zip::ZipArchive::new(zip_file)?;
    zip.extract(TOKENS_PATH.as_str())?;

    Ok(())
}

/// Generate the random secret to access reserved endpoints and exports it as env. Publish this secret to Amazon Parameter Store.
async fn generate_secret() -> Result<()> {
    let mut secret_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut secret_bytes[..]);
    let secret = hex::encode(secret_bytes);
    std::env::set_var("ACCESS_SECRET", &secret);

    let aws_client = SsmClient::new(REGION.clone());
    let put_request = rusoto_ssm::PutParameterRequest {
        allowed_pattern: None,
        data_type: Some("text".to_string()),
        description: Some("Endpoints secret".to_string()),
        key_id: None,
        name: "secret".to_string(),
        overwrite: Some(true),
        policies: None,
        tags: None,
        tier: None,
        type_: Some("SecureString".to_string()),
        value: secret.clone(),
    };
    aws_client.put_parameter(put_request).await?;

    Ok(())
}

/// Perform the steps to finalize the ceremony state before shut down
async fn finalize_state(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    info!("Performing last contribution verification (if any)...");
    if let Err(e) = rest_utils::perform_verify_chunks(coordinator.clone()).await {
        // Log any error without interrupting the shutdown procedure
        warn!("Ignoring error while performing last verification: {}", e);
    }

    info!("Performing last coordinator update...");
    if let Err(e) = rest_utils::perform_coordinator_update(coordinator.clone()).await {
        // Log any error without interrupting the shutdown procedure
        warn!("Ignoring error while performing last update: {}", e);
    }

    info!("Saving final coordinator state");
    coordinator.write().await.shutdown()?;

    Ok(())
}

/// Rocket main function using the [`tokio`] runtime
#[rocket::main]
pub async fn main() {
    let tracing_enable_color = std::env::var("RUST_LOG_COLOR").is_ok();
    tracing_subscriber::fmt().with_ansi(tracing_enable_color).init();
    print_env!(
        "AWS_S3_PROD",
        "AWS_S3_BUCKET",
        "AWS_S3_ENDPOINT",
        "NAMADA_MPC_IP_BAN",
        "NAMADA_MPC_TIMEOUT_SECONDS",
        "HEALTH_PATH",
        "NAMADA_TOKENS_PATH",
        "CEREMONY_START_TIMESTAMP",
        "TOKENS_FILE_PREFIX",
        "NAMADA_COHORT_TIME"
    );

    // Generate, publish and export the secret token
    //generate_secret().await.expect("Error while generating secret token"); FIXME: uncomment

    // Set the environment
    let keypair = tokio::task::spawn_blocking(|| io::generate_keypair(KeyPairUser::Coordinator))
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
    if std::fs::metadata(TOKENS_PATH.as_str()).is_err() {
        download_tokens().await.expect("Error while retrieving tokens");
    }

    // Initialize the coordinator
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
        rest::get_coordinator_state,
        rest::get_healthcheck,
        rest::update_cohorts
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
        rest::get_coordinator_state,
        rest::get_healthcheck,
        rest::update_cohorts
    ];

    let build_rocket = rocket::build()
        .mount("/", routes)
        .manage(coordinator.clone())
        .register("/", catchers![
            rest_utils::invalid_signature,
            rest_utils::unauthorized,
            rest_utils::missing_required_header,
            rest_utils::io_error,
            rest_utils::unprocessable_entity,
            rest_utils::mismatching_checksum,
            rest_utils::invalid_header
        ]);
    let ignite_rocket = build_rocket.ignite().await.expect("Coordinator server didn't ignite");
    let shutdown = ignite_rocket.shutdown();

    // Sleep until ceremony start time has been reached
    #[cfg(not(debug_assertions))]
    {
        let ceremony_start_time = {
            let timestamp_env = std::env::var("CEREMONY_START_TIMESTAMP").unwrap();
            let timestamp = timestamp_env.parse::<i64>().unwrap();
            time::OffsetDateTime::from_unix_timestamp(timestamp).unwrap()
        };

        let now = time::OffsetDateTime::now_utc();

        if now < ceremony_start_time {
            let delta = ceremony_start_time - now;
            info!("Waiting till ceremony start time to start the server");
            info!(
                "Ceremony start time (UTC): {}, time left: {}",
                ceremony_start_time, delta
            );
            tokio::time::sleep((delta).try_into().expect("Failed conversion of Duration")).await;
        }
    }

    info!("Booting up coordinator rest server");
    
    // Spawn task to update the coordinator periodically
    let mut update_handle = rocket::tokio::spawn(update_coordinator(up_coordinator));

    // Spawn task to verify the contributions periodically
    let mut verify_handle = rocket::tokio::spawn(verify_contributions(verify_coordinator));

    // Spawn Rocket server task
    let mut rocket_handle = rocket::tokio::spawn(ignite_rocket.launch());

    // let (a, b) = tokio::join!( FIXME: remove
    //     verify_handle,
    //     rocket_handle
    // );

    // Pass mutable refs to be able to manually abort the tasks when needed
    // NOTE: the passed-in futures are not cancel-safe per se. We enforce safety during the shutdown by means of the following three:
    //  - spawn_blocking functions: the async runtime cannot cancel these functions and so these run till they return
    //  - Arc<RwLock<Coordinator>>: all of the functions involved in the shutdown process require a write lock of the coordinator, so they cannot proceed
    //      until the previous function has released the lock
    //  - The involved spawn_blocking functions acquire a write lock for their entire duration, meaning no other function can be executed in parallel
    //  An alternative solution for a graceful shutdown would have been to implement a communication channel shared by the three tasks to notify the start
    //  of the shutdown preocedure and implement the cleanup logic in each of these functions
    tokio::select! {
        update_result = &mut update_handle => {
            match update_result.expect("Update task panicked") {
                Ok(()) => {
                    // Cohorts are over, terminate the ceremony
                    info!("Cohorts are over, notifying rest server to shut down...");   

                    // Cancel concurrent tasks
                    info!("Cancelling concurrent tasks...");
                    verify_handle.abort();
                    shutdown.notify();

                    // FIXME: channel

                    tokio::join!( //FIXME: handle
                        verify_handle,
                        rocket_handle
                    );

                    info!("Concurrent tasks terminated");

                    finalize_state(coordinator).await.expect("Failed ceremony state finalize");
                },
                Err(e) => error!("Update of Coordinator failed: {}", e),
            }
        },
        verify_result = &mut verify_handle => {
            match verify_result.expect("Verify task panicked") {
                Ok(()) => unreachable!(),
                Err(e) => error!("Verify of Coordinator failed: {}", e),
            }
        },
        rocket_result = &mut rocket_handle => {
            match rocket_result.expect("Rocket task panicked") {
                Ok(_) => {
                    // Rest server received shutdown signal, terminate the ceremony
                    info!("Rocket task completed, ending the ceremony...");

                    // Cancel concurrent tasks
                    info!("Cancelling concurrent tasks...");
                    verify_handle.abort();
                    update_handle.abort();

                    tokio::join!( //FIXME: handle
                        verify_handle,
                        update_handle
                    );
                    info!("Concurrent tasks terminated");
                    
                    finalize_state(coordinator).await.expect("Failed ceremony state finalize");
                },
                Err(e) => error!("Rocket failed: {}", e)
            }
        }
    }
}

// FIXME: run test and fmt
// FIXME: rebase 
