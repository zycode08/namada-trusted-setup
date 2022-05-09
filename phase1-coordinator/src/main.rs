use phase1_coordinator::{authentication::Production as ProductionSig, environment::Parameters, rest, Coordinator};

#[cfg(debug_assertions)]
use phase1_coordinator::environment::Testing;

#[cfg(not(debug_assertions))]
use phase1_coordinator::environment::Production;

use rocket::{self, routes, tokio::{self, sync::RwLock, time::Duration}};

use std::sync::Arc;
use anyhow::Result;

#[cfg(debug_assertions)]
const SLEEP_TIME: Duration = Duration::from_secs(5);
#[cfg(not(debug_assertions))]
const SLEEP_TIME: Duration = Duration::from_secs(30);

/// Loops forever and updates the [`Coordinator`] periodically
async fn update_coordinator(coordinator: Arc<RwLock<Coordinator>>) -> Result<()> {
    loop {
        let mut write_lock = coordinator.clone().write_owned().await;
        tokio::task::spawn_blocking(move || write_lock.update()).await??;

        tokio::time::sleep(SLEEP_TIME).await;
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
    let mut coordinator =
        Coordinator::new(environment.into(), Arc::new(ProductionSig)).expect("Failed to instantiate coordinator");
    coordinator.initialize().expect("Initialization of coordinator failed!");

    let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(coordinator));
    let up_coordinator = coordinator.clone();

    // Build Rocket REST server
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
        ])
        .manage(coordinator);

    let ignite_rocket = build_rocket.ignite().await.expect("Coordinator server didn't ignite");

    // Spawn task to update the coordinator periodically
    let update_handle = rocket::tokio::spawn(update_coordinator(up_coordinator));

    // Spawn Rocket server task
    let rocket_handle = rocket::tokio::spawn(ignite_rocket.launch());

    tokio::select! {
        update_result = update_handle => {
            match update_result { //FIXME: export to function? Or to macro?
                Ok(inner) => {
                    match inner {
                        Ok(()) => println!("Update task completed"),
                        Err(e) => eprintln!("Update of Coordinator failed: {}", e),
                    }
                },
                Err(e) => eprintln!("Update task panicked! {}", e),
            }
        },
        rocket_result = rocket_handle => {
            match rocket_result {
                Ok(inner) => match inner {
                    Ok(()) => println!("Rocket task completed"),
                    Err(e) => eprintln!("Rocket failed: {}", e)
                },
                Err(e) => eprintln!("Rocket task panicked! {}", e),
            }
        }
    }   
    // FIXME: log with tracing
    // FIXME: let the update enpoint and request only in debug mode (conditional compilation) 
    // FIXME: resolve all FIXMEs
}
