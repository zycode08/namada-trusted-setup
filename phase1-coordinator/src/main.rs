use phase1_coordinator::{
    authentication::{Dummy, Signature},
    environment::{Development, Environment, Parameters},
    objects::{task::Task, LockedLocators, Participant},
    Coordinator,
};
use serde::{Deserialize, Serialize};
use tracing_subscriber;

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub struct LockResponse {
    /// The chunk id
    #[serde(alias = "chunkId")]
    pub chunk_id: u64,

    /// The contribution id
    #[serde(alias = "contributionId")]
    pub contribution_id: u64,

    /// Indicator if the chunk was locked
    pub locked: bool,

    /// The participant id related to the lock
    #[serde(alias = "participantId")]
    pub participant_id: String,

    /// The locator of the previous response
    #[serde(alias = "previousResponseLocator")]
    pub previous_response_locator: String,

    /// The locator of the challenge file that the participant will download
    #[serde(alias = "challengeLocator")]
    pub challenge_locator: String,

    /// The locator where the participant will upload their completed contribution.
    #[serde(alias = "responseLocator")]
    pub response_locator: String,

    #[serde(alias = "responseChunkId")]
    pub response_chunk_id: u64,

    #[serde(alias = "responseContributionId")]
    pub response_contribution_id: u64,
}

use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{sync::RwLock, task, time::sleep};
use tracing::*;

use rand::RngCore;

pub const SEED_LENGTH: usize = 32;
pub type Seed = [u8; SEED_LENGTH];

type PublicKey = String;
use once_cell::sync::Lazy;

pub type SigningKey = String;

/// Contributor ID 1 for testing purposes only.
pub static TEST_CONTRIBUTOR_ID_1: Lazy<Participant> =
    Lazy::new(|| Participant::Contributor("testing-coordinator-contributor-1".to_string()));
pub static TEST_CONTRIBUTOR_IP_1: Lazy<IpAddr> = Lazy::new(|| IpAddr::V4("0.0.0.1".parse().unwrap()));

/// Contributor ID 2 for testing purposes only.
pub static TEST_CONTRIBUTOR_ID_2: Lazy<Participant> =
    Lazy::new(|| Participant::Contributor("testing-coordinator-contributor-2".to_string()));
pub static TEST_CONTRIBUTOR_IP_2: Lazy<IpAddr> = Lazy::new(|| IpAddr::V4("0.0.0.2".parse().unwrap()));

fn instantiate_coordinator(environment: &Environment, signature: Arc<dyn Signature>) -> anyhow::Result<Coordinator> {
    Ok(Coordinator::new(environment.clone(), signature)?)
}

// 1. Join the ceremony queue.
async fn join_ceremony_queue(coordinator: &Arc<RwLock<Coordinator>>, contributor: Participant) -> anyhow::Result<()> {
    let contributor_ip = IpAddr::V4("0.0.0.1".parse().unwrap());
    Ok(coordinator
        .write()
        .await
        .add_to_queue(contributor, Some(contributor_ip), 10)?)
}

// 2. Lock a chunk in the ceremony.
async fn try_lock(coordinator: &Arc<RwLock<Coordinator>>, contributor: &Participant) -> LockedLocators {
    let (_chunk_id, locked_locators) = coordinator.write().await.try_lock(contributor).unwrap();
    locked_locators
}

// 3. Download a chunk from the coordinator, which should be contributed to upon receipt.
async fn download_chunk(
    coordinator: &Arc<RwLock<Coordinator>>,
    contributor: &Participant,
    locked_locators: LockedLocators,
) -> anyhow::Result<Task> {
    let response_locator = locked_locators.next_contribution();
    let round_height = response_locator.round_height();
    let chunk_id = response_locator.chunk_id();
    let contribution_id = response_locator.contribution_id();

    let response_task = Task::new(chunk_id, contribution_id);
    let info = coordinator
        .read()
        .await
        .state()
        .current_participant_info(contributor)
        .unwrap()
        .clone();

    if info.pending_tasks().is_empty() {
        // return Err(CoordinatorError::ContributorPendingTasksCannotBeEmpty(
        //     contributor.clone(),
        // ));
    }

    if !info
        .pending_tasks()
        .iter()
        .find(|pending_task| pending_task == &&response_task)
        .is_some()
    {
        // return Err(CoordinatorError::PendingTasksMustContainResponseTask { response_task });
    }

    Ok(response_task)
}

// 4. Process the chunk
async fn process_chunk(
    coordinator: &Arc<RwLock<Coordinator>>,
    contributor: &Participant,
    contributor_signing_key: &SigningKey,
    locked_locators: LockedLocators,
    seed: &Seed,
) -> () {
    let response_locator = locked_locators.next_contribution();
    let round_height = response_locator.round_height();
    let chunk_id = response_locator.chunk_id();
    let contribution_id = response_locator.contribution_id();
    let contribute = coordinator.write().await.run_computation(
        round_height,
        chunk_id,
        contribution_id,
        &contributor,
        &contributor_signing_key,
        &seed,
    );
    // if contribute.is_err() {
    //     println!(
    //         "Failed to run computation for chunk {} as contributor {:?}\n{}",
    //         chunk_id,
    //         &contributor,
    //         serde_json::to_string_pretty(&coordinator.read().await.current_round()?)?
    //     );
    //     contribute?;
    // }
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Set the environment.
    let environment: Environment = Development::from(Parameters::TestCustom {
        number_of_chunks: 1,
        power: 12,
        batch_size: 256,
    })
    .into();
    // use phase1_coordinator::environment::Production;
    // let environment: Environment = Production::from(Parameters::AleoInner).into();

    // Instantiate the coordinator.
    let coordinator: Arc<RwLock<Coordinator>> =
        Arc::new(RwLock::new(instantiate_coordinator(&environment, Arc::new(Dummy))?));

    let ceremony_coordinator = coordinator.clone();
    // Initialize the coordinator.
    ceremony_coordinator.write().await.initialize().unwrap();
    // 0. Setup Client side, generate keypairs
    // Client side: Create a participant public/private key
    // ...

    ceremony_coordinator.write().await.update().unwrap();
    // 1. Join the ceremony queue.
    let contributor_1 = Lazy::force(&TEST_CONTRIBUTOR_ID_1).clone();
    // join_ceremony_queue(&ceremony_coordinator, contributor_1.clone())
    //     .await
    //     .unwrap();
    ceremony_coordinator.write().await.update().unwrap();

    // 2. Lock a chunk in the ceremony.
    let locked_locators_1 = try_lock(&ceremony_coordinator, &contributor_1).await;
    ceremony_coordinator.write().await.update().unwrap();

    // 3. Download a chunk from the coordinator, which should be contributed to upon receipt.
    let response_task = download_chunk(&ceremony_coordinator, &contributor_1, locked_locators_1.clone());
    ceremony_coordinator.write().await.update().unwrap();

    // 4. Process the chunk
    let contributor_signing_key_1: SigningKey = "secret_key".to_string();
    let mut seed: Seed = [0; SEED_LENGTH];
    rand::thread_rng().fill_bytes(&mut seed[..]);
    process_chunk(
        &coordinator,
        &contributor_1,
        &contributor_signing_key_1,
        locked_locators_1.clone(),
        &seed,
    );
    ceremony_coordinator.write().await.update().unwrap();
    let response_locator = locked_locators_1.next_contribution();
    let round_height = response_locator.round_height();
    let chunk_id = response_locator.chunk_id();
    let _response = ceremony_coordinator
        .write()
        .await
        .try_contribute(&contributor_1, chunk_id)
        .unwrap();

    // Client side: call join_queue, response OK or Err
    // Server side:
    // let joined = coordinator
    // 	.write()
    // 	.await
    // 	.add_to_queue(contributor, Some(contributor), 10)
    // 	.unwrap();
    // Return joined: Bool

    // 2. Lock a chunk in the ceremony.
    // Client side: call try_lock, parameters: address, response: response_locator
    // Server side:
    // let (_chunk_id, locked_locators) = self.try_lock(contributor)?;
    // let response_locator = locked_locators.next_contribution();
    // Return response_locator: LockResponse

    // 3. Download a chunk from the coordinator, which should be contributed to upon receipt.
    // let round_height = response_locator.round_height();
    // let chunk_id = response_locator.chunk_id();
    // let contribution_id = response_locator.contribution_id();
    /*
     let ceremony = task::spawn(async move {
         // Initialize the coordinator.
         ceremony_coordinator.write().await.initialize().unwrap();

         // Initialize the coordinator loop.
         loop {
             // Run the update operation.
             if let Err(error) = ceremony_coordinator.write().await.update() {
                 error!("{}", error);
             }

             // Sleep for 10 seconds in between iterations.
             sleep(Duration::from_secs(10)).await;
             break;
         }
     });

     // Initialize the shutdown procedure.
     let shutdown_handler = {
         let shutdown_coordinator = coordinator.clone();
         task::spawn(async move {
             tokio::signal::ctrl_c()
                 .await
                 .expect("Error while waiting for shutdown signal");
             shutdown_coordinator
                 .write()
                 .await
                 .shutdown()
                 .expect("Error while shutting down");
         })
     };

     tokio::select! {
         _ = shutdown_handler => {
             println!("Shutdown completed first")
         }
         _ = ceremony => {
             println!("Ceremony completed first")
         }
     };
    */

    Ok(())
}
