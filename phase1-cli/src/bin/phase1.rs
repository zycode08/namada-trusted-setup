use phase1_coordinator::{
    authentication::{KeyPair, Production, Signature},
    commands::Computation,
    objects::{ContributionFileSignature, ContributionState},
    rest::{ContributorStatus, PostChunkRequest, UPDATE_TIME},
    storage::Object,
    COORDINATOR_KEYPAIR_FILE,
};

use reqwest::{Client, Url};

use anyhow::Result;
use phase1_cli::{requests, ContributorOpt};
use serde_json;
use setup_utils::calculate_hash;
use structopt::StructOpt;

use std::{
    fs::{self, File},
    io::{Read, Write},
    time::Instant,
};

use base64;
use bs58;

use tokio::time;

use tracing::{debug, error, info};

const CONTRIBUTOR_KEYPAIR_FILE: &str = "contributor.keypair";
const KEYPAIR_ERROR: &str = "Failed to retrieve keypair";

macro_rules! pretty_hash {
    ($hash:expr) => {{
        let mut output = format!("\n\n");
        for line in $hash.chunks(16) {
            output += "\t";
            for section in line.chunks(4) {
                for b in section {
                    output += &format!("{:02x}", b);
                }
                output += " ";
            }
            output += "\n";
        }
        output
    }};
}

/// Retrieve [`KeyPair`] from file if it exists, otherwise generates a new keypair
/// and store its json encoding into a file. The coordinator argument tells
/// whether the keypair of a coordinator or a contributor is requested (this
/// depends on the specific endpoint intended to be queried)
fn get_keypair(coordinator: bool) -> Result<KeyPair> {
    let path = if coordinator {
        COORDINATOR_KEYPAIR_FILE
    } else {
        CONTRIBUTOR_KEYPAIR_FILE
    };

    match fs::read(path) {
        Ok(keypair_str) => {
            info!("Found keypair file, retrieving key");
            Ok(serde_json::from_slice(&keypair_str)?)
        }
        Err(_) => {
            info!("Missing keypair file, generating new one");
            let keypair = KeyPair::new();
            debug!("Generated pubkey {}", keypair.pubkey());

            fs::write(path, &serde_json::to_vec(&keypair)?)?;
            Ok(keypair)
        }
    }
}

fn get_file_as_byte_vec(filename: &str, round_height: u64, contribution_id: u64) -> Result<Vec<u8>> {
    let mut f = File::open(filename)?;
    let metadata = std::fs::metadata(filename)?;

    let anoma_file_size: u64 = Object::anoma_contribution_file_size(round_height, contribution_id);
    let mut buffer = vec![0; anoma_file_size as usize];
    debug!(
        "anoma_contribution_file_size: round_height {}, contribution_id {}",
        round_height, contribution_id
    );
    debug!("metadata file length {}", metadata.len());
    f.read(&mut buffer)?;

    Ok(buffer)
}

fn compute_contribution(
    pubkey: &str,
    round_height: u64,
    challenge: &[u8],
    challenge_hash: &[u8],
    contribution_id: u64,
) -> Result<Vec<u8>> {
    // Pubkey contains special chars that aren't written to the filename. Encode it in base58
    let base58_pubkey = bs58::encode(base64::decode(pubkey)?).into_string();
    let filename: String = String::from(format!(
        "anoma_contribution_round_{}_public_key_{}.params",
        round_height, base58_pubkey
    ));
    let mut response_writer = File::create(filename.as_str())?;
    response_writer.write_all(&challenge_hash)?;

    // TODO: add json file with the challenge hash, the contribution hash and the response hash (challenge_hash, contribution)
    let start = Instant::now();

    #[cfg(debug_assertions)]
    Computation::contribute_test_masp(&challenge, &mut response_writer);

    #[cfg(not(debug_assertions))]
    Computation::contribute_masp(&challenge, &mut response_writer);

    debug!("response writer {:?}", response_writer);
    println!("Completed contribution in {:?}", start.elapsed());

    Ok(get_file_as_byte_vec(filename.as_str(), round_height, contribution_id)?)
}

async fn do_contribute(client: &Client, coordinator: &mut Url, keypair: &KeyPair) -> Result<()> {
    let locked_locators = requests::post_lock_chunk(client, coordinator, keypair).await?;
    let response_locator = locked_locators.next_contribution();
    let round_height = response_locator.round_height();
    let contribution_id = response_locator.contribution_id();

    let task = requests::get_chunk(client, coordinator, keypair, &locked_locators).await?;

    let challenge = requests::get_challenge(client, coordinator, keypair, &locked_locators).await?;
    // debug!("Challenge is {}", pretty_hash!(&challenge));

    // Saves the challenge locally, in case the contributor is paranoid and wants to double check himself
    let mut challenge_writer = File::create(String::from(format!("anoma_challenge_round_{}.params", round_height)))?;
    challenge_writer.write_all(&challenge.as_slice())?;

    let challenge_hash = calculate_hash(challenge.as_ref());
    debug!("Challenge hash is {}", pretty_hash!(&challenge_hash));
    debug!("Challenge length {}", challenge.len());

    let keypair_owned = keypair.to_owned();
    let contribution = tokio::task::spawn_blocking(move || {
        compute_contribution(
            keypair_owned.pubkey(),
            round_height,
            &challenge,
            challenge_hash.to_vec().as_ref(),
            contribution_id,
        )
    })
    .await??;

    let contribution_hash = calculate_hash(contribution.as_ref());
    debug!("Contribution hash is {}", pretty_hash!(&contribution_hash));
    debug!("Contribution length: {}", contribution.len());

    let contribution_state = ContributionState::new(
        challenge_hash.to_vec(),
        calculate_hash(contribution.as_ref()).to_vec(),
        None,
    )?;

    let signature = Production.sign(keypair.sigkey(), &contribution_state.signature_message()?)?;

    let contribution_file_signature = ContributionFileSignature::new(signature, contribution_state)?;

    let post_chunk_req = PostChunkRequest::new(
        locked_locators.next_contribution(),
        contribution,
        locked_locators.next_contribution_file_signature(),
        contribution_file_signature,
    );
    requests::post_chunk(client, coordinator, keypair, &post_chunk_req).await?;

    requests::post_contribute_chunk(client, coordinator, keypair, task.chunk_id()).await?;

    Ok(())
}

async fn contribute(client: &Client, coordinator: &mut Url, keypair: &KeyPair) {
    // NOTE: heartbeat may fail shortly before completing the contribution when the coordinator starts to aggregate
    //  the round beacause, at that moment, the contributor has already been moved out of the list of current contributors
    //  and therefore cannot heartbeat anymore. This would case the select! statement to stop the contribution
    //  process. To address this, different calls to [`requests::post_heartbeat`] have been placed around to send the
    //  heartbeat signal only when appropriate.
    requests::post_join_queue(client, coordinator, keypair)
        .await
        .expect("Couldn't join the queue");

    loop {
        // Check the contributor's position in the queue
        let queue_status = requests::get_contributor_queue_status(client, coordinator, keypair)
            .await
            .expect("Couldn't get the status of contributor");

        match queue_status {
            ContributorStatus::Queue(position, size) => {
                println!(
                    "Queue position: {}\nQueue size: {}\nEstimated waiting time: {} min",
                    position,
                    size,
                    position * 5
                );
                // Send heartbeat
                requests::post_heartbeat(client, coordinator, keypair).await.expect("Couldn't heartbeat");
            }
            ContributorStatus::Round => {
                // Spawn heartbeat task
                let client_copy = client.clone();
                let mut coordinator_copy = coordinator.clone();
                let keypair_copy = keypair.clone();
                let heartbeat_handle =
                    tokio::task::spawn(
                        async move { heartbeat(&client_copy, &mut coordinator_copy, &keypair_copy).await },
                    );

                // Spawn contribute task
                let client_copy = client.clone();
                let mut coordinator_copy = coordinator.clone();
                let keypair_copy = keypair.clone();
                let contribute_handle = tokio::task::spawn(async move {
                    do_contribute(&client_copy, &mut coordinator_copy, &keypair_copy).await
                });

                tokio::select! { //FIXME: handle this select
                    // heartbeat_result = heartbeat_handle => {
                    //     if let Err(e) = heartbeat_result.expect("Heartbeat task panicked") {
                    //         error!("Heartbeat failed: {}", e);
                    //     }
                    // },
                    contribute_result = contribute_handle => {
                        match contribute_result.expect("Contribute task panicked") {
                            Ok(()) => info!("Contribution task completed"),
                            Err(e) => error!("Contribution failed: {}", e),
                        }
                    }
                }
                // NOTE: need to manually cancel the task becasue, by default, async runtimes use detach on drop strategy
                //  (see here https://blog.yoshuawuyts.com/async-cancellation-1/#cancelling-tasks), meaning that the task
                //  only gets detached from the main execution unit but keeps running in the background until the main
                //  function returns
                heartbeat_handle.abort(); //FIXME:
            }
            ContributorStatus::Finished => {
                println!("Contribution done!");
                break;
            }
            ContributorStatus::Other => {
                println!("Something went wrong!");
                // Send heartbeat
                requests::post_heartbeat(client, coordinator, keypair).await.expect("Couldn't heartbeat");
            }
        }

        // Get status updates
        time::sleep(UPDATE_TIME).await;
    }
}

/// Periodically send an heartbeat signal to the Coordinator to prevent it from
/// droppping the contributor out of the ceremony in the middle of a contribution.
/// Heartbeat is checked by the Coordinator every 120 seconds.
async fn heartbeat(client: &Client, coordinator: &mut Url, keypair: &KeyPair) -> Result<()> {
    loop {
        info!("About to post heartbeat"); //FIXME: remove
        requests::post_heartbeat(client, coordinator, keypair).await?;
        info!("Posted heartbeat"); //FIXME: change to debug

        time::sleep(UPDATE_TIME).await;
    }
}

async fn close_ceremony(client: &Client, coordinator: &mut Url, keypair: &KeyPair) {
    match requests::get_stop_coordinator(client, coordinator, keypair).await {
        Ok(()) => info!("Ceremony completed!"),
        Err(e) => error!("{}", e),
    }
}

#[cfg(debug_assertions)]
async fn verify_contributions(client: &Client, coordinator: &mut Url, keypair: &KeyPair) {
    match requests::get_verify_chunks(client, coordinator, keypair).await {
        Ok(()) => info!("Verification of pending contributions completed"),
        Err(e) => error!("{}", e),
    }
}

#[cfg(debug_assertions)]
async fn update_coordinator(client: &Client, coordinator: &mut Url, keypair: &KeyPair) {
    match requests::get_update(client, coordinator, keypair).await {
        Ok(()) => info!("Coordinator updated"),
        Err(e) => error!("{}", e),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opt = ContributorOpt::from_args();
    let client = Client::new();

    match opt {
        ContributorOpt::Contribute(mut url) => {
            let keypair = get_keypair(false).expect(KEYPAIR_ERROR);
            contribute(&client, &mut url.coordinator, &keypair).await;
        }
        ContributorOpt::CloseCeremony(mut url) => {
            let keypair = get_keypair(true).expect(KEYPAIR_ERROR);
            close_ceremony(&client, &mut url.coordinator, &keypair).await;
        }
        #[cfg(debug_assertions)]
        ContributorOpt::VerifyContributions(mut url) => {
            let keypair = get_keypair(true).expect(KEYPAIR_ERROR);
            verify_contributions(&client, &mut url.coordinator, &keypair).await;
        }
        #[cfg(debug_assertions)]
        ContributorOpt::UpdateCoordinator(mut url) => {
            let keypair = get_keypair(true).expect(KEYPAIR_ERROR);
            update_coordinator(&client, &mut url.coordinator, &keypair).await;
        }
    }
}
