use phase1_coordinator::{
    authentication::{KeyPair, Production, Signature},
    commands::Computation,
    io,
    objects::{ContributionFileSignature, ContributionState},
    rest::{ContributionInfo, ContributionTimeStamps, ContributorStatus, PostChunkRequest, UPDATE_TIME},
    storage::Object,
};

use reqwest::{Client, Url};

use anyhow::{anyhow, Result};
use phase1_cli::{requests, ContributorOpt};
use serde::{Deserialize, Serialize};
use serde_json;
use setup_utils::calculate_hash;
use structopt::StructOpt;

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write, BufWriter},
    time::Instant,
};

use chrono::Utc;

use base64;
use bs58;

use regex::Regex;

use tokio::{task::JoinHandle, time};

use tracing::{debug, error, info};

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

/// Asks the user a few questions to properly setup the contribution
fn initialize_contribution() -> Result<ContributionInfo> { //FIXME: test regex?
    let mut contrib_info = ContributionInfo::default();
    println!("Welcome to the Namada trusted setup ceremony!\nBefore starting, a couple of questions:");
    let incentivization  = io::get_user_input("Do you want to participate in the incentivised trusted setup? [y/n]", Some(&Regex::new(r"(?i)[yn]")?))?.to_lowercase();

    if incentivization == "y" {
        // Ask for personal info
        contrib_info.full_name = Some(io::get_user_input("Please enter your full name:", None)?);
        contrib_info.email = Some(io::get_user_input("Please enter your email address:", Some(&Regex::new(r".+[@].+[.].+")?))?);
        contrib_info.is_incentivized = true;
    };

    if io::get_user_input("Do you want to take part in the contest? [y/n]", Some(&Regex::new(r"(?i)[yn]")?))?.to_lowercase() == "y" {
        contrib_info.is_contest_participant = true;
    };

    Ok(contrib_info)
}

// FIXME: async operations on files? Try measuring performance

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
// FIXME: rename some functions
/// Generates randomness for the ceremony
fn compute_contribution(
    pubkey: &str,
    round_height: u64,
    challenge: &[u8],
    challenge_hash: &[u8],
    contribution_id: u64,
) -> Result<Vec<u8>> {
    // Pubkey contains special chars that aren't writable to the filename. Encode it in base58
    let base58_pubkey = bs58::encode(base64::decode(pubkey)?).into_string();
    let filename: String = String::from(format!(
        "namada_contribution_round_{}_public_key_{}.params",
        round_height, base58_pubkey
    ));
    let mut response_writer = File::create(filename.as_str())?;
    response_writer.write_all(&challenge_hash)?;

    let start = Instant::now();

    #[cfg(debug_assertions)]
    Computation::contribute_test_masp(&challenge, &mut response_writer);

    #[cfg(not(debug_assertions))]
    Computation::contribute_masp(&challenge, &mut response_writer);

    debug!("response writer {:?}", response_writer);
    println!("Completed contribution in {:?}", start.elapsed());

    Ok(get_file_as_byte_vec(filename.as_str(), round_height, contribution_id)?)
}

async fn do_contribute(client: &Client, coordinator: &mut Url, keypair: &KeyPair, mut contrib_info: ContributionInfo) -> Result<()> {
    let locked_locators = requests::post_lock_chunk(client, coordinator, keypair).await?;
    contrib_info.timestamps.challenge_locked = Utc::now();
    let response_locator = locked_locators.next_contribution();
    let round_height = response_locator.round_height();
    contrib_info.ceremony_round = round_height;
    let contribution_id = response_locator.contribution_id();

    let task = requests::get_chunk(client, coordinator, keypair, &locked_locators).await?;

    let challenge = requests::get_challenge(client, coordinator, keypair, &locked_locators).await?;
    contrib_info.timestamps.challenge_downloaded = Utc::now();

    // Saves the challenge locally, in case the contributor is paranoid and wants to double check himself
    let mut challenge_writer = File::create(String::from(format!("namada_challenge_round_{}.params", round_height)))?;
    challenge_writer.write_all(&challenge.as_slice())?;

    let challenge_hash = calculate_hash(challenge.as_ref());
    debug!("Challenge hash is {}", pretty_hash!(&challenge_hash));
    debug!("Challenge length {}", challenge.len());

    let keypair_owned = keypair.to_owned();
    contrib_info.timestamps.start_computation = Utc::now();
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
    contrib_info.timestamps.end_computation = Utc::now();

    let contribution_hash = calculate_hash(contribution.as_ref());
    let contribution_hash_str = pretty_hash!(&contribution_hash);
    debug!("Contribution hash is {}", contribution_hash_str);
    debug!("Contribution length: {}", contribution.len());
    contrib_info.contribution_hash = contribution_hash_str;
    contrib_info.contribution_hash_signature = Production.sign(keypair.sigkey(), contrib_info.contribution_hash.as_str())?;

    let contribution_state = ContributionState::new(
        challenge_hash.to_vec(),
        contribution_hash.to_vec(),
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
    contrib_info.timestamps.end_contribution = Utc::now();

    // FIXME: populate the missing fields of contrib if needed
    // Compute signature of info FIXME: remove if unused
    let mut serde_contrib_info = serde_json::to_value(contrib_info.clone())?;
    serde_contrib_info["contributor_info_signature"].take();
    let serialized_contrib_info = serde_contrib_info.to_string();
    let contrib_info_signature = Production.sign(keypair.sigkey(), serialized_contrib_info.as_str())?;
    contrib_info.contributor_info_signature = contrib_info_signature;

    // Write contribution summary file and send it to the Coordinator
    fs::write(format!("namada_contributor_info_round_{}.json", contrib_info.ceremony_round), &serde_json::to_vec(&contrib_info)?)?;
    requests::post_contribution_info(client, coordinator, keypair, contrib_info).await?;

    Ok(())
}

async fn contribute(client: &Client, coordinator: &mut Url, keypair: &KeyPair, heartbeat_handle: &JoinHandle<Result<()>>, mut contrib_info: ContributionInfo,) {
    requests::post_join_queue(client, coordinator, keypair)
        .await
        .expect("Couldn't join the queue");

    contrib_info.timestamps.joined_queue = Utc::now();

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
            }
            ContributorStatus::Round => {
                do_contribute(client, coordinator, keypair, contrib_info.clone()).await.expect("Contribution failed");
                // NOTE: need to manually cancel the heartbeat task because, by default, async runtimes use detach on drop strategy
                //  (see https://blog.yoshuawuyts.com/async-cancellation-1/#cancelling-tasks), meaning that the task
                //  only gets detached from the main execution unit but keeps running in the background until the main
                //  function returns. This would cause the contributor to send heartbeats even after it has been removed
                //  from the list of current contributors, causing an error
                heartbeat_handle.abort();
            }
            ContributorStatus::Finished => {
                println!("Contribution done!");
                break;
            }
            ContributorStatus::Other => {
                println!("Something went wrong!");
            }
        }

        // Get status updates
        time::sleep(UPDATE_TIME).await;
    }
}

async fn close_ceremony(client: &Client, coordinator: &mut Url, keypair: &KeyPair) {
    match requests::get_stop_coordinator(client, coordinator, keypair).await {
        Ok(()) => info!("Ceremony completed!"),
        Err(e) => error!("{}", e),
    }
}

async fn get_contributions(client: &Client, coordinator: &mut Url, keypair: &KeyPair) {
    match requests::get_contributions_info(client, coordinator, keypair).await {
        Ok(contributions) => info!("Contributions:\n{:#?}", contributions),
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
            let mut contrib_info = tokio::task::spawn_blocking(initialize_contribution).await.unwrap().expect("Error while initializing the contribution");
            contrib_info.timestamps.start_contribution = Utc::now();

            let keypair = tokio::task::spawn_blocking(io::generate_keypair).await.unwrap().expect("Error while generating the keypair");
            contrib_info.public_key = keypair.pubkey().to_string();

            // Spawn heartbeat task to prevent the Coordinator from
            // droppping the contributor out of the ceremony in the middle of a contribution.
            // Heartbeat is checked by the Coordinator every 120 seconds.
            let client_copy = client.clone();
            let mut coordinator_copy = url.coordinator.clone();
            let keypair_copy = keypair.clone();
            let heartbeat_handle =
                tokio::task::spawn(
                    async move { loop {
                        requests::post_heartbeat(&client_copy, &mut coordinator_copy, &keypair_copy).await?;
                
                        time::sleep(UPDATE_TIME).await;
                    } },
                );

            contribute(&client, &mut url.coordinator, &keypair, &heartbeat_handle, contrib_info).await;
        }
        ContributorOpt::CloseCeremony(mut url) => {
            let keypair = tokio::task::spawn_blocking(io::generate_keypair).await.unwrap().expect("Error while generating the keypair");
            close_ceremony(&client, &mut url.coordinator, &keypair).await;
        }
        ContributorOpt::GetContributions(mut url) => {
            let keypair = tokio::task::spawn_blocking(io::generate_keypair).await.unwrap().expect("Error while generating the keypair");
            get_contributions(&client, &mut url.coordinator, &keypair).await;
        }
        #[cfg(debug_assertions)]
        ContributorOpt::VerifyContributions(mut url) => {
            let keypair = tokio::task::spawn_blocking(io::generate_keypair).await.unwrap().expect("Error while generating the keypair");
            verify_contributions(&client, &mut url.coordinator, &keypair).await;
        }
        #[cfg(debug_assertions)]
        ContributorOpt::UpdateCoordinator(mut url) => {
            let keypair = tokio::task::spawn_blocking(io::generate_keypair).await.unwrap().expect("Error while generating the keypair");
            update_coordinator(&client, &mut url.coordinator, &keypair).await;
        }
    }
}
