use phase1_coordinator::{
    authentication::{KeyPair, Production, Signature},
    commands::Computation,
    objects::{ContributionFileSignature, ContributionState},
    rest::{ContributorStatus, PostChunkRequest, UPDATE_TIME},
    storage::Object,
    COORDINATOR_KEYPAIR_FILE,
};

use rand::Rng;
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

use chrono::{DateTime, Utc};

use base64;
use bs58;
use bip39::{Language, Mnemonic};

use rand::distributions::{Distribution, Uniform};
use regex::Regex;

use tokio::{task::JoinHandle, time};

use tracing::{debug, error, info};

const CONTRIBUTION_INFO_FILE: &str = "contribution.info";
const MNEMONIC_LEN: usize = 24;
const MNEMONIC_CHECK_LEN: usize = 3;

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

/// The datetimes of the contribution 
#[derive(Debug, Deserialize, Serialize)]
struct ContributionTimeStamps {
    // User starts the CLI
    start_contribution: DateTime<Utc>,
    // User has joined the queue
    joined_queue: DateTime<Utc>,
    // User has locked the challenge on the coordinator
    challenge_locked: DateTime<Utc>,
    // User has completed the download of the challenge
    challenge_downloaded: DateTime<Utc>,
    // User starts computation locally or downloads the file to another machine
    start_computation: DateTime<Utc>,
    // User finishes computation locally or uploads the file from another machine
    end_computation: DateTime<Utc>,
    // User attests that the file was uploaded correctly
    end_contribution: DateTime<Utc>
}

impl Default for ContributionTimeStamps {
    /// Generate a [`ContributionTimeStamps`] instance with all the timestamps 
    /// set to [`Utc::now`].
    fn default() -> Self {
        let timestamp = Utc::now();
        Self { start_contribution: timestamp, joined_queue: timestamp, challenge_locked: timestamp, challenge_downloaded: timestamp, start_computation: timestamp, end_computation: timestamp, end_contribution: timestamp }
    }
}

/// Summary info about the contribution. This data is supposed to be sent to the 
/// Coordinator and stored in a file
#[derive(Debug, Default, Deserialize, Serialize)]
struct ContributionInfo {
    // Name of the contributor
    full_name: Option<String>,
    // Email of the contributor
    email: Option<String>,
   // ed25519 public key, base64 encoded
    public_key: String,
   // User participates in incentivized program or not
   is_incentivized: bool,
   // User expresses his intent to participate or not in the contest for creative contributions
   is_contest_participant: bool,
   // User can choose to contribute on another machine
   is_another_machine: bool,
   // User can choose the default method to generate randomness or his own.
   is_own_seed_of_randomness: bool,
   // Round in which the contribution took place
   ceremony_round: u64,
   // Hash of the contribution run by masp-mpc, contained in the transcript
   contribution_hash: String,
   // FIXME: is this necessary? so other user can check the contribution hash against the public key?
   contribution_hash_signature: String,
   // Hash of the file saved on disk and sent to the coordinator
   contribution_file_hash: String, //FIXME: what's the difference with contribution_hash?
   // Signature of the contribution
   contribution_file_signature: String,
   // Some timestamps to get performance metrics of the ceremony
   timestamps: ContributionTimeStamps,
   // Signature of this struct
   contributor_info_signature: String
}

/// Helper function to get input from the user. Accept an optional [`Regex`] to
/// compare the answer to.
fn get_user_input(request: &str, expected: Option<&Regex>) -> Result<String> {
    let mut response = String::new();

    loop {
        println!("{}", request);
        std::io::stdin().read_line(&mut response)?;

        if expected.is_none() || expected.is_match(response) {
            break;
        }

        println!("Wrong answer format, please answer again");
    }

    Ok(response)
}

/// Asks the user for some questions to properly setup the contribution.
fn initialize_contribution() -> Result<ContributionInfo> {
    let mut contrib_info = ContributionInfo::default();
    println!("Welcome to the Namanda trusted setup ceremony!\nBefore starting, a couple of questions:");
    let incentivization  = get_user_input("Do you want to participate in the incentivised trusted setup? y/n", Some(&Regex::new(r"(?i)[yn]")?))?.to_lowercase();

    if incentivization == "y" {
        // Ask for personal info
        contrib_info.full_name = Some(get_user_input("Please enter your full name:", None)?);
        contrib_info.email = Some(get_user_input("Please enter your email address:", Some(&Regex::new(r".*@.*..*")?))?); //FIXME: regex
        contrib_info.is_incentivized = true;
    };

    if get_user_input("Do you want to take part in the contest? y/n", Some(&Regex::new(r"(?i)[yn]")?))?.to_lowercase() == "y" {
        contrib_info.is_contest_participant = true;
    };

    Ok(contrib_info)
}

/// Generates a new [`KeyPair`] from a mnemonic provided by the user
fn generate_keypair() -> Result<KeyPair> {
    // Request mnemonic to the user
    let mnemonic_str = get_user_input("Please provide a 24 words mnemonic for your keypair:", Some(&Regex::new(r"(?x)\w{24}")?))?;
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_str.trim()).map_err(|e| anyhow!("Error while parsing mnemonic string: {}", e))?; 

    if mnemonic.word_count() != MNEMONIC_LEN { //FIXME: remove if regex works
        return Err(anyhow!("Mnemonic is supposed to be 24 words in size"));
    }

    // // Check if the user has correctly stored the mnemonic FIXME: decomment
    // let mut rng = rand::thread_rng();
    // let uniform = Uniform::from(1..MNEMONIC_LEN);
    // let random_indexes: Vec<usize> = uniform.sample_iter(rng).take(MNEMONIC_CHECK_LEN).collect();

    // println!("Mnemonic verification step");
    // let mnemonic_slice: Vec<&'static str> = mnemonic.word_iter().collect();

    // for i in random_indexes {
    //    let response = get_user_input(format!("Enter the word at index {} of your mnemonic:", i).as_str(), Some(&Regex::new(r"\w")?))?;
 
    //     if response.trim() != mnemonic_slice[i - 1] {
    //         debug!("Expected: {}, answer: {}", mnemonic_slice[i - 1], response);
    //         return Err(anyhow!("Wrong answer!"));
    //     }
    // }

    // println!("Verification passed. Be sure to safely store your mnemonic phrase!");

    let seed = mnemonic.to_seed_normalized("");
    Ok(KeyPair::try_from_seed(&seed)?)
}

// FIXME: async operations on files?

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
        "anoma_contribution_round_{}_public_key_{}.params",
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

async fn do_contribute(client: &Client, coordinator: &mut Url, keypair: &KeyPair, contrib_info: &mut ContributionInfo) -> Result<()> {
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
    let mut challenge_writer = File::create(String::from(format!("anoma_challenge_round_{}.params", round_height)))?;
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
    debug!("Contribution hash is {}", pretty_hash!(&contribution_hash));
    debug!("Contribution length: {}", contribution.len());
    contrib_info.contribution_hash = String::from(contribution_hash); //FIXME: works?
    contrib_info.contribution_hash_signature = Production.sign(contrib_info.public_key.as_str(), contrib_info.contribution_hash.as_str())?;

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

    // Compute signature of info
    let serde_contrib_info = serde_json::to_value(contrib_info)?;
    serde_contrib_info["contributor_info_signature"].take();
    let serialized_contrib_info = serde_contrib_info.to_string();
    let contrib_info_signature = Production.sign(contrib_info.public_key.as_str(), serialized_contrib_info.as_str())?;
    contrib_info.contributor_info_signature = contrib_info_signature;

    // Write contribution summary file and send it to the Coordinator FIXME: complete
    fs::write(CONTRIBUTION_INFO_FILE, &serde_json::to_vec(&contrib_info)?);

    Ok(())
}

async fn contribute(client: &Client, coordinator: &mut Url, keypair: &KeyPair, heartbeat_handle: &JoinHandle<Result<()>>, &mut contrib_info: ContributionInfo,) {
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
                do_contribute(client, coordinator, keypair, &mut contrib_info).await.expect("Contribution failed");
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

            let keypair = tokio::task::spawn_blocking(generate_keypair).await.unwrap().expect("Error while generating the keypair");
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

            contribute(&client, &mut url.coordinator, &keypair, &heartbeat_handle, &mut contrib_info).await;
        }
        ContributorOpt::CloseCeremony(mut url) => {
            // FIXME: get keypair, ask for some of the words since the keypair is already stored in the executable  
            let keypair = serde_json::from_slice(&fs::read(COORDINATOR_KEYPAIR_FILE).expect("Unable to read file")).expect("Error while retrieving the keypair");
            close_ceremony(&client, &mut url.coordinator, &keypair).await;
        }
        #[cfg(debug_assertions)]
        ContributorOpt::VerifyContributions(mut url) => {
            // FIXME: get keypair
            let keypair = serde_json::from_slice(&fs::read(COORDINATOR_KEYPAIR_FILE).expect("Unable to read file")).expect("Error while retrieving the keypair");
            verify_contributions(&client, &mut url.coordinator, &keypair).await;
        }
        #[cfg(debug_assertions)]
        ContributorOpt::UpdateCoordinator(mut url) => {
            // FIXME: get keypair
            let keypair = serde_json::from_slice(&fs::read(COORDINATOR_KEYPAIR_FILE).expect("Unable to read file")).expect("Error while retrieving the keypair");
            update_coordinator(&client, &mut url.coordinator, &keypair).await;
        }
    }
}
