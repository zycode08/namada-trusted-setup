use phase1_coordinator::{
    authentication::{KeyPair, Production, Signature},
    commands::Computation,
    objects::{round::LockedLocators, ContributionFileSignature, ContributionState, Task},
    rest::{ContributeChunkRequest, ContributorStatus, GetChunkRequest, PostChunkRequest},
    storage::{ContributionLocator, Object},
};

use reqwest::{Client, Url};

use crate::requests::RequestError;
use anyhow::Result;
use phase1_cli::{requests, ContributorOpt};
use setup_utils::calculate_hash;
use structopt::StructOpt;

use std::{
    fs::File,
    io::{Read, Write},
    time::{Duration, Instant},
};

use bs58;
use base64;

use tokio::time;

use tracing::{debug, error, info};

const TEN_SECONDS: Duration = Duration::from_secs(10);

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
    let filename: String = String::from(format!("anoma_contribution_round_{}_public_key_{}.params", round_height, base58_pubkey));
    let mut response_writer = File::create(filename.as_str())?;
    response_writer.write_all(challenge_hash);

    // TODO: add json file with the challenge hash, the contribution hash and the response hash (challenge_hash, contribution)
    let start = Instant::now();

    #[cfg(debug_assertions)]
    Computation::contribute_test_masp(challenge, &mut response_writer);

    #[cfg(not(debug_assertions))]
    Computation::contribute_masp(challenge, &mut response_writer);

    debug!("response writer {:?}", response_writer);
    println!("Completed contribution in {:?}", start.elapsed());

    Ok(get_file_as_byte_vec(filename.as_str(), round_height, contribution_id)?)
}

async fn do_contribute(client: &Client, coordinator: &mut Url, sigkey: &str, pubkey: &str) -> Result<()> {
    let locked_locators = requests::post_lock_chunk(client, coordinator, pubkey).await?;
    let response_locator = locked_locators.next_contribution();
    let round_height = response_locator.round_height();
    let contribution_id = response_locator.contribution_id();

    let get_chunk_req = GetChunkRequest::new(pubkey.to_owned(), locked_locators.clone());
    let task = requests::get_chunk(client, coordinator, &get_chunk_req).await?;

    let challenge = requests::get_challenge(client, coordinator, &locked_locators).await?;
    debug!("Challenge is {}", pretty_hash!(&challenge));

    // Saves the challenge locally, in case the contributor is paranoid and wants to double check himself
    let mut challenge_writer = File::create(String::from(format!("anoma_challenge_round_{}.params", round_height)))?;
    challenge_writer.write_all(challenge.as_slice());

    let challenge_hash = calculate_hash(challenge.as_ref());
    debug!("Challenge hash is {}", pretty_hash!(&challenge_hash));

    let contribution = compute_contribution(
        pubkey,
        round_height,
        &challenge,
        challenge_hash.to_vec().as_ref(),
        contribution_id,
    )?;

    debug!("Contribution length: {}", contribution.len());

    let contribution_state = ContributionState::new(
        challenge_hash.to_vec(),
        calculate_hash(contribution.as_ref()).to_vec(),
        None,
    )?;

    let signature = Production.sign(sigkey, &contribution_state.signature_message()?)?;

    let contribution_file_signature = ContributionFileSignature::new(signature, contribution_state)?;

    let post_chunk_req = PostChunkRequest::new(
        locked_locators.next_contribution(),
        contribution,
        locked_locators.next_contribution_file_signature(),
        contribution_file_signature,
    );
    requests::post_chunk(client, coordinator, &post_chunk_req).await?;

    let contribute_chunk_req = ContributeChunkRequest::new(pubkey.to_owned(), task.chunk_id());
    let contribution_locator = requests::post_contribute_chunk(client, coordinator, &contribute_chunk_req).await?;

    requests::post_heartbeat(client, coordinator, pubkey).await?;

    Ok(())
}

async fn contribute(client: &Client, coordinator: &mut Url) {
    let keypair = KeyPair::new();
    debug!("Contributor pubkey {}", keypair.pubkey());

    if let Err(e) = requests::post_join_queue(&client, coordinator, keypair.pubkey()).await {
        error!("{}", e); //FIXME: expect
        panic!();
    }

    loop {
        // For testing purposes only. this needs to be moved to the operator.
        // Update the coordinator
        if let Err(e) = requests::get_update(&client, coordinator).await { //FIXME: remove
            // Log this error and continue
            error!("{}", e);
        }

        // Check the contributor's position in the queue
        let queue_status = requests::get_contributor_queue_status(&client, coordinator, keypair.pubkey())
            .await
            .unwrap(); //FIXME: expect

        match queue_status {
            ContributorStatus::Queue(position, size) => println!(
                "Queue position: {}\nQueue size: {}\nEstimated waiting time: {} min",
                position,
                size,
                position * 2
            ),
            ContributorStatus::Round => {
                if let Err(e) = do_contribute(&client, coordinator, keypair.sigkey(), keypair.pubkey()).await {
                    eprintln!("{}", e);
                    panic!();
                }
            }
            ContributorStatus::Finished => {
                println!("Contribution done!");
                break;
            }
            ContributorStatus::Other => println!("Something went wrong!"),
        }

        // Get status updates each 10 seconds FIXME: use SLEEP_TIME  from main
        time::sleep(TEN_SECONDS).await;
    }
}

async fn close_ceremony(client: &Client, coordinator: &mut Url) {
    match requests::get_stop_coordinator(client, coordinator).await {
        Ok(()) => info!("Ceremony completed!"),
        Err(e) => error!("{}", e),
    }
}

async fn verify_contributions(client: &Client, coordinator: &mut Url) {
    match requests::get_verify_chunks(client, coordinator).await {
        Ok(()) => info!("Verification of pending contributions completed"),
        Err(e) => error!("{}", e), // FIXME: what to do in this case? Stop coordinator?
    }
}

#[cfg(debug_assertions)]
async fn update_coordinator(client: &Client, coordinator: &mut Url) {
    match requests::get_update(client, coordinator).await {
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
            contribute(&client, &mut url.coordinator).await;
        }
        ContributorOpt::CloseCeremony(mut url) => {
            close_ceremony(&client, &mut url.coordinator).await;
        }
        ContributorOpt::VerifyContributions(mut url) => {
            verify_contributions(&client, &mut url.coordinator).await;
        }
        #[cfg(debug_assertions)]
        ContributorOpt::UpdateCoordinator(mut url) => {
            update_coordinator(&client, &mut url.coordinator).await;
        }
    }
}
