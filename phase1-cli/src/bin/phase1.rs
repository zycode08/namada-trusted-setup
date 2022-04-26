use phase1_coordinator::{
    authentication::{Dummy, Signature},
    commands::Computation,
    objects::{round::LockedLocators, ContributionFileSignature, ContributionState, Task},
    rest::{ContributeChunkRequest, GetChunkRequest, PostChunkRequest},
    storage::ContributionLocator,
};
use reqwest::{Client, Url};

use crate::requests::RequestError;
use phase1_cli::{requests, ContributorOpt};
use setup_utils::calculate_hash;
use structopt::StructOpt;

use std::fs::File;
use std::io::{Read, Write};
use tracing::debug;

/*
fn compute_contribution_mock() -> Vec<u8> {
    //FIXME: remove and compute proper contribution
    let mut contribution: Vec<u8> = Vec::with_capacity(4576);

    // Set bytes 0..64 of contribution to be the hash of the challenge (hardcoded for now)
    contribution.extend_from_slice(&challenge_hash);
    // Fill the rest of contribution with random bytes
    let random: Vec<u8> = (64..4576).map(|_| rand::random::<u8>()).collect();
    contribution.extend_from_slice(&random);

    contribution
}
*/
fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = std::fs::metadata(&filename).expect("unable to read metadata");
    // let mut buffer = vec![0; metadata.len() as usize];
    let mut buffer = vec![0; 40_000];
    debug!("metadata file length {}", metadata.len());
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

fn compute_contribution(challenge: &Vec<u8>, challenge_hash: &Vec<u8>) -> Vec<u8> {
    let filename: String = String::from("response_challenge.params");
    let mut response_writer = File::create(&filename).unwrap();

    response_writer.write_all(challenge_hash.as_slice());

    Computation::contribute_test_masp_cli(&challenge, &mut response_writer);
    debug!("response writer {:?}", response_writer);

    get_file_as_byte_vec(&filename)
}

async fn do_contribute(client: &Client, coordinator: &mut Url, pubkey: String) -> Result<(), RequestError> {
    let locked_locators = requests::post_lock_chunk(client, coordinator, &pubkey).await?;
    let response_locator = locked_locators.next_contribution();
    let round_height = response_locator.round_height();
    let chunk_id = response_locator.chunk_id();
    let contribution_id = response_locator.contribution_id();

    let get_chunk_req = GetChunkRequest::new(pubkey.clone(), locked_locators.clone());
    let task = requests::get_chunk(client, coordinator, &get_chunk_req).await?;

    let challenge = requests::get_challenge(client, coordinator, &locked_locators).await?;
    debug!("challenge {:?}", challenge);
    let challenge_hash = calculate_hash(challenge.as_ref());
    debug!("challenge hash{:?}", challenge_hash);

    let contribution = compute_contribution(&challenge, challenge_hash.to_vec().as_ref());

    debug!("contribution length: {}", contribution.len());

    let contribution_state = ContributionState::new(
        challenge_hash.to_vec(),
        calculate_hash(contribution.as_ref()).to_vec(),
        None,
    )
    .unwrap();
    let signature = Dummy //FIXME: proper signature
        .sign(
            String::from("private_key").as_str(),
            &contribution_state.signature_message().unwrap(),
        )
        .unwrap();

    let contribution_file_signature = ContributionFileSignature::new(signature, contribution_state).unwrap();

    let post_chunk_req = PostChunkRequest::new(
        locked_locators.next_contribution(),
        contribution,
        locked_locators.next_contribution_file_signature(),
        contribution_file_signature,
    );
    requests::post_chunk(client, coordinator, &post_chunk_req).await?;

    let contribute_chunk_req = ContributeChunkRequest::new(pubkey.clone(), task.chunk_id());
    let contribution_locator = requests::post_contribute_chunk(client, coordinator, &contribute_chunk_req).await?;

    requests::post_heartbeat(client, coordinator, &pubkey).await?;

    Ok(())
}

async fn contribute(client: &Client, coordinator: &mut Url) {
    // FIXME: generate proper keypair and loop till finds a public key not known by the coordinator
    let pubkey = String::from("random public key 2");
    requests::post_join_queue(&client, coordinator, &pubkey).await.unwrap();

    let mut i = 0;
    loop {
        if i == 1 {
            //FIXME: just for testing, remove for production
            break;
        }
        // Update the coordinator
        if let Err(e) = requests::get_update(&client, coordinator).await {
            //FIXME: ignore this error and continue
            eprintln!("{}", e);
        }

        if let Err(e) = do_contribute(&client, coordinator, pubkey.clone()).await {
            eprintln!("{}", e);
            panic!();
        }

        i += 1;
    }
}

async fn close_ceremony(client: &Client, coordinator: &mut Url) {
    match requests::get_stop_coordinator(client, coordinator).await {
        Ok(()) => println!("Ceremony completed!"),
        Err(e) => eprintln!("{}", e),
    }
}

async fn verify_contributions(client: &Client, coordinator: &mut Url) {
    match requests::get_verify_chunks(client, coordinator).await {
        Ok(()) => println!("Verification of contributions completed!"),
        Err(e) => eprintln!("{}", e), // FIXME: what to do in this case? Stop coordinator?
    }
}

async fn update_coordinator(client: &Client, coordinator: &mut Url) {
    match requests::get_update(client, coordinator).await {
        Ok(()) => println!("Coordinator updated!"),
        Err(e) => eprintln!("{}", e),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opt = ContributorOpt::from_args();
    let client = Client::new();

    match opt {
        ContributorOpt::Contribute(mut url) => {
            //FIXME: share code
            contribute(&client, &mut url.coordinator).await;
        }
        ContributorOpt::CloseCeremony(mut url) => {
            close_ceremony(&client, &mut url.coordinator).await;
        }
        ContributorOpt::VerifyContributions(mut url) => {
            verify_contributions(&client, &mut url.coordinator).await;
        }
        ContributorOpt::UpdateCoordinator(mut url) => {
            update_coordinator(&client, &mut url.coordinator).await;
        }
    }
}
