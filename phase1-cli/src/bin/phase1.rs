use phase1_coordinator::{
    authentication::{Dummy, Signature},
    objects::{round::LockedLocators, ContributionFileSignature, ContributionState, Task},
    rest::{ContributeChunkRequest, GetChunkRequest, PostChunkRequest},
    storage::ContributionLocator,
};
use reqwest::{Client, Url};

use crate::requests::RequestError;
use phase1_cli::{requests, ContributorOpt};
use setup_utils::calculate_hash;
use structopt::StructOpt;

const challenge_hash: [u8; 64] = [
    //FIXME: remove
    158, 167, 167, 94, 234, 132, 233, 197, 1, 148, 182, 205, 36, 136, 75, 54, 202, 188, 135, 189, 177, 222, 187, 165,
    159, 128, 163, 15, 86, 185, 122, 72, 126, 37, 93, 199, 216, 101, 191, 240, 140, 245, 71, 217, 225, 170, 47, 76, 74,
    27, 38, 64, 190, 181, 33, 94, 137, 255, 187, 144, 45, 114, 74, 232,
];

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

async fn do_contribute(client: &Client, coordinator: &mut Url, pubkey: String) -> Result<(), RequestError> {
    let locked_locators = requests::post_lock_chunk(client, coordinator, &pubkey).await?;

    let get_chunk_req = GetChunkRequest::new(pubkey.clone(), locked_locators.clone());
    let task = requests::get_chunk(client, coordinator, &get_chunk_req).await?;

    let contribution = compute_contribution_mock();

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
    let pubkey = String::from("random public key");
    requests::post_join_queue(&client, coordinator, &pubkey).await.unwrap();

    let mut i = 0;
    loop {
        if i == 3 {
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
    match requests::post_stop_coordinator(client, coordinator).await {
        Ok(()) => println!("Ceremony completed!"),
        Err(e) => eprintln!("{}", e),
    }
}

#[tokio::main]
async fn main() {
    let opt = ContributorOpt::from_args();
    let client = Client::new();

    match opt {
        ContributorOpt::Contribute(url) => {
            let mut coordinator = url.coordinator;
            contribute(&client, &mut coordinator).await;
        }
        ContributorOpt::CloseCeremony(url) => {
            let mut coordinator = url.coordinator;
            close_ceremony(&client, &mut coordinator).await;
        }
    }
}
