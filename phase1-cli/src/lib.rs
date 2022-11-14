// Documentation
#![doc = include_str!("../README.md")]

use std::path::PathBuf;

pub mod ascii_logo;
pub mod keys;
pub mod requests;

use phase1_coordinator::{
    objects::round::LockedLocators,
    rest_utils::{ContributorStatus, PostChunkRequest},
};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct CoordinatorUrl {
    #[structopt(
        help = "The ip address and port of the coordinator",
        required = true,
        default_value = "http://0.0.0.0:8080",
        env = "NAMADA_COORDINATOR_ADDRESS",
        parse(try_from_str)
    )]
    pub coordinator: Url,
}

/// Accepts both the ceremony token and the secret token for reserved endpoints
#[derive(Debug, StructOpt)]
pub struct RequestWithToken {
    #[structopt(flatten)]
    pub url: CoordinatorUrl,
    #[structopt(help = "The secret token required for the request")]
    pub token: String,
}

#[derive(Debug, StructOpt)]
pub struct MnemonicPath {
    #[structopt(help = "The path to the mnemonic file", required = true, parse(try_from_str))]
    pub path: PathBuf,
}

#[derive(Debug, StructOpt)]
pub struct Contributors {
    #[structopt(
        help = "The path to the contributors.json file",
        required = true,
        parse(try_from_str),
        long
    )]
    pub path: PathBuf,
    #[structopt(help = "The amount of tokens to assign", required = true, long)]
    pub amount: u32,
}

#[derive(Debug, StructOpt)]
pub enum Branches {
    #[structopt(
        about = "Performs only the communication with the Coordinator, to be used in conjunction with \"namada-ts contribute offline\" on another machine"
    )]
    AnotherMachine {
        #[structopt(flatten)]
        request: RequestWithToken,
    },
    #[structopt(about = "The default contribution path, executes both communication and computation on this machine")]
    Default {
        #[structopt(flatten)]
        request: RequestWithToken,
        #[structopt(
            long,
            help = "Give a custom random seed (32 bytes / 64 characters in hexadecimal) for the ChaCha RNG"
        )]
        custom_seed: bool,
    },
    #[structopt(
        about = "Performs only the computation of the contribution, to be used in conjunction with \"namada-ts contribute another-machine\" on a separate machine"
    )]
    Offline {
        #[structopt(
            long,
            help = "Give a custom random seed (32 bytes / 64 characters in hexadecimal) for the ChaCha RNG"
        )]
        custom_seed: bool,
    },
}

pub enum TokenCohort {
    Finished,
    InProgress,
    Pending,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
    pub from: u64,
    pub to: u64,
    pub index: u64,
    pub id: String,
}

impl Token {
    pub fn is_valid_cohort(&self) -> TokenCohort {
        let utc_now = chrono::offset::Utc::now().timestamp() as u64;
        if self.from <= utc_now && utc_now < self.to {
            TokenCohort::InProgress
        } else if utc_now < self.from {
            TokenCohort::Pending
        } else {
            TokenCohort::Finished
        }
    }
}

#[derive(Debug, StructOpt)]
pub struct VerifySignatureContribution {
    #[structopt(about = "The contribution public key")]
    pub pubkey: String,
    #[structopt(about = "The contribution message hash")]
    pub message: String,
    #[structopt(about = "The contribution signature")]
    pub signature: String
}

#[derive(Debug, StructOpt)]
#[structopt(name = "namada-ts", about = "Namada CLI for trusted setup.")]
pub enum CeremonyOpt {
    #[structopt(about = "Contribute to the ceremony")]
    Contribute(Branches),
    #[structopt(about = "Stop the coordinator and close the ceremony")]
    CloseCeremony(CoordinatorUrl),
    #[structopt(about = "Generate a Namada keypair from a mnemonic")]
    ExportKeypair(MnemonicPath),
    #[structopt(about = "Generate the list of addresses of the contributors")]
    GenerateAddresses(Contributors),
    #[cfg(debug_assertions)]
    #[structopt(about = "Get a list of all the contributions received")]
    GetContributions(CoordinatorUrl),
    #[structopt(about = "Get the state of the coordinator")]
    GetState(RequestWithToken),
    #[cfg(debug_assertions)]
    #[structopt(about = "Verify the pending contributions")]
    VerifyContributions(CoordinatorUrl),
    #[structopt(about = "Update the cohorts' tokens")]
    UpdateCohorts(CoordinatorUrl),
    #[cfg(debug_assertions)]
    #[structopt(about = "Update manually the coordinator")]
    UpdateCoordinator(CoordinatorUrl),
    #[structopt(about = "Verify signature")]
    VerifySignature(VerifySignatureContribution),
}
