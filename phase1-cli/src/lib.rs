// Documentation
#![doc = include_str!("../README.md")]

use std::path::PathBuf;

pub mod ascii_logo;
pub mod keys;
pub mod requests;

use phase1_coordinator::{
    objects::round::LockedLocators,
    rest::{ContributorStatus, PostChunkRequest},
};

use reqwest::Url;
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
    AnotherMachine {
        #[structopt(flatten)]
        url: CoordinatorUrl,
    },
    Default {
        #[structopt(flatten)]
        url: CoordinatorUrl,
        #[structopt(
            long,
            help = "Give a custom random seed (32 bytes / 64 characters in hexadecimal) for the ChaCha RNG"
        )]
        custom_seed: bool,
    },
    Offline {
        #[structopt(
            long,
            help = "Give a custom random seed (32 bytes / 64 characters in hexadecimal) for the ChaCha RNG"
        )]
        custom_seed: bool,
    },
}

#[derive(Debug, StructOpt)]
#[structopt(name = "namada-mpc", about = "Namada CLI for trusted setup.")]
pub enum CeremonyOpt {
    #[structopt(about = "Contribute to the ceremony")]
    Contribute(Branches),
    #[structopt(about = "Stop the coordinator and close the ceremony")]
    CloseCeremony(CoordinatorUrl),
    #[structopt(about = "Generate a Namada keypair from a mnemonic")]
    ExportKeypair(MnemonicPath),
    #[structopt(about = "Generate the list of addresses of the contributors")]
    GenerateAddresses(Contributors),
    #[structopt(about = "Get a list of all the contributions received")]
    GetContributions(CoordinatorUrl),
    #[cfg(debug_assertions)]
    #[structopt(about = "Verify the pending contributions")]
    VerifyContributions(CoordinatorUrl),
    #[cfg(debug_assertions)]
    #[structopt(about = "Update manually the coordinator")]
    UpdateCoordinator(CoordinatorUrl),
}
