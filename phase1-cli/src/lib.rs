// Documentation
#![doc = include_str!("../README.md")]

mod combine;
pub use combine::combine;

mod contribute;
pub use contribute::contribute;

mod new_challenge;
pub use new_challenge::new_challenge;

pub mod requests;

mod transform_pok_and_correctness;
pub use transform_pok_and_correctness::transform_pok_and_correctness;

mod transform_ratios;
pub use transform_ratios::transform_ratios;

use phase1_coordinator::{
    objects::{round::LockedLocators, Task},
    rest::{ContributorStatus, PostChunkRequest},
    storage::ContributionLocator,
};

use reqwest::Url;
use structopt::StructOpt;


#[derive(Debug, StructOpt)]
pub struct CoordinatorUrl {
    #[structopt(
        help = "The ip address and port of the coordinator",
        required = true,
        default_value = "http://127.0.0.1:8000",
        env = "ANOMA_COORDINATOR_ADDRESS",
        parse(try_from_str)
    )]
    pub coordinator: Url,
}

#[derive(Debug, StructOpt)]
pub struct ContributionArgs {
    #[structopt(flatten)]
    pub coordinator: CoordinatorUrl,
    #[structopt(
        help = "The path to the mnemonic phrase file needed to generate the keypair for the contribution. The phrase should consists of 24 words.",
        required = true,
    )]
    pub mnemonic_file_path: Path,
    #[structopt(
        help = "The passhprase used to generate the seed from the mnemonic.",
        required = true,
    )]
    pub passphrase: String
}

// FIXME: since also for the coordinator we must use mnemonics now, the coordinator will pass the mnemonic file (possibly encrypted), so no need to save it, but all the commands
//  of the coordinator will need to take the path to this file + passphrase + encyption key?

#[derive(Debug, StructOpt)]
#[structopt(name = "anoma-mpc", about = "Anoma CLI for trusted setup.")]
pub enum ContributorOpt {
    #[structopt(about = "Contribute to the ceremony")]
    Contribute(ContributionArgs),
    #[structopt(about = "Stop the coordinator and close the ceremony")]
    CloseCeremony(CoordinatorUrl),
    #[cfg(debug_assertions)]
    #[structopt(about = "Verify the pending contributions")]
    VerifyContributions(CoordinatorUrl),
    #[cfg(debug_assertions)]
    #[structopt(about = "Update manually the coordinator")]
    UpdateCoordinator(CoordinatorUrl),
}
