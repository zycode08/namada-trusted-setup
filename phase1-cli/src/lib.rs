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
    rest::{ContributeChunkRequest, GetChunkRequest, PostChunkRequest},
    storage::ContributionLocator,
};

use reqwest::Url;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct CoordinatorUrl { //FIXME: tuple struct?
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
#[structopt(name = "anoma-mpc", about = "Anoma CLI for trusted setup.")]
pub enum ContributorOpt {
    #[structopt(about = "Contribute to the trusted setup")]
    Contribute(CoordinatorUrl),
    #[structopt(about = "Stop the coordinator and close the ceremony")]
    CloseCeremony(CoordinatorUrl),
    #[structopt(about = "Verify the pending contributions")]
    VerifyContributions(CoordinatorUrl),
    #[structopt(about = "Update manually the coordinator")]
    UpdateCoordinator(CoordinatorUrl)
}
