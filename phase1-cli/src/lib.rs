// Documentation
#![doc = include_str!("../README.md")]

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
#[structopt(name = "namada-mpc", about = "Namada CLI for trusted setup.")]
pub enum CeremonyOpt {
    #[structopt(about = "Contribute to the ceremony")]
    Contribute {
        #[structopt(flatten)]
        url: CoordinatorUrl,
        #[structopt(
            long,
            help = "Perform only the randomness computation step skipping all communication"
        )]
        offline: bool,
    },
    #[structopt(about = "Stop the coordinator and close the ceremony")]
    CloseCeremony(CoordinatorUrl),
    #[structopt(about = "Get a list of all the contributions received")]
    GetContributions(CoordinatorUrl),
    #[cfg(debug_assertions)]
    #[structopt(about = "Verify the pending contributions")]
    VerifyContributions(CoordinatorUrl),
    #[cfg(debug_assertions)]
    #[structopt(about = "Update manually the coordinator")]
    UpdateCoordinator(CoordinatorUrl),
}
