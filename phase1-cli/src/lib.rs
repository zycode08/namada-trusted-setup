// Documentation
#![doc = include_str!("../README.md")]
// FIXME: fix readme documentation
// FIXME: fix binaries and dependencies in Cargo.toml

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

use phase1::{
    helpers::{contribution_mode_from_str, curve_from_str, proving_system_from_str, CurveKind},
    ContributionMode,
    ProvingSystem,
};


use phase1_coordinator::{
    objects::{round::LockedLocators, Task},
    rest::{ContributeChunkRequest, GetChunkRequest, PostChunkRequest},
    storage::ContributionLocator,
};

use structopt::StructOpt;


#[derive(Debug, StructOpt)]
#[structopt(name = "contribute", about = "Contribute to the parameters computation.")]
pub struct ContributorOpt {
    #[structopt(help = "The ip address and port of the coordinator", env = "ANOMA_COORDINATOR_ADDRESS")]
    pub coordinator: String,
}
