use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use serde_json::Error;

/// Timestamps of the contribution 
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContributionTimeStamps {
    // User starts the CLI
    pub start_contribution: DateTime<Utc>,
    // User has joined the queue
    pub joined_queue: DateTime<Utc>,
    // User has locked the challenge on the coordinator
    pub challenge_locked: DateTime<Utc>,
    // User has completed the download of the challenge
    pub challenge_downloaded: DateTime<Utc>,
    // User starts computation locally or downloads the file to another machine
    pub start_computation: DateTime<Utc>,
    // User finishes computation locally or uploads the file from another machine
    pub end_computation: DateTime<Utc>,
    // User attests that the file was uploaded correctly
    pub end_contribution: DateTime<Utc>
}

impl Default for ContributionTimeStamps {
    /// Generate a [`ContributionTimeStamps`] instance with all the timestamps 
    /// set to [`Utc::now`].
    fn default() -> Self {
        let timestamp = Utc::now();
        Self { start_contribution: timestamp, joined_queue: timestamp, challenge_locked: timestamp, challenge_downloaded: timestamp, start_computation: timestamp, end_computation: timestamp, end_contribution: timestamp }
    }
}

/// A summarized version of [`ContributionTimeStamps`] 
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrimmedContributionTimeStamps {
    start_contribution: DateTime<Utc>,
    end_contribution: DateTime<Utc>
}

impl From<ContributionTimeStamps> for TrimmedContributionTimeStamps {
    fn from(parent: ContributionTimeStamps) -> Self {
        Self {
            start_contribution: parent.start_contribution,
            end_contribution: parent.end_contribution
        }
    }
}

/// Summary info about the contribution
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ContributionInfo {
    // Name of the contributor
    pub full_name: Option<String>,
    // Email of the contributor
    pub email: Option<String>,
   // ed25519 public key, base64 encoded
   pub public_key: String,
   // User participates in incentivized program or not
   pub is_incentivized: bool,
   // User expresses his intent to participate or not in the contest for creative contributions
   pub is_contest_participant: bool,
   // User can choose to contribute on another machine
   pub is_another_machine: bool,
   // User can choose the default method to generate randomness or his own.
   pub is_own_seed_of_randomness: bool,
   // Round in which the contribution took place
   pub ceremony_round: u64,
   // Hash of the contribution run by masp-mpc, contained in the transcript
   pub contribution_hash: String,
   // Signature of the contribution hash
   pub contribution_hash_signature: String,
   // Hash of the file saved on disk and sent to the coordinator
   pub contribution_file_hash: String,
   // Signature of the contribution
   pub contribution_file_signature: String,
   // Some timestamps to get performance metrics of the ceremony
   pub timestamps: ContributionTimeStamps,
   // Signature of this struct, computed on the json string encoding of all the other fields of this struct
   pub contributor_info_signature: String
}

/// A summarized version of [`ContributionInfo`]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrimmedContributionInfo {
    public_key: String,
    is_another_machine: bool,
    is_own_seed_of_randomness: bool,
    ceremony_round: u64,
    contribution_hash: String,
    contribution_hash_signature: String,
    timestamps: TrimmedContributionTimeStamps
}

impl From<ContributionInfo> for TrimmedContributionInfo {
    fn from(parent: ContributionInfo) -> Self {
        Self {
            public_key: parent.public_key,
            is_another_machine: parent.is_another_machine,
            is_own_seed_of_randomness: parent.is_own_seed_of_randomness,
            ceremony_round: parent.ceremony_round,
            contribution_hash: parent.contribution_hash,
            contribution_hash_signature: parent.contribution_hash_signature,
            timestamps: parent.timestamps.into()
        }
    }
}