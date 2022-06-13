use crate::authentication::{Production, Signature, KeyPair};

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContributionInfoError {
    #[error("Error while serializing ContributionInfo: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Expected ContributionInfo to be serialized as a Map")]
    UnexpectedSerializationFormat,
    #[error("Error while signing ContributionInfo: {0}")]
    SignatureError(String)
}

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

impl ContributionInfo {
    /// Computes the signature of a json string encoding the struct.
    pub fn try_sign(&mut self, sigkey: &str) -> Result<(), ContributionInfoError> {
        // FIXME: sign the hash of the json
        let mut serde_contrib_info = serde_json::to_value(self.clone())?;

        // Remove contributor_info_signature from json
        let mut map = serde_contrib_info.as_object_mut().ok_or(ContributionInfoError::UnexpectedSerializationFormat)?;
        map.remove("contributor_info_signature");

        // Compute signature
        let serialized_contrib_info = serde_contrib_info.to_string();
        let contrib_info_signature = Production.sign(sigkey, serialized_contrib_info.as_str()).map_err(|e| ContributionInfoError::SignatureError(format!("{}", e)))?;
        self.contributor_info_signature = contrib_info_signature;

        Ok(())
    }

    /// Verifies the signature.
    fn verify_signature(&self) -> Result<bool, ContributionInfoError> {
        let mut serde_contrib_info = serde_json::to_value(self.clone())?; //FIXME: first part in common with try_sign

        // Remove contributor_info_signature from json
        let mut map = serde_contrib_info.as_object_mut().expect("Expected ContributionInfo to be a Map");
        map.remove("contributor_info_signature");

        let serialized_contrib_info = serde_contrib_info.to_string();
        
        Ok(Production.verify(self.public_key.as_str(), serialized_contrib_info.as_str(), self.contributor_info_signature.as_str()))
    }
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

#[cfg(test)]
mod tests {
    use crate::authentication::KeyPair;

    use super::ContributionInfo;

    #[test]
    fn sign_and_verify() {
        let keypair = KeyPair::new();
        let mut test_info = ContributionInfo::default();
        test_info.public_key = keypair.pubkey().to_owned();

        test_info.try_sign(keypair.sigkey()).unwrap();

        assert!(test_info.verify_signature().unwrap());
    }
}