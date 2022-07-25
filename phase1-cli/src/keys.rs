use std::fmt::Display;
use std::str::FromStr;

use orion::{aead, kdf};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ed25519_compact::{KeyPair, Seed};

const ENCRYPTED_KEY_PREFIX: &str = "encrypted:";

/// A keypair stored in a wallet
#[derive(Debug)]
pub enum StoredKeypair { //FIXME: remove
    /// An encrypted keypair
    Encrypted(EncryptedKeypair),
}

impl Serialize for StoredKeypair {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // String encoded, because toml doesn't support enums
        match self {
            StoredKeypair::Encrypted(encrypted) => {
                let keypair_string =
                    format!("{}{}", ENCRYPTED_KEY_PREFIX, encrypted);
                serde::Serialize::serialize(&keypair_string, serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for StoredKeypair { //FIXME: remove, maybe keep it for testing
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let keypair_string: String =
            serde::Deserialize::deserialize(deserializer)
                .map_err(|err| {
                    DeserializeStoredKeypairError::InvalidStoredKeypairString(
                        err.to_string(),
                    )
                })
                .map_err(D::Error::custom)?;
        if let Some(encrypted) =
            keypair_string.strip_prefix(ENCRYPTED_KEY_PREFIX)
        {
            FromStr::from_str(encrypted)
                .map(Self::Encrypted)
                .map_err(|err| {
                    DeserializeStoredKeypairError::InvalidStoredKeypairString(
                        err.to_string(),
                    )
                })
                .map_err(D::Error::custom)
        } else {
            Err(DeserializeStoredKeypairError::MissingPrefix)
                .map_err(D::Error::custom)
        }
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DeserializeStoredKeypairError { //FIXME: remove
    #[error("The stored keypair is not valid: {0}")]
    InvalidStoredKeypairString(String),
    #[error("The stored keypair is missing a prefix")]
    MissingPrefix,
}

/// An encrypted keypair stored in a wallet
#[derive(Debug)]
pub struct EncryptedKeypair(Vec<u8>);

impl Display for EncryptedKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl FromStr for EncryptedKeypair {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(Self)
    }
}

impl StoredKeypair {
    /// Construct a keypair for storage. Returns the key for storing.
    pub fn from_seed(
        seed: &[u8],
        password: impl AsRef<[u8]>,
    ) -> Self {
        Self::Encrypted(EncryptedKeypair::from_seed(seed, password))
    }
}

impl EncryptedKeypair {
    /// Encrypt a keypair and store it with its salt.
    pub fn from_seed(seed: &[u8], password: impl AsRef<[u8]>) -> Self { //FIXME: String or ref u8
        let salt = kdf::Salt::default();
        let encryption_key = encryption_key(&salt, password.as_ref());

        let keypair = KeyPair::from_seed(Seed::from_slice(&seed[.. 32]).unwrap());
        // NOTE: need to append an initial 0 to match the borsh encoding of the enum in the ledger.
        //  Also need to truncate the length to 33 because the private key also contains the pubkey in the
        //  trailing 32 bytes
        let mut sk = vec![0u8];
        sk.extend_from_slice(&keypair.sk.to_vec());
        sk.truncate(33);

        let encrypted_keypair = aead::seal(&encryption_key, &sk)
            .expect("Encryption of data shouldn't fail");
        let encrypted_data = [salt.as_ref(), &encrypted_keypair].concat();

        Self(encrypted_data)
    }
}

/// Make encryption secret key from a password.
fn encryption_key(salt: &kdf::Salt, password: &[u8]) -> kdf::SecretKey {
    kdf::Password::from_slice(password)
        .and_then(|password| kdf::derive_key(&password, salt, 3, 1 << 16, 32))
        .expect("Generation of encryption secret key shouldn't fail")
}
