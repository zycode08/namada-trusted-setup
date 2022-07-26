use std::{fmt::Display, collections::HashMap};
use std::str::FromStr;

use bech32::{Variant, ToBase32};
use orion::{aead, kdf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use ed25519_compact::{KeyPair, Seed};

const ADDRESS_BECH32_VARIANT: bech32::Variant = Variant::Bech32m;
const ADDRESS_HRP: &str = "atest";
const ENCRYPTED_KEY_PREFIX: &str = "encrypted:";
/// An address string before bech32m encoding must be this size.
const FIXED_LEN_STRING_BYTES: usize = 45;
const PKH_HASH_LEN: usize = 40;
const PREFIX_IMPLICIT: &str = "imp";

// FIXME: docstrings

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DeserializeStoredKeypairError {
    #[error("The stored keypair is not valid: {0}")]
    InvalidStoredKeypairString(String),
    #[error("The stored keypair is missing a prefix")]
    MissingPrefix,
}

#[derive(Deserialize, Serialize)]
pub struct TomlConfig {
    keys: HashMap<String, EncryptedKeypair>, //FIXME: &str?
    addresses: HashMap<String ,String>,
    pkhs: HashMap<String, String>
}

impl TomlConfig {
    pub fn new(alias: String, key: EncryptedKeypair, address: String, pkh: String) -> Self {
        let mut keys = HashMap::from([(alias.clone(), key)]);
        let addresses = HashMap::from([(alias.clone(), address)]);
        let pkhs = HashMap::from([(pkh, alias)]); 

        Self { keys, addresses, pkhs }
    }
}

/// An encrypted keypair stored in a wallet
#[derive(Debug)]
pub struct EncryptedKeypair(Vec<u8>);

impl Serialize for EncryptedKeypair {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let keypair_string = format!("{}{}", ENCRYPTED_KEY_PREFIX, self);
        serde::Serialize::serialize(&keypair_string, serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptedKeypair {
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
                .map_err(|err: hex::FromHexError| {
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

impl EncryptedKeypair {
    /// Encrypt a keypair and store it with its salt. Returns the keypair and the pubkey.
    pub fn from_seed(seed: &[u8], password: impl AsRef<[u8]>) -> (Self, String) {
        let keypair = KeyPair::from_seed(Seed::from_slice(&seed[.. 32]).unwrap());
        // NOTE: need to append an initial 0 to match the borsh encoding of the enum in the ledger.
        //  Also need to truncate the length to 33 because the private key also contains the pubkey in the
        //  trailing 32 bytes
        let mut sk = vec![0u8];
        sk.extend_from_slice(&keypair.sk.to_vec()); //FIXME: truncate here
        sk.truncate(33);

        let salt = kdf::Salt::default();
        let encryption_key = encryption_key(&salt, password.as_ref());

        let encrypted_keypair = aead::seal(&encryption_key, &sk)
            .expect("Encryption of data shouldn't fail");
        let encrypted_data = [salt.as_ref(), &encrypted_keypair].concat();

        (Self(encrypted_data), hex::encode(keypair.pk.to_vec()))
    }
}

/// Make encryption secret key from a password.
fn encryption_key(salt: &kdf::Salt, password: &[u8]) -> kdf::SecretKey {
    kdf::Password::from_slice(password)
        .and_then(|password| kdf::derive_key(&password, salt, 3, 1 << 16, 32))
        .expect("Generation of encryption secret key shouldn't fail")
}

// FIXME: methods of encrypted keypair?
/// Generates an address from a provided, hex encoded, public key.
pub fn generate_address(pk: &str) -> String {
    // Prepend 0 to match Namada borsh encoding
    let mut adjusted_pk = String::from("0");
    adjusted_pk.push_str(pk);

    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(adjusted_pk);

    // hex of the first 40 chars of the hash
    format!(
        "{:.width$X}",
        hasher.finalize(),
        width = PKH_HASH_LEN
    )
}

/// Generates a Namada address by Bech32m encoding it.
pub fn bech_encode_address(address: &str) -> String {
    let mut bytes = format!("{}::{}", PREFIX_IMPLICIT, address).into_bytes();
    bytes.resize(FIXED_LEN_STRING_BYTES, b' ');

    bech32::encode(ADDRESS_HRP, bytes.to_base32(), ADDRESS_BECH32_VARIANT).unwrap()
}
