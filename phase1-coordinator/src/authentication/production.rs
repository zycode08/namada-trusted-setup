use crate::authentication::Signature as SigTrait;
use ed25519_compact::{KeyPair as EdKeyPair, Noise, PublicKey, SecretKey, Signature};
use base64;
use std::ops::Deref;
use hex;

/// A private/public key couple encoded in [`base64`]
pub struct KeyPair {
    pubkey: String,
    sigkey: String
}

impl KeyPair {
    /// Generate a random key pair.
    pub fn new() -> Self {
        let keypair = EdKeyPair::generate();

        KeyPair { pubkey: base64::encode(keypair.pk.deref()), sigkey: base64::encode(keypair.sk.deref()) }
    }

    /// Get the key pair's public key.
    #[must_use]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
    }

    /// Get the key pair's signing (private) key.
    #[must_use]
    pub fn sigkey(&self) -> String {
        self.sigkey.clone()
    }
}

/// The authentication to be used in production, based on [`ed25519_compact`]
pub struct Production;

impl SigTrait for Production {
  /// Returns the name of the signature scheme.
  fn name(&self) -> String {
      String::from("Production")
  }

  /// Returns `true` if the signature scheme is safe for use in production.
  fn is_secure(&self) -> bool {
      true
  }

  /// Signs the given message using the given signing key,
  /// and returns the signature as a [`hex`] encoded string.
  /// Signing key is expected to be [`base64`] encoded.
  fn sign(&self, signing_key: &str, message: &str) -> anyhow::Result<String> {
      let signing_key_bytes = base64::decode(signing_key)?;
      let signing_key = SecretKey::from_slice(signing_key_bytes.as_ref())?;
      
      let signature = signing_key.sign(message, Some(Noise::generate()));

      Ok(hex::encode(signature))
  }

  /// Verifies the given signature for the given message and public key,
  /// and returns `true` if the signature is valid.
  /// Public key is expected to be [`base64`] encoded.
  /// Signature is expected to be [`hex`] encoded.
  fn verify(&self, public_key: &str, message: &str, signature: &str) -> bool {
      let public_key_bytes = base64::decode(public_key).expect("Invalid public key encoding");
      let public_key = PublicKey::from_slice(public_key_bytes.as_ref()).expect("Invalid public key");
      
      let signature_bytes = hex::decode(signature).expect("Invalid signature encoding");
      let signature = Signature::from_slice(signature_bytes.as_ref()).expect("Invalid signature");

      public_key.verify(message, &signature).is_ok()
  }
}
