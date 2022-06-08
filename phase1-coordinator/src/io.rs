use crate::authentication::KeyPair;
use rand::Rng;
use regex::Regex;
use bip39::{Language, Mnemonic};
use thiserror::Error;
use tracing::debug;

const MNEMONIC_LEN: usize = 24;
const MNEMONIC_CHECK_LEN: usize = 3;

#[derive(Debug, Error)]
pub enum IOError {
    #[error("Wrong answer in mnemonic check")]
    CheckMnemonicError,
    #[error("Error in user input: {0}")]
    InputError(#[from] std::io::Error),
    #[error("Error in KeyPair generation: {0}")]
    KeyPairError(#[from] ed25519_compact::Error),
    #[error("Mnemonic error: {0}")]
    MnemonicError(bip39::Error),
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

type Result<T> = std::result::Result<T, IOError>;

/// Helper function to get input from the user. Accept an optional [`Regex`] to
/// check the validity of the reply
pub fn get_user_input(request: &str, expected: Option<&Regex>) -> Result<String> {
    let mut response = String::new();

    loop {
        println!("{}", request);
        std::io::stdin().read_line(&mut response)?;
        response = response.trim().to_owned();

        match expected {
            Some(re) => {
                if re.is_match(response.as_str()) {
                    break;
                }
            },
            None => break,
        }

        response.clear();
        println!("Invalid reply, please type a valid answer...");
    }

    Ok(response)
}

/// Generates a new [`KeyPair`] from a mnemonic provided by the user
pub fn generate_keypair() -> Result<KeyPair> {
    // Request mnemonic to the user
    let mnemonic_str = get_user_input(format!("Please provide a {} words mnemonic for your keypair:", MNEMONIC_LEN).as_str(), Some(&Regex::new(r"^([[:alpha:]]+\s){23}[[:alpha:]]+$")?))?;
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_str.as_str()).map_err(|e| {IOError::MnemonicError(e)})?;

    // Check if the user has correctly stored the mnemonic
    #[cfg(not(debug_assertions))]
    check_mnemonic(&mnemonic)?;

    let seed = mnemonic.to_seed_normalized("");
    Ok(KeyPair::try_from_seed(&seed)?)
}

/// Interactively check if the user has correctly stored the mnemonic phrase
fn check_mnemonic(mnemonic: &Mnemonic) -> Result<()> {
    let mut rng = rand::thread_rng();
    let mut indexes = [0usize; MNEMONIC_LEN];

    for i in 1..MNEMONIC_LEN {
        indexes[i] = i;
    }
    indexes.shuffle(&mut rng);

    println!("Mnemonic verification step");
    let mnemonic_slice: Vec<&'static str> = mnemonic.word_iter().collect();

    for i in indexes[..MNEMONIC_CHECK_LEN].iter() {
       let response = get_user_input(format!("Enter the word at index {} of your mnemonic:", i).as_str(), Some(&Regex::new(r"[[:alpha:]]+")?))?;
 
        if response != mnemonic_slice[i - 1] {
            debug!("Expected: {}, answer: {}", mnemonic_slice[i - 1], response);
            return Err(IOError::CheckMnemonicError);
        }
    }

    println!("Verification passed. Be sure to safely store your mnemonic phrase!");

    Ok(())
}
