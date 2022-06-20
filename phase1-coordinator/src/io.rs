use std::io::{Write, Read};

use crate::authentication::KeyPair;
use bip39::{Language, Mnemonic};
use rand::prelude::SliceRandom;
use regex::Regex;
use thiserror::Error;
use tracing::debug;
use termion::screen::AlternateScreen;

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
/// check the validity of the reply.
pub fn get_user_input(request: &str, expected: Option<&Regex>) -> Result<String>{
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
            }
            None => break,
        }

        response.clear();
        println!("Invalid reply, please type a valid answer...");
    }

    Ok(response)
}

/// Generates a new [`KeyPair`] from a mnemonic. If argument `from_mnemonic` is set
/// then the keypair is generated from the mnemonic provided by the user, otherwise
/// it's generated randomly.
pub fn generate_keypair(from_mnemonic: bool) -> Result<KeyPair> {
    let mnemonic = if from_mnemonic {
        let mnemonic_str = get_user_input(
            format!("Please provide a {} words mnemonic for your keypair:", MNEMONIC_LEN).as_str(),
            Some(&Regex::new(r"^([[:alpha:]]+\s){23}[[:alpha:]]+$")?),
        )?;

        Mnemonic::parse_in_normalized(Language::English, mnemonic_str.as_str())
            .map_err(|e| IOError::MnemonicError(e))?
    } else {
        // Generate random mnemonic
        let mut rng = rand_06::thread_rng();
        let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, MNEMONIC_LEN).map_err(|e| IOError::MnemonicError(e))?;

        // Print mnemonic to the user in a different terminal
        {
            let mut secret_screen = AlternateScreen::from(std::io::stdout());
            writeln!(&mut secret_screen, "Safely store your 24 words mnemonic: {}", mnemonic);
            get_user_input(format!("Press enter when you've done it...").as_str(), None)?;
        } // End scope, get back to stdin/stdout

        // Check if the user has correctly stored the mnemonic
        #[cfg(not(debug_assertions))]
        check_mnemonic(&mnemonic)?;

        mnemonic
    };

    let seed = mnemonic.to_seed_normalized("");
    Ok(KeyPair::try_from_seed(&seed)?)
}

/// Interactively check if the user has correctly stored the mnemonic phrase
fn check_mnemonic(mnemonic: &Mnemonic) -> Result<()> {
    let mut rng = rand::thread_rng();
    let mut indexes = [0usize; MNEMONIC_LEN];

    for i in 0..MNEMONIC_LEN {
        indexes[i] = i;
    }
    indexes.shuffle(&mut rng);

    println!("Mnemonic verification step");
    let mnemonic_slice: Vec<&'static str> = mnemonic.word_iter().collect();

    for &i in indexes[..MNEMONIC_CHECK_LEN].iter() {
        let response = get_user_input(
            format!("Enter the word at index {} of your mnemonic:", i + 1).as_str(),
            Some(&Regex::new(r"[[:alpha:]]+")?),
        )?;

        if response != mnemonic_slice[i] {
            debug!("Expected: {}, answer: {}", mnemonic_slice[i], response);
            return Err(IOError::CheckMnemonicError);
        }
    }

    println!("Verification passed");

    Ok(())
}
