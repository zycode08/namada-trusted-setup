use std::{io::Write, ops::Deref, fmt::Display};

use crate::authentication::KeyPair;
use bip39::{Language, Mnemonic};
use colored::*;
#[cfg(not(debug_assertions))]
use rand::prelude::SliceRandom;
use regex::Regex;
use termion::screen::AlternateScreen;
use thiserror::Error;
#[cfg(not(debug_assertions))]
use tracing::debug;

const MNEMONIC_LEN: usize = 24;

#[derive(Debug, Error)]
pub enum IOError {
    #[error("Wrong answer in mnemonic check")]
    CheckMnemonicError,
    #[error("Error in IO: {0}")]
    InputError(#[from] std::io::Error),
    #[error("Error in KeyPair generation: {0}")]
    KeyPairError(#[from] ed25519_compact::Error),
    #[error("Mnemonic error: {0}")]
    MnemonicError(bip39::Error),
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

type Result<T> = std::result::Result<T, IOError>;
struct MnemonicWrap(Mnemonic);

impl Deref for MnemonicWrap {
    type Target = Mnemonic;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Mnemonic> for MnemonicWrap {
    fn from(m: Mnemonic) -> Self {
        Self(m)
    }
}

impl From<MnemonicWrap> for Mnemonic {
    fn from(m: MnemonicWrap) -> Self {
        m.0
    }
}

impl Display for MnemonicWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Get longest word
        let max_len = self.word_iter().enumerate().map(|(i, word)| format!("{}. {}  ", i + 1, word)).max_by_key(|x| x.len()).unwrap().len();

        // Display
        let stripe = format!("{}", "=".repeat((max_len * 4) - 2));
        writeln!(f, "{}", stripe)?;
        let mut i = 0;
        let words: Vec<&str> = self.word_iter().collect();

        while i < MNEMONIC_LEN {
            let mut segments: [String; 4] = [String::new(), String::new(), String::new(), String::new()];

            for j in 0..4 {
                let tmp = if j < 3 {
                    format!("{}. {}  ", i + j + 1, words[i + j])
                } else {
                    format!("{}. {}", i + j + 1, words[i + j])
                };

                segments[j] = format!("{:max_len$}", tmp);
            }

            writeln!(f, "{}{}{}{}", segments[0], segments[1], segments[2], segments[3])?;
            
            i += 4;
        }

        writeln!(f, "{}", stripe)?;

        Ok(())
    }
}

/// Helper function to get input from the user. Accept an optional [`Regex`] to
/// check the validity of the reply.
pub fn get_user_input<S>(request: S, expected: Option<&Regex>) -> Result<String>
where S: std::fmt::Display {
    let mut response = String::new();

    loop {
        print!("{} ", request);
        std::io::stdout().flush()?;
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
        println!("{}", "Invalid reply, please type a valid answer...".red().bold());
    }

    Ok(response)
}

/// Generates a new [`KeyPair`] from a mnemonic provided by the user.
pub fn keypair_from_mnemonic() -> Result<KeyPair> {
    let mnemonic_str = get_user_input(
        format!("Please provide a {} words mnemonic for your keypair:", MNEMONIC_LEN).as_str(),
        Some(&Regex::new(r"^([[:alpha:]]+\s){23}[[:alpha:]]+$")?),
    )?;
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_str.as_str())
        .map_err(|e| IOError::MnemonicError(e))?;
    let seed = mnemonic.to_seed_normalized("");
    
    Ok(KeyPair::try_from_seed(&seed)?)
}

/// Generates a new [`KeyPair`] from a randomly generated mnemonic. If argument `is_server` is set than the mnemonic is saved 
/// to a file, otherwise it gets printed to the user.
pub fn generate_keypair(is_server: bool) -> Result<KeyPair> {
    // Generate random mnemonic
    let mut rng = rand_06::thread_rng();
    let mnemonic: MnemonicWrap = Mnemonic::generate_in_with(&mut rng, Language::English, MNEMONIC_LEN)
        .map_err(|e| IOError::MnemonicError(e))?.into();

    if is_server {
        std::fs::write("coordinator.mnemonic", mnemonic.to_string())?;
    } else {
        // Print mnemonic to the user in a different terminal
        {
            let mut secret_screen = AlternateScreen::from(std::io::stdout());
            writeln!(&mut secret_screen, "Safely store your 24 words mnemonic:\n{}", mnemonic)?;
            get_user_input(format!("Press enter when you've done it...").as_str(), None)?;
        } // End scope, get back to stdout

        // Check if the user has correctly stored the mnemonic
        #[cfg(not(debug_assertions))]
        check_mnemonic(&mnemonic)?;
    }
    let mnemonic: Mnemonic = mnemonic.into();
    let seed = mnemonic.to_seed_normalized("");

    Ok(KeyPair::try_from_seed(&seed)?)
}

/// Interactively check if the user has correctly stored the mnemonic phrase
#[cfg(not(debug_assertions))]
fn check_mnemonic(mnemonic: &Mnemonic) -> Result<()> {
    let mut rng = rand::thread_rng();
    let mut indexes = [0usize; MNEMONIC_LEN];

    for i in 0..MNEMONIC_LEN {
        indexes[i] = i;
    }
    indexes.shuffle(&mut rng);

    //FIXME: print to alternate screen
    println!("{}", "Mnemonic verification step".yellow().bold());
    let mnemonic_slice: Vec<&'static str> = mnemonic.word_iter().collect();

    for &i in indexes[..3].iter() {
        let response = get_user_input(
            format!("Enter the word at index {} of your mnemonic:", i + 1).as_str(),
            Some(&Regex::new(r"[[:alpha:]]+")?),
        )?;

        if response != mnemonic_slice[i] {
            debug!("Expected: {}, answer: {}", mnemonic_slice[i], response);
            return Err(IOError::CheckMnemonicError);
        }
    }

    println!("{}", "Verification passed".green().bold());

    Ok(())
}
