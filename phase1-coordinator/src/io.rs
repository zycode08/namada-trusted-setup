use std::{fmt::Display, io::Write, ops::Deref};

use crate::authentication::KeyPair;
use bip39::{Language, Mnemonic};
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};
use owo_colors::OwoColorize;
#[cfg(not(debug_assertions))]
use rand::prelude::SliceRandom;
use regex::Regex;
use thiserror::Error;
#[cfg(not(debug_assertions))]
use tracing::debug;

const COORDINATOR_MNEMONIC_FILE: &str = "coordinator.mnemonic";
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

/// Types of user requesting a [`KeyPair`]
pub enum KeyPairUser {
    Contributor,
    Coordinator,
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
        let max_len = self
            .word_iter()
            .enumerate()
            .map(|(i, word)| word.len() + 4 + (if i < 10 { 1 } else { 2 }))
            .max()
            .unwrap();

        // Display
        let mut i = 0;
        let words: Vec<&str> = self.word_iter().collect();
        let stripe = format!("{}", "=".repeat((max_len * 4) - 2));
        let mut result = stripe.clone();
        result.push_str("\n");

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

            result.push_str(format!("{}{}{}{}\n", segments[0], segments[1], segments[2], segments[3]).as_str());
            i += 4;
        }

        result.push_str(stripe.as_str());

        writeln!(f, "{}", result)
    }
}

/// Helper function to get input from the user. Accept an optional [`Regex`] to
/// check the validity of the reply.
pub fn get_user_input<S>(request: S, expected: Option<&Regex>) -> Result<String>
where
    S: std::fmt::Display,
{
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

/// Generates a seed from a string representing a mnemonic. This string is supposed to have the same format of the
/// one produced by the fmt method of [MnemonicWrap]
pub fn seed_from_string(input: &str) -> Result<[u8; 64]> {
    // Convert to a string of separated words
    let re = Regex::new(r"[[:digit:]]+[.]\s[[:alpha:]]+")?;
    let words = re
        .find_iter(input)
        .map(|mat| mat.as_str().rsplit_once(" ").unwrap().1)
        .fold(String::new(), |mut acc, word| {
            acc.push_str(word);
            acc.push(' ');
            acc
        });
    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, words.as_str()).map_err(|e| IOError::MnemonicError(e))?;

    Ok(mnemonic.to_seed_normalized(""))
}

/// Generates a new [`KeyPair`] from a mnemonic retrieved from the coordinator.mnemonic file in the current working directory.
pub fn keypair_from_mnemonic() -> Result<KeyPair> {
    let mnemonic_str = std::fs::read_to_string(COORDINATOR_MNEMONIC_FILE)?;
    let seed = seed_from_string(&mnemonic_str)?;

    Ok(KeyPair::try_from_seed(&seed)?)
}

/// Generates a new [`KeyPair`] from a randomly generated mnemonic.
/// Cases:
/// - Contributor -> print and check the mnemonic with the user
/// - Coordinator -> save the mnemonic to a file
pub fn generate_keypair(user: KeyPairUser) -> Result<KeyPair> {
    // Generate random mnemonic
    let mut rng = rand_06::thread_rng();
    let mnemonic: MnemonicWrap = Mnemonic::generate_in_with(&mut rng, Language::English, MNEMONIC_LEN)
        .map_err(|e| IOError::MnemonicError(e))?
        .into();

    match user {
        KeyPairUser::Coordinator => std::fs::write(COORDINATOR_MNEMONIC_FILE, mnemonic.to_string())?,
        KeyPairUser::Contributor => {
            // Print mnemonic to the user in a different terminal
            execute!(std::io::stdout(), EnterAlternateScreen)?;
            println!("{}", "Safely store your 24 words mnemonic:\n".bright_cyan());
            println!("{}", mnemonic);
            println!(
                "{}",
                "The next step will be to verify if you've correctly written the words above.".bright_cyan()
            );
            get_user_input(format!("{}", "Press enter when you've done it".yellow()).as_str(), None)?;
            execute!(std::io::stdout(), LeaveAlternateScreen)?;

            #[cfg(not(debug_assertions))]
            {
                execute!(std::io::stdout(), EnterAlternateScreen)?;
                let verification_outcome = check_mnemonic(&mnemonic);
                execute!(std::io::stdout(), LeaveAlternateScreen)?;

                match verification_outcome {
                    Ok(_) => println!("{}", "Mnemonic verification passed".green().bold()),
                    Err(e) => {
                        println!("{}", e.to_string().red().bold());
                        return Err(e);
                    }
                }
            }
        }
    }

    let mnemonic: Mnemonic = mnemonic.into();
    let seed = mnemonic.to_seed_normalized("");

    Ok(KeyPair::try_from_seed(&seed)?)
}

/// Verify a signature against a pubkey and message
pub fn verify_signature(pubkey: String, signature: String, message: String) -> bool {
    let pk = ed25519_compact::PublicKey::from_slice(&hex::decode(pubkey).unwrap());
    let signature = ed25519_compact::Signature::from_slice(&hex::decode(signature).unwrap());

    match (pk, signature) {
        (Ok(pk), Ok(signature)) => match pk.verify(&message, &signature) {
            Ok(_) => true,
            Err(_) => false,
        },
        _ => false,
    }
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

    println!("{}", "Mnemonic verification step".yellow().bold());
    let mnemonic_slice: Vec<&'static str> = mnemonic.word_iter().collect();

    for &i in indexes[..3].iter() {
        // 3 attempts for each word
        for attempt in 0..3 {
            let response = get_user_input(
                format!("Enter the word at index {} of your mnemonic:", i + 1).as_str(),
                Some(&Regex::new(r"[[:alpha:]]+")?),
            )?;

            if response == mnemonic_slice[i] {
                break;
            } else {
                if attempt == 2 {
                    debug!("Expected: {}, answer: {}", mnemonic_slice[i], response);
                    return Err(IOError::CheckMnemonicError);
                } else {
                    debug!("Wrong answer, retry");
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::seed_from_string;

    #[test]
    fn test_seed_from_string() {
        let mnemonic_ok_1 = "Safely store your 24 words mnemonic:
        ======================================================
        1. scheme     2. drift      3. lava       4. crystal    
        5. miracle    6. average    7. admit      8. tuna       
        9. all        10. initial   11. seat      12. crash     
        13. mask      14. depend    15. kangaroo  16. dove      
        17. olive     18. pumpkin   19. trap      20. minute    
        21. history   22. enter     23. immense   24. settle    
        ======================================================";

        let mnemonic_ok_2 = "1. scheme     2. drift      3. lava       4. crystal    
        5. miracle    6. average    7. admit      8. tuna       
        9. all        10. initial   11. seat      12. crash     
        13. mask      14. depend    15. kangaroo  16. dove      
        17. olive     18. pumpkin   19. trap      20. minute    
        21. history   22. enter     23. immense   24. settle";

        let mnemonic_ok_3 = "Safely store your 24 words mnemonic:
        ======================================================
        1. scheme2. drift      3. lava       4. crystal    
        5. miracle    6. average    7. admit      8. tuna       
        9. all        10. initial   11. seat      12. crash     
        13. mask      14. depend    15. kangaroo  16. dove      
        17. olive     18. pumpkin   19. trap      20. minute    
        21. history   22. enter     23. immense   24. settle    
        ======================================================";

        let mnemonic_wrong = "Safely store your 24 words mnemonic:
        ======================================================
        1. scheme     drift      3. lava       4. crystal    
        5. miracle    6. average    7. admit      8. tuna       
        9. all        10. initial   11. seat      12. crash     
        13. mask      14. depend    15. kangaroo  16. dove      
        17. olive     18. pumpkin   19. trap      20. minute    
        21. history   22. enter     23. immense   24. settle    
        ======================================================";

        let seed_ok_1 = seed_from_string(mnemonic_ok_1).unwrap();
        let seed_ok_2 = seed_from_string(mnemonic_ok_2).unwrap();
        let seed_ok_3 = seed_from_string(mnemonic_ok_3).unwrap();
        let seed_wrong = seed_from_string(mnemonic_wrong).unwrap();

        assert_eq!(seed_ok_1, seed_ok_2);
        assert_eq!(seed_ok_2, seed_ok_3);
        assert_ne!(seed_wrong, seed_ok_1);
    }
}
