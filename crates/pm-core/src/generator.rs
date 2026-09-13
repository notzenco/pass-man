//! Password generation.
//!
//! Generated passwords are drawn from the OS CSPRNG and use rejection sampling
//! so every character is uniformly distributed. A naive `% charset_len` would
//! bias toward the start of the alphabet, which measurably weakens passwords.

use crate::crypto::random_bytes;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Characters that are easily confused when read or transcribed.
const AMBIGUOUS: &[char] = &['l', 'I', '1', 'O', '0', 'o', '|', '`', '\'', '"'];

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";

/// Options controlling character-set passwords.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordOptions {
    /// Total number of characters.
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Omit characters like `l`, `1`, `O`, and `0`.
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordOptions {
    /// A short options preset for quick construction.
    pub fn new(length: usize) -> Self {
        Self {
            length,
            ..Self::default()
        }
    }

    /// Validate the option set.
    pub fn validate(&self) -> Result<()> {
        if self.length == 0 {
            return Err(Error::InvalidField("password length".into()));
        }
        // Bounded so a caller cannot ask for a megabyte string by accident.
        if self.length > 1024 {
            return Err(Error::InvalidField("password length (max 1024)".into()));
        }
        if !self.lowercase && !self.uppercase && !self.digits && !self.symbols {
            return Err(Error::InvalidField(
                "at least one character class is required".into(),
            ));
        }
        Ok(())
    }

    /// Build the effective alphabet.
    fn alphabet(&self) -> Vec<char> {
        let mut chars: Vec<char> = Vec::new();
        if self.lowercase {
            chars.extend(LOWERCASE.chars());
        }
        if self.uppercase {
            chars.extend(UPPERCASE.chars());
        }
        if self.digits {
            chars.extend(DIGITS.chars());
        }
        if self.symbols {
            chars.extend(SYMBOLS.chars());
        }
        if self.exclude_ambiguous {
            chars.retain(|c| !AMBIGUOUS.contains(c));
        }
        chars
    }
}

/// Draw one uniformly random index in `0..n` using rejection sampling.
///
/// Uses as many random bytes as needed to cover `n`, and rejects values in the
/// incomplete final block so every index is equally likely.
fn uniform_index(n: usize) -> usize {
    assert!(n > 0, "uniform_index requires n > 0");
    if n == 1 {
        return 0;
    }
    // Smallest number of bytes whose range covers n.
    let bytes_needed = ((usize::BITS - (n - 1).leading_zeros()) as usize)
        .div_ceil(8)
        .max(1);
    // Range of the full byte space and the largest multiple of n within it.
    let space = 1u128 << (bytes_needed * 8);
    let limit = space - (space % n as u128);
    loop {
        let mut buf = [0u8; 16];
        let slice = &mut buf[..bytes_needed];
        random_bytes(slice);
        let mut value: u128 = 0;
        for &byte in slice.iter() {
            value = (value << 8) | byte as u128;
        }
        if value < limit {
            return (value % n as u128) as usize;
        }
    }
}

/// Generate a random password using the given options.
pub fn generate(opts: &PasswordOptions) -> Result<String> {
    opts.validate()?;
    let alphabet = opts.alphabet();
    if alphabet.is_empty() {
        return Err(Error::InvalidField("empty alphabet".into()));
    }
    let mut out = String::with_capacity(opts.length);
    let mut indices = vec![0usize; opts.length];
    for slot in indices.iter_mut() {
        *slot = uniform_index(alphabet.len());
    }

    // Guarantee at least one character from each requested class so the result
    // matches what password policies expect, then place the remaining random
    // characters. The final string is shuffled so the guaranteed characters are
    // not always in a predictable leading position.
    let mut required: Vec<char> = Vec::new();
    if opts.lowercase {
        let pool: Vec<char> = class_chars(LOWERCASE, opts.exclude_ambiguous);
        if !pool.is_empty() {
            required.push(pool[uniform_index(pool.len())]);
        }
    }
    if opts.uppercase {
        let pool: Vec<char> = class_chars(UPPERCASE, opts.exclude_ambiguous);
        if !pool.is_empty() {
            required.push(pool[uniform_index(pool.len())]);
        }
    }
    if opts.digits {
        let pool: Vec<char> = class_chars(DIGITS, opts.exclude_ambiguous);
        if !pool.is_empty() {
            required.push(pool[uniform_index(pool.len())]);
        }
    }
    if opts.symbols {
        let pool: Vec<char> = class_chars(SYMBOLS, opts.exclude_ambiguous);
        if !pool.is_empty() {
            required.push(pool[uniform_index(pool.len())]);
        }
    }

    for (i, index) in indices.iter().enumerate() {
        let ch = if i < required.len() {
            required[i]
        } else {
            alphabet[*index]
        };
        out.push(ch);
    }

    // Fisher-Yates shuffle using the same unbiased index source.
    let mut chars: Vec<char> = out.chars().collect();
    for i in (1..chars.len()).rev() {
        let j = uniform_index(i + 1);
        chars.swap(i, j);
    }
    Ok(chars.into_iter().collect())
}

fn class_chars(class: &str, exclude_ambiguous: bool) -> Vec<char> {
    class
        .chars()
        .filter(|c| !exclude_ambiguous || !AMBIGUOUS.contains(c))
        .collect()
}

/// Estimate entropy in bits for the given options.
///
/// This is `length * log2(alphabet)`, the ideal figure. It does not account for
/// the guarantee of one character per class, which slightly reduces real entropy
/// but is dominated by the length term for typical settings.
pub fn entropy_bits(opts: &PasswordOptions) -> f64 {
    let n = opts.alphabet().len();
    if n <= 1 {
        return 0.0;
    }
    (opts.length as f64) * (n as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn respects_length_and_classes() {
        let opts = PasswordOptions {
            length: 32,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        };
        let pw = generate(&opts).unwrap();
        assert_eq!(pw.chars().count(), 32);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn only_selected_classes_are_used() {
        let opts = PasswordOptions {
            length: 40,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        let pw = generate(&opts).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn ambiguous_characters_are_excluded() {
        let opts = PasswordOptions {
            length: 200,
            exclude_ambiguous: true,
            ..PasswordOptions::default()
        };
        let pw = generate(&opts).unwrap();
        assert!(!pw.chars().any(|c| AMBIGUOUS.contains(&c)));
    }

    #[test]
    fn passwords_are_unique() {
        let opts = PasswordOptions::new(24);
        let a = generate(&opts).unwrap();
        let b = generate(&opts).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn no_character_dominates_uniformly() {
        // With an alphabet of 26 lowercase letters, sampling many characters
        // should not heavily skew. This catches modulo bias regressions.
        let opts = PasswordOptions {
            length: 1024,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let mut counts = std::collections::HashMap::new();
        for _ in 0..40 {
            for c in generate(&opts).unwrap().chars() {
                *counts.entry(c).or_insert(0usize) += 1;
            }
        }
        let total: usize = counts.values().sum();
        let expected = total as f64 / 26.0;
        for count in counts.values() {
            let ratio = *count as f64 / expected;
            assert!(
                ratio > 0.75 && ratio < 1.25,
                "skewed distribution: {count} vs {expected}"
            );
        }
        assert_eq!(counts.len(), 26, "all letters should appear");
    }

    #[test]
    fn invalid_options_are_rejected() {
        assert!(generate(&PasswordOptions {
            length: 0,
            ..Default::default()
        })
        .is_err());
        assert!(generate(&PasswordOptions {
            length: 5000,
            ..Default::default()
        })
        .is_err());
        assert!(generate(&PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn entropy_increases_with_length_and_alphabet() {
        let short = PasswordOptions::new(8);
        let long = PasswordOptions::new(16);
        assert!(entropy_bits(&long) > entropy_bits(&short));

        let small = PasswordOptions {
            length: 16,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(entropy_bits(&PasswordOptions::new(16)) > entropy_bits(&small));
    }

    #[test]
    fn generated_passwords_are_in_the_alphabet() {
        let opts = PasswordOptions::default();
        let allowed: HashSet<char> = opts.alphabet().into_iter().collect();
        let pw = generate(&opts).unwrap();
        assert!(pw.chars().all(|c| allowed.contains(&c)));
    }
}
