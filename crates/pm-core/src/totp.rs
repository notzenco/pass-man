//! Time-based one-time passwords (RFC 6238, built on RFC 4226 HOTP).
//!
//! Implemented directly on `hmac` + `sha1` so there is no third-party TOTP crate
//! in the trust path. Both SHA-1 and SHA-256 secrets are supported; SHA-1 is the
//! de-facto default for authenticator apps.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// Hash algorithm for TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
}

/// TOTP parameters. Defaults match what authenticator apps expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    /// Number of digits in the code (6 or 8).
    pub digits: u32,
    /// Time step in seconds.
    pub period: u64,
    pub algorithm: TotpAlgorithm,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
        }
    }
}

impl TotpParams {
    /// Validate the parameters.
    pub fn validate(&self) -> Result<()> {
        if self.digits != 6 && self.digits != 8 {
            return Err(Error::InvalidField("totp digits (must be 6 or 8)".into()));
        }
        if self.period == 0 {
            return Err(Error::InvalidField("totp period".into()));
        }
        Ok(())
    }
}

/// Compute the HOTP value for a counter (RFC 4226).
fn hotp(secret: &[u8], counter: u64, params: &TotpParams) -> Result<u32> {
    let msg = counter.to_be_bytes();
    let mac_bytes: Vec<u8> = match params.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(secret)
                .map_err(|_| Error::InvalidField("totp secret".into()))?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|_| Error::InvalidField("totp secret".into()))?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation per RFC 4226 section 5.3.
    let offset = (mac_bytes[mac_bytes.len() - 1] & 0x0f) as usize;
    if offset + 4 > mac_bytes.len() {
        return Err(Error::Crypto);
    }
    let binary = ((mac_bytes[offset] as u32 & 0x7f) << 24)
        | ((mac_bytes[offset + 1] as u32) << 16)
        | ((mac_bytes[offset + 2] as u32) << 8)
        | (mac_bytes[offset + 3] as u32);

    let modulus = 10u32.pow(params.digits);
    Ok(binary % modulus)
}

/// Generate the code for a given unix time.
pub fn code_at(secret: &[u8], unix_seconds: u64, params: TotpParams) -> Result<String> {
    params.validate()?;
    if secret.is_empty() {
        return Err(Error::InvalidField("totp secret is empty".into()));
    }
    let counter = unix_seconds / params.period;
    let value = hotp(secret, counter, &params)?;
    Ok(format!("{:0width$}", value, width = params.digits as usize))
}

/// Generate the current code.
pub fn now(secret: &[u8], params: TotpParams) -> Result<String> {
    code_at(secret, crate::format::now_unix().max(0) as u64, params)
}

/// Seconds remaining until the current code expires.
pub fn seconds_remaining(period: u64, unix_seconds: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    period - (unix_seconds % period)
}

/// Verify a code, allowing `skew` steps before and after the current one to
/// tolerate clock drift. Returns the matched step offset if valid.
pub fn verify(
    secret: &[u8],
    code: &str,
    unix_seconds: u64,
    params: TotpParams,
    skew: u64,
) -> Result<bool> {
    params.validate()?;
    let expected_len = params.digits as usize;
    let candidate: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if candidate.len() != expected_len {
        return Ok(false);
    }
    let current_step = unix_seconds / params.period;
    let low = current_step.saturating_sub(skew);
    for step in low..=current_step + skew {
        let value = hotp(secret, step, &params)?;
        let rendered = format!("{:0width$}", value, width = expected_len);
        // Constant-time-ish comparison: avoid early exit on the first mismatch.
        if rendered.len() == candidate.len()
            && rendered
                .bytes()
                .zip(candidate.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Decode a base32 secret as used in `otpauth://` URIs.
///
/// Accepts upper/lowercase, ignores spaces and dashes, and tolerates missing
/// padding. This is the format authenticator apps display and export.
pub fn decode_base32(secret: &str) -> Result<Vec<u8>> {
    let mut bits = 0u64;
    let mut bit_count = 0u32;
    let mut out = Vec::new();
    for ch in secret.chars() {
        if ch == ' ' || ch == '-' || ch == '=' {
            continue;
        }
        let value = match ch.to_ascii_uppercase() {
            'A'..='Z' => ch.to_ascii_uppercase() as u8 - b'A',
            '2'..='7' => ch as u8 - b'2' + 26,
            other => {
                return Err(Error::InvalidField(format!(
                    "invalid base32 character `{other}`"
                )))
            }
        };
        bits = (bits << 5) | value as u64;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    if out.is_empty() {
        return Err(Error::InvalidField("empty base32 secret".into()));
    }
    Ok(out)
}

/// Parse an `otpauth://totp/...` URI, returning the secret and parameters.
pub fn parse_otpauth_uri(uri: &str) -> Result<(Vec<u8>, TotpParams, Option<String>)> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .or_else(|| uri.strip_prefix("otpauth://TOTP/"))
        .ok_or_else(|| Error::InvalidField("not a totp otpauth uri".into()))?;
    let (label, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };

    let mut secret = None;
    let mut digits = 6;
    let mut period = 30u64;
    let mut algorithm = TotpAlgorithm::Sha1;

    for pair in query.split('&') {
        let (key, value) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(decode_base32(value)?),
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| Error::InvalidField("digits".into()))?
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| Error::InvalidField("period".into()))?
            }
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    other => return Err(Error::UnsupportedAlgorithm(format!("totp {other}"))),
                }
            }
            _ => {}
        }
    }

    let secret = secret.ok_or_else(|| Error::InvalidField("uri missing secret".into()))?;
    let params = TotpParams {
        digits,
        period,
        algorithm,
    };
    params.validate()?;
    let label = percent_decode(label);
    Ok((secret, params, Some(label)))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors, seed = "12345678901234567890" (ASCII).
    const SEED_SHA1: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_vectors() {
        let params = TotpParams {
            digits: 8,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
        };
        let cases = [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (time, expected) in cases {
            assert_eq!(
                code_at(SEED_SHA1, time, params).unwrap(),
                expected,
                "t={time}"
            );
        }
    }

    #[test]
    fn six_digit_codes_are_zero_padded() {
        let params = TotpParams {
            digits: 6,
            ..Default::default()
        };
        let code = code_at(SEED_SHA1, 1_111_111_109, params).unwrap();
        assert_eq!(
            code,
            &"07081804"[2..],
            "6 digits should be the low 6 of the 8-digit value"
        );
        assert_eq!(code.len(), 6);
        assert!(code.starts_with('0') || code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn base32_decoding_matches_known_secret() {
        // "JBSWY3DPEHPK3PXP" is the canonical "Hello!" example secret.
        let decoded = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decoded, b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn base32_accepts_lowercase_spaces_and_padding() {
        let a = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        let b = decode_base32("jbswy3dp ehpk3pxp====").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn base32_rejects_invalid_characters() {
        assert!(decode_base32("JBSWY3DP1").is_err()); // 1 is not in base32
        assert!(decode_base32("!@#$").is_err());
    }

    #[test]
    fn otpauth_uri_parses() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30";
        let (secret, params, label) = parse_otpauth_uri(uri).unwrap();
        assert_eq!(secret, decode_base32("JBSWY3DPEHPK3PXP").unwrap());
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
        assert_eq!(label.as_deref(), Some("Example:alice@example.com"));
    }

    #[test]
    fn otpauth_uri_percent_decodes_label() {
        let uri = "otpauth://totp/My%20Site?secret=JBSWY3DPEHPK3PXP";
        let (_, _, label) = parse_otpauth_uri(uri).unwrap();
        assert_eq!(label.as_deref(), Some("My Site"));
    }

    #[test]
    fn otpauth_uri_rejects_non_totp() {
        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=JBSWY3DP").is_err());
        assert!(parse_otpauth_uri("https://example.com").is_err());
    }

    #[test]
    fn verify_accepts_current_and_drifted_codes() {
        let params = TotpParams::default();
        let now = 1_111_111_111u64;
        let code = code_at(SEED_SHA1, now, params).unwrap();
        assert!(verify(SEED_SHA1, &code, now, params, 1).unwrap());
        // One step earlier, within skew.
        let prev = code_at(SEED_SHA1, now - 30, params).unwrap();
        assert!(verify(SEED_SHA1, &prev, now, params, 1).unwrap());
        // Far outside skew.
        let old = code_at(SEED_SHA1, now - 300, params).unwrap();
        assert!(!verify(SEED_SHA1, &old, now, params, 1).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_length_and_nondigits() {
        let params = TotpParams::default();
        let now = 1_111_111_111u64;
        let code = code_at(SEED_SHA1, now, params).unwrap();
        assert!(!verify(SEED_SHA1, "12345", now, params, 1).unwrap());
        assert!(!verify(SEED_SHA1, "abcdef", now, params, 1).unwrap());
        assert!(!verify(SEED_SHA1, &code, now + 30 * 100, params, 1).unwrap());
    }

    #[test]
    fn seconds_remaining_counts_down() {
        assert_eq!(seconds_remaining(30, 0), 30);
        assert_eq!(seconds_remaining(30, 1), 29);
        assert_eq!(seconds_remaining(30, 29), 1);
        assert_eq!(seconds_remaining(30, 30), 30);
    }

    #[test]
    fn empty_secret_is_rejected() {
        assert!(code_at(&[], 0, TotpParams::default()).is_err());
    }

    #[test]
    fn invalid_digits_are_rejected() {
        let params = TotpParams {
            digits: 7,
            ..Default::default()
        };
        assert!(code_at(SEED_SHA1, 0, params).is_err());
    }
}
