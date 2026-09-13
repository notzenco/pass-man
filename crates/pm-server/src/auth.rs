//! Account authentication.
//!
//! Account passwords authenticate to the *server* and are distinct from vault
//! master passwords. The server stores an Argon2id PHC hash it can verify but
//! from which it cannot recover a password. Sessions are opaque random tokens.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;

use crate::db::Account;
use crate::error::{ApiError, ApiResult};

/// Session lifetime in seconds (30 days).
pub const SESSION_TTL_SECS: i64 = 60 * 60 * 24 * 30;

/// Hash an account password for storage.
pub fn hash_password(password: &str) -> ApiResult<String> {
    let mut salt_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|_| ApiError::BadRequest("could not generate salt".into()))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::BadRequest("could not hash password".into()))
}

/// Verify a password against a stored PHC hash.
pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Generate a new session token: 32 random bytes as URL-safe base64.
pub fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    pm_core::crypto::to_base64(&bytes)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Minimal input validation so obviously malformed requests fail early.
pub fn validate_credentials(email: &str, password: &str) -> ApiResult<()> {
    let email = email.trim();
    if email.len() < 3 || !email.contains('@') || email.len() > 254 {
        return Err(ApiError::BadRequest("invalid email".into()));
    }
    if password.len() < 10 {
        return Err(ApiError::BadRequest(
            "account password must be at least 10 characters".into(),
        ));
    }
    if password.len() > 1024 {
        return Err(ApiError::BadRequest("account password too long".into()));
    }
    Ok(())
}

/// A fixed hash used to keep login timing uniform when the email is unknown.
/// Generated once on first use; never corresponds to a real account.
fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("dummy-password-for-timing").unwrap_or_default())
}

/// Authenticate and return the account, or `Unauthorized`.
///
/// Verification runs even when the account is absent, so an attacker cannot
/// distinguish "unknown email" from "wrong password" by response time.
pub fn authenticate(account: Option<Account>, password: &str) -> ApiResult<Account> {
    let Some(account) = account else {
        let _ = verify_password(password, dummy_hash());
        return Err(ApiError::Unauthorized);
    };
    if !verify_password(password, &account.password_hash) {
        return Err(ApiError::Unauthorized);
    }
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_verifies() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn hash_is_salted_per_call() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tokens_are_url_safe_and_unique() {
        let a = new_session_token();
        let b = new_session_token();
        assert_ne!(a, b);
        assert!(!a.contains('+') && !a.contains('/') && !a.contains('='));
    }

    #[test]
    fn credential_validation() {
        assert!(validate_credentials("a@b.co", "longenough1").is_ok());
        assert!(validate_credentials("nope", "longenough1").is_err());
        assert!(validate_credentials("a@b.co", "short").is_err());
    }
}
