//! Cryptographic primitives for the vault format.
//!
//! See `docs/FORMAT.md` for the normative specification. This module implements
//! exactly the operations described there and nothing else.

pub mod keys;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Number of random bytes in every nonce.
pub const NONCE_LEN: usize = 24;
/// Number of bytes in every symmetric key.
pub const KEY_LEN: usize = 32;
/// Number of bytes in the Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;
/// Number of random bytes in a KDF salt.
pub const SALT_LEN: usize = 16;

/// Default Argon2id memory cost, in KiB (64 MiB).
pub const DEFAULT_M_COST: u32 = 65_536;
/// Default Argon2id iteration count.
pub const DEFAULT_T_COST: u32 = 3;
/// Default Argon2id parallelism.
pub const DEFAULT_P_COST: u32 = 1;

/// Argon2id parameters recorded in a vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    /// Reject parameters that Argon2 itself would refuse or that are absurdly
    /// weak, so a tampered header cannot downgrade the KDF.
    pub fn validate(&self) -> Result<()> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|_| Error::InvalidField("kdf params".into()))?;
        if params.m_cost() < 8 || params.t_cost() < 1 || params.p_cost() < 1 {
            return Err(Error::InvalidField("kdf params".into()));
        }
        Ok(())
    }
}

/// Fill `buf` with cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    rand::rngs::OsRng.fill_bytes(buf);
}

/// Generate a fresh random 32-byte key.
pub fn random_key() -> keys::SecretKey {
    let mut bytes = [0u8; KEY_LEN];
    random_bytes(&mut bytes);
    keys::SecretKey::from_bytes(bytes)
}

/// Generate a fresh 24-byte nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce);
    nonce
}

/// Generate a fresh 16-byte salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt);
    salt
}

/// Derive the master key from a password and the header's KDF parameters.
pub fn derive_master_key(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<keys::SecretKey> {
    params.validate()?;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|_| Error::InvalidField("kdf params".into()))?,
    );
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| Error::Crypto)?;
    let key = keys::SecretKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// Encrypt `plaintext` with XChaCha20-Poly1305, returning `nonce || ciphertext`.
pub fn seal(key: &keys::SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    let nonce_bytes = random_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `nonce || ciphertext` with XChaCha20-Poly1305.
pub fn open(key: &keys::SecretKey, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::ShortCiphertext);
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::BadCredentials)
}

/// Encrypt with additional data derived by the caller; used for key wrapping.
pub fn seal_key(
    key: &keys::SecretKey,
    aad: &[u8],
    plaintext_key: &keys::SecretKey,
) -> Result<Vec<u8>> {
    seal(key, aad, plaintext_key.expose())
}

/// Decrypt a wrapped key.
pub fn open_key(key: &keys::SecretKey, aad: &[u8], sealed: &[u8]) -> Result<keys::SecretKey> {
    let bytes = open(key, aad, sealed)?;
    if bytes.len() != KEY_LEN {
        return Err(Error::Corrupt("wrapped key has wrong length".into()));
    }
    let mut buf = [0u8; KEY_LEN];
    buf.copy_from_slice(&bytes);
    Ok(keys::SecretKey::from_bytes(buf))
}

/// Encode bytes as standard base64 (with padding).
pub fn to_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode standard base64.
pub fn from_base64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = random_key();
        let msg = b"hello vault";
        let sealed = seal(&key, b"aad", msg).unwrap();
        assert_eq!(open(&key, b"aad", &sealed).unwrap(), msg);
    }

    #[test]
    fn open_fails_with_wrong_aad() {
        let key = random_key();
        let sealed = seal(&key, b"aad", b"secret").unwrap();
        assert!(open(&key, b"other", &sealed).is_err());
    }

    #[test]
    fn open_fails_with_wrong_key() {
        let key = random_key();
        let other = random_key();
        let sealed = seal(&key, b"", b"secret").unwrap();
        assert!(open(&other, b"", &sealed).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let key = random_key();
        let mut sealed = seal(&key, b"", b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(open(&key, b"", &sealed).is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let key = random_key();
        let a = seal(&key, b"", b"x").unwrap();
        let b = seal(&key, b"", b"x").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_is_deterministic() {
        let salt = random_salt();
        let params = KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let a = derive_master_key("hunter2", &salt, params).unwrap();
        let b = derive_master_key("hunter2", &salt, params).unwrap();
        let c = derive_master_key("hunter3", &salt, params).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    #[test]
    fn base64_roundtrip() {
        let data = vec![0u8, 1, 2, 250, 255];
        let encoded = to_base64(&data);
        assert_eq!(from_base64(&encoded).unwrap(), data);
    }
}
