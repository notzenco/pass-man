//! On-disk vault header and the AAD strings bound into every AEAD operation.
//!
//! The header is the only unencrypted structured part of a vault besides the
//! `items` table's routing columns. See `docs/FORMAT.md` §4.

use serde::{Deserialize, Serialize};

use crate::crypto::keys::SecretKey;
use crate::crypto::{self, KdfParams, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};

/// Format version this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;

/// Algorithm identifiers. Strings, not numbers, so unknown values are explicit.
pub const KDF_ARGON2ID_V1: &str = "argon2id-v1";
/// Key id for the master-password wrap.
pub const KEY_ID_MASTER: &str = "m";

const AAD_KEY_WRAP: &[u8] = b"pmvault/v1/key-wrap";
const AAD_ITEM: &[u8] = b"pmvault/v1/item";

/// The decrypted in-memory header of an unlocked vault.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub format_version: u32,
    pub vault_id: uuid::Uuid,
    pub kdf_algorithm: String,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: KdfParams,
    pub created_at: i64,
    pub updated_at: i64,
}

impl VaultHeader {
    /// Build a fresh header for a new vault.
    pub fn new() -> Self {
        let now = now_unix();
        Self {
            format_version: FORMAT_VERSION,
            vault_id: uuid::Uuid::new_v4(),
            kdf_algorithm: KDF_ARGON2ID_V1.to_string(),
            kdf_salt: crypto::random_salt().to_vec(),
            kdf_params: KdfParams::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Reject anything this build cannot safely interpret.
    pub fn validate(&self) -> Result<()> {
        if self.format_version > FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: self.format_version,
                supported: FORMAT_VERSION,
            });
        }
        if self.kdf_algorithm != KDF_ARGON2ID_V1 {
            return Err(Error::UnsupportedAlgorithm(self.kdf_algorithm.clone()));
        }
        if self.kdf_salt.len() != crypto::SALT_LEN {
            return Err(Error::Corrupt("bad kdf salt length".into()));
        }
        self.kdf_params.validate()?;
        Ok(())
    }

    /// AAD for wrapping or unwrapping the vault key.
    pub fn key_wrap_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_KEY_WRAP.len() + 16);
        aad.extend_from_slice(AAD_KEY_WRAP);
        aad.extend_from_slice(self.vault_id.as_bytes());
        aad
    }

    /// AAD for an item body, binding id and type.
    pub fn item_aad(&self, item_id: &str, item_type: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_ITEM.len() + 16 + item_id.len() + item_type.len());
        aad.extend_from_slice(AAD_ITEM);
        aad.extend_from_slice(self.vault_id.as_bytes());
        aad.extend_from_slice(item_id.as_bytes());
        aad.extend_from_slice(item_type.as_bytes());
        aad
    }
}

impl Default for VaultHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// A vault key wrapped for one reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWrap {
    pub key_id: String,
    pub sealed: Vec<u8>,
}

impl KeyWrap {
    /// Wrap `vault_key` under `master_key`.
    pub fn wrap_master(master_key: &SecretKey, vault_key: &SecretKey, aad: &[u8]) -> Result<Self> {
        Ok(Self {
            key_id: KEY_ID_MASTER.to_string(),
            sealed: crypto::seal_key(master_key, aad, vault_key)?,
        })
    }

    /// Unwrap the vault key. Fails with `BadCredentials` on a wrong password.
    pub fn unwrap(&self, master_key: &SecretKey, aad: &[u8]) -> Result<SecretKey> {
        if self.sealed.len() != NONCE_LEN + KEY_LEN + TAG_LEN {
            return Err(Error::Corrupt("bad key wrap length".into()));
        }
        crypto::open_key(master_key, aad, &self.sealed)
    }
}

/// Current time as unix seconds.
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Generate a fresh random vault key.
pub fn new_vault_key() -> SecretKey {
    crypto::random_key()
}

/// Generate a fresh random item id.
pub fn new_item_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_newer_than_supported_is_rejected() {
        let mut header = VaultHeader::new();
        header.format_version = FORMAT_VERSION + 1;
        assert!(matches!(
            header.validate(),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn unknown_kdf_is_rejected() {
        let mut header = VaultHeader::new();
        header.kdf_algorithm = "rot13-v1".into();
        assert!(matches!(
            header.validate(),
            Err(Error::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn item_aad_is_unique_per_item_and_type() {
        let header = VaultHeader::new();
        let a = header.item_aad("id-1", "login");
        let b = header.item_aad("id-2", "login");
        let c = header.item_aad("id-1", "note");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn wrong_password_cannot_unwrap() {
        let header = VaultHeader::new();
        let aad = header.key_wrap_aad();
        let vault_key = new_vault_key();
        let master = crypto::random_key();
        let wrong = crypto::random_key();
        let wrap = KeyWrap::wrap_master(&master, &vault_key, &aad).unwrap();
        assert!(wrap.unwrap(&master, &aad).is_ok());
        assert!(wrap.unwrap(&wrong, &aad).is_err());
    }

    #[test]
    fn key_wrap_is_bound_to_vault_id() {
        let header = VaultHeader::new();
        let vault_key = new_vault_key();
        let master = crypto::random_key();
        let wrap = KeyWrap::wrap_master(&master, &vault_key, &header.key_wrap_aad()).unwrap();

        let mut other = VaultHeader::new();
        other.vault_id = uuid::Uuid::new_v4();
        assert!(wrap.unwrap(&master, &other.key_wrap_aad()).is_err());
    }
}
