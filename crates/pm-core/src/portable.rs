//! A portable, in-memory vault container for platforms without SQLite.
//!
//! Browser extensions and other WASM environments cannot run SQLite, so they use
//! this container instead of [`crate::storage`]. It shares the exact same
//! header, key hierarchy, AAD construction, and AEAD operations as the file
//! vault, so a portable vault and a file vault with the same key material are
//! interchangeable at the crypto layer.
//!
//! The container serializes to JSON. Callers are responsible for persisting that
//! JSON wherever they like (for example `chrome.storage.local`); it is already
//! fully encrypted.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::crypto;
use crate::crypto::keys::SecretKey;
use crate::error::{Error, Result};
use crate::format::{self, KeyWrap, VaultHeader};
use crate::model::{Item, ItemBody, ItemMeta, ItemType};

/// One encrypted record inside a portable vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableRecord {
    pub item_id: String,
    pub item_type: String,
    /// Base64 of `nonce || ciphertext`, identical in form to the file vault.
    pub ciphertext: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub deleted: bool,
}

/// The serialized form of a portable vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableBlob {
    pub format_version: u32,
    pub vault_id: String,
    pub kdf_algorithm: String,
    pub kdf_salt: String,
    pub kdf_m_cost: u32,
    pub kdf_t_cost: u32,
    pub kdf_p_cost: u32,
    pub key_wrap_id: String,
    pub key_wrap: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub records: Vec<PortableRecord>,
}

/// An unlocked portable vault holding live key material.
pub struct PortableVault {
    header: VaultHeader,
    vault_key: SecretKey,
    records: BTreeMap<String, PortableRecord>,
}

impl PortableVault {
    /// Create a new empty portable vault.
    pub fn create(password: &str) -> Result<(Self, String)> {
        let header = VaultHeader::new();
        let master_key = crypto::derive_master_key(password, &header.kdf_salt, header.kdf_params)?;
        let vault_key = format::new_vault_key();
        let wrap = KeyWrap::wrap_master(&master_key, &vault_key, &header.key_wrap_aad())?;
        let vault = Self {
            header,
            vault_key,
            records: BTreeMap::new(),
        };
        let blob = vault.to_blob_string(&wrap)?;
        Ok((vault, blob))
    }

    /// Unlock a portable vault from its serialized blob.
    pub fn unlock(blob: &str, password: &str) -> Result<Self> {
        let parsed: PortableBlob = serde_json::from_str(blob)?;
        if parsed.format_version > format::FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: parsed.format_version,
                supported: format::FORMAT_VERSION,
            });
        }
        let vault_id = uuid::Uuid::parse_str(&parsed.vault_id)
            .map_err(|_| Error::Corrupt("bad vault_id".into()))?;
        let header = VaultHeader {
            format_version: parsed.format_version,
            vault_id,
            kdf_algorithm: parsed.kdf_algorithm.clone(),
            kdf_salt: crypto::from_base64(&parsed.kdf_salt)?,
            kdf_params: crypto::KdfParams {
                m_cost: parsed.kdf_m_cost,
                t_cost: parsed.kdf_t_cost,
                p_cost: parsed.kdf_p_cost,
            },
            created_at: parsed.created_at,
            updated_at: parsed.updated_at,
        };
        header.validate()?;

        let wrap = KeyWrap {
            key_id: parsed.key_wrap_id.clone(),
            sealed: crypto::from_base64(&parsed.key_wrap)?,
        };
        let master_key = crypto::derive_master_key(password, &header.kdf_salt, header.kdf_params)?;
        let vault_key = wrap.unwrap(&master_key, &header.key_wrap_aad())?;

        let mut records = BTreeMap::new();
        for record in &parsed.records {
            records.insert(record.item_id.clone(), record.clone());
        }
        Ok(Self {
            header,
            vault_key,
            records,
        })
    }

    /// The vault's stable identifier.
    pub fn vault_id(&self) -> uuid::Uuid {
        self.header.vault_id
    }

    /// Serialize the current state, re-wrapping the vault key for `password`.
    ///
    /// The wrap is recomputed so the returned blob can be unlocked with
    /// `password` regardless of how the vault was originally opened.
    pub fn to_blob(&self, password: &str) -> Result<String> {
        let master_key =
            crypto::derive_master_key(password, &self.header.kdf_salt, self.header.kdf_params)?;
        let wrap = KeyWrap::wrap_master(&master_key, &self.vault_key, &self.header.key_wrap_aad())?;
        self.to_blob_string(&wrap)
    }

    /// Serialize with an existing key wrap.
    pub fn to_blob_string(&self, wrap: &KeyWrap) -> Result<String> {
        let blob = PortableBlob {
            format_version: self.header.format_version,
            vault_id: self.header.vault_id.to_string(),
            kdf_algorithm: self.header.kdf_algorithm.clone(),
            kdf_salt: crypto::to_base64(&self.header.kdf_salt),
            kdf_m_cost: self.header.kdf_params.m_cost,
            kdf_t_cost: self.header.kdf_params.t_cost,
            kdf_p_cost: self.header.kdf_params.p_cost,
            key_wrap_id: wrap.key_id.clone(),
            key_wrap: crypto::to_base64(&wrap.sealed),
            created_at: self.header.created_at,
            updated_at: self.header.updated_at,
            records: self.records.values().cloned().collect(),
        };
        Ok(serde_json::to_string(&blob)?)
    }

    /// Create an item.
    pub fn create_item(&mut self, item_type: ItemType, body: ItemBody) -> Result<Item> {
        let now = format::now_unix();
        let id = format::new_item_id();
        self.put(id.clone(), item_type, &body, now, now, false)?;
        Ok(Item {
            meta: ItemMeta {
                id,
                item_type,
                created_at: now,
                updated_at: now,
                deleted: false,
            },
            body,
        })
    }

    /// Get a non-deleted item.
    pub fn get_item(&self, id: &str) -> Result<Item> {
        let record = self
            .records
            .get(id)
            .ok_or_else(|| Error::ItemNotFound(id.into()))?;
        if record.deleted {
            return Err(Error::ItemNotFound(id.into()));
        }
        self.decrypt(id, record)
    }

    /// List non-deleted items.
    pub fn list_items(&self) -> Result<Vec<Item>> {
        self.records
            .values()
            .filter(|r| !r.deleted)
            .map(|r| self.decrypt(&r.item_id, r))
            .collect()
    }

    /// Update an item.
    pub fn update_item(&mut self, id: &str, item_type: ItemType, body: ItemBody) -> Result<Item> {
        let existing = self
            .records
            .get(id)
            .ok_or_else(|| Error::ItemNotFound(id.into()))?;
        if existing.deleted {
            return Err(Error::ItemNotFound(id.into()));
        }
        let created_at = existing.created_at;
        let now = format::now_unix();
        self.put(id.to_string(), item_type, &body, created_at, now, false)?;
        Ok(Item {
            meta: ItemMeta {
                id: id.to_string(),
                item_type,
                created_at,
                updated_at: now,
                deleted: false,
            },
            body,
        })
    }

    /// Mark an item deleted, keeping a tombstone.
    pub fn delete_item(&mut self, id: &str) -> Result<()> {
        let mut record = self
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| Error::ItemNotFound(id.into()))?;
        record.deleted = true;
        record.updated_at = format::now_unix();
        self.records.insert(id.to_string(), record);
        Ok(())
    }

    /// All records including tombstones, for sync export.
    pub fn records(&self) -> Vec<PortableRecord> {
        self.records.values().cloned().collect()
    }

    /// Merge records using last-writer-wins, rejecting ones that do not
    /// authenticate against this vault's key.
    pub fn merge(&mut self, incoming: &[PortableRecord]) -> Result<usize> {
        let mut applied = 0;
        for record in incoming {
            if ItemType::parse(&record.item_type).is_none() {
                continue;
            }
            let local_updated = self
                .records
                .get(&record.item_id)
                .map(|r| r.updated_at)
                .unwrap_or(i64::MIN);
            if record.updated_at <= local_updated {
                continue;
            }
            // Verify authenticity before storing.
            let aad = self.header.item_aad(&record.item_id, &record.item_type);
            let key = self.vault_key.derive_item_key(&record.item_id);
            crypto::open(&key, &aad, &crypto::from_base64(&record.ciphertext)?)?;
            self.records.insert(record.item_id.clone(), record.clone());
            applied += 1;
        }
        Ok(applied)
    }

    fn decrypt(&self, id: &str, record: &PortableRecord) -> Result<Item> {
        let item_type = ItemType::parse(&record.item_type)
            .ok_or_else(|| Error::Corrupt(format!("unknown item type `{}`", record.item_type)))?;
        let aad = self.header.item_aad(id, &record.item_type);
        let key = self.vault_key.derive_item_key(id);
        let plaintext = crypto::open(&key, &aad, &crypto::from_base64(&record.ciphertext)?)?;
        let body: ItemBody = serde_json::from_slice(&plaintext)?;
        Ok(Item {
            meta: ItemMeta {
                id: id.to_string(),
                item_type,
                created_at: record.created_at,
                updated_at: record.updated_at,
                deleted: record.deleted,
            },
            body,
        })
    }

    fn put(
        &mut self,
        id: String,
        item_type: ItemType,
        body: &ItemBody,
        created_at: i64,
        updated_at: i64,
        deleted: bool,
    ) -> Result<()> {
        let aad = self.header.item_aad(&id, item_type.as_str());
        let key = self.vault_key.derive_item_key(&id);
        let ciphertext = crypto::seal(&key, &aad, &serde_json::to_vec(body)?)?;
        self.records.insert(
            id.clone(),
            PortableRecord {
                item_id: id,
                item_type: item_type.as_str().to_string(),
                ciphertext: crypto::to_base64(&ciphertext),
                created_at,
                updated_at,
                deleted,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(title: &str, password: &str) -> ItemBody {
        let mut body = ItemBody::new(title);
        body.password = Some(password.into());
        body
    }

    #[test]
    fn create_unlock_roundtrip() {
        let (mut vault, initial_blob) = PortableVault::create("pw").unwrap();
        // The blob returned at creation is already unlockable.
        PortableVault::unlock(&initial_blob, "pw").unwrap();

        let id = vault
            .create_item(ItemType::Login, login("Email", "s3cret"))
            .unwrap()
            .meta
            .id;
        let blob = vault.to_blob("pw").unwrap();

        let unlocked = PortableVault::unlock(&blob, "pw").unwrap();
        assert_eq!(
            unlocked.get_item(&id).unwrap().body.password.as_deref(),
            Some("s3cret")
        );
        assert!(!blob.is_empty());
    }

    #[test]
    fn wrong_password_fails() {
        let (_vault, blob) = PortableVault::create("right").unwrap();
        assert!(matches!(
            PortableVault::unlock(&blob, "wrong"),
            Err(Error::BadCredentials)
        ));
    }

    #[test]
    fn blob_does_not_leak_plaintext() {
        let (mut vault, _blob) = PortableVault::create("pw").unwrap();
        vault
            .create_item(ItemType::Login, login("Bank", "top-secret-value"))
            .unwrap();
        let blob = vault.to_blob("pw").unwrap();
        assert!(!blob.contains("top-secret-value"));
        assert!(!blob.contains("Bank"));
    }

    #[test]
    fn merge_rejects_forged_record() {
        let (mut a, _) = PortableVault::create("pw").unwrap();
        let item = a.create_item(ItemType::Note, ItemBody::new("x")).unwrap();
        let mut forged = a.records()[0].clone();
        forged.updated_at += 100;
        forged.ciphertext = crypto::to_base64(&[0u8; 80]);
        assert!(a.merge(&[forged]).is_err());
        let _ = item;
    }

    #[test]
    fn merge_applies_newer_and_skips_older() {
        let (mut a, _) = PortableVault::create("pw").unwrap();
        let id = a
            .create_item(ItemType::Note, ItemBody::new("title"))
            .unwrap()
            .meta
            .id;
        let good = a.records()[0].clone();

        let mut older = good.clone();
        older.updated_at -= 100;
        assert_eq!(a.merge(&[older]).unwrap(), 0);

        let mut newer = good.clone();
        newer.updated_at += 100;
        assert_eq!(a.merge(&[newer]).unwrap(), 1);
        let _ = id;
    }
}
