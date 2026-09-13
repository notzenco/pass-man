//! Sync record model and local merge.
//!
//! The server stores these records opaquely; see `docs/FORMAT.md` §6. Ciphertext
//! bytes are copied verbatim from the vault, so the AEAD AAD still binds the
//! vault id and item id and the server cannot forge or move records.

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::Result;
use crate::format::VaultHeader;
use crate::model::{Item, ItemType};
use crate::storage::StoredItem;
use crate::vault::Vault;

/// A single item record as exchanged with the sync server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRecord {
    pub item_id: String,
    /// Server-assigned, strictly increasing. Zero means not yet persisted.
    #[serde(default)]
    pub revision: i64,
    pub deleted: bool,
    pub item_type: String,
    /// Base64 of `nonce || ciphertext`, byte-identical to the vault column.
    pub ciphertext: String,
    pub client_updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

impl SyncRecord {
    /// Build a record from a local stored row.
    pub fn from_stored(stored: &StoredItem, device_id: Option<String>) -> Self {
        Self {
            item_id: stored.id.clone(),
            revision: 0,
            deleted: stored.deleted,
            item_type: stored.item_type.clone(),
            ciphertext: crypto::to_base64(&stored.ciphertext),
            client_updated_at: stored.updated_at,
            device_id,
        }
    }

    /// Convert back to a storable row for a local push.
    pub fn to_stored(&self, created_at: i64) -> Result<StoredItem> {
        Ok(StoredItem {
            id: self.item_id.clone(),
            item_type: self.item_type.clone(),
            ciphertext: crypto::from_base64(&self.ciphertext)?,
            created_at,
            updated_at: self.client_updated_at,
            deleted: self.deleted,
        })
    }

    /// Decrypt this record into a full item. Requires the unlocked vault key,
    /// which the server never has.
    pub fn decrypt(
        &self,
        header: &VaultHeader,
        vault_key: &crypto::keys::SecretKey,
    ) -> Result<Item> {
        let stored = self.to_stored(self.client_updated_at)?;
        crate::storage::decrypt_item(header, vault_key, &stored)
    }
}

/// Outcome of merging a remote record into a local vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// The remote record was newer and replaced (or tombstoned) the local item.
    Applied,
    /// The local item was newer; the remote record was ignored.
    Skipped,
    /// The item type string was not recognized and the record was ignored.
    UnknownType,
}

impl Vault {
    /// Export all local rows as sync records.
    pub fn export_records(&self, device_id: Option<String>) -> Result<Vec<SyncRecord>> {
        let stored = self.storage().list_stored()?;
        Ok(stored
            .iter()
            .map(|s| SyncRecord::from_stored(s, device_id.clone()))
            .collect())
    }

    /// Merge a batch of remote records, last-writer-wins per item.
    ///
    /// A record is applied only when it decrypts successfully; a record that
    /// fails authentication is rejected rather than corrupting the local vault.
    pub fn merge_records(&self, records: &[SyncRecord]) -> Result<Vec<MergeOutcome>> {
        let header = self.header();
        let mut outcomes = Vec::with_capacity(records.len());
        for record in records {
            outcomes.push(self.merge_one(header, record)?);
        }
        Ok(outcomes)
    }

    fn merge_one(&self, header: &VaultHeader, record: &SyncRecord) -> Result<MergeOutcome> {
        if ItemType::parse(&record.item_type).is_none() {
            return Ok(MergeOutcome::UnknownType);
        }
        let local = self.storage().get_stored(&record.item_id)?;
        let local_updated = local.as_ref().map(|s| s.updated_at).unwrap_or(i64::MIN);
        if record.client_updated_at <= local_updated {
            return Ok(MergeOutcome::Skipped);
        }
        // Reject records that do not authenticate against our vault key.
        let item_key = self.vault_key_derive(&record.item_id);
        let aad = header.item_aad(&record.item_id, &record.item_type);
        let ciphertext = crypto::from_base64(&record.ciphertext)?;
        crypto::open(&item_key, &aad, &ciphertext)?;

        let created_at = local
            .as_ref()
            .map(|s| s.created_at)
            .unwrap_or(record.client_updated_at);
        self.storage().upsert_item(&record.to_stored(created_at)?)?;
        Ok(MergeOutcome::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::now_unix;
    use crate::model::ItemBody;
    use tempfile::TempDir;

    fn vault_at(path: &std::path::Path) -> Vault {
        Vault::create(path, "pw").unwrap()
    }

    #[test]
    fn push_then_pull_between_two_vaults() {
        // The server-facing flow: export from one device, merge into another
        // vault that shares the same key material. We simulate the shared key by
        // copying the vault file before diverging.
        let dir = TempDir::new().unwrap();
        let a_path = dir.path().join("a.pmvault");
        let b_path = dir.path().join("b.pmvault");

        let a = vault_at(&a_path);
        // Snapshot the empty vault as device B's starting state, so the item
        // added below exists only on A.
        drop(a);
        std::fs::copy(&a_path, &b_path).unwrap();

        let a = Vault::unlock(&a_path, "pw").unwrap();
        a.create_item(ItemType::Login, {
            let mut b = ItemBody::new("Email");
            b.password = Some("s3cret".into());
            b
        })
        .unwrap();

        let a = Vault::unlock(&a_path, "pw").unwrap();
        let b = Vault::unlock(&b_path, "pw").unwrap();

        let records = a.export_records(Some("device-a".into())).unwrap();
        assert_eq!(records.len(), 1);
        let outcomes = b.merge_records(&records).unwrap();
        assert_eq!(outcomes, vec![MergeOutcome::Applied]);
        assert_eq!(b.list_items().unwrap().len(), 1);
    }

    #[test]
    fn older_remote_record_is_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.pmvault");
        let vault = vault_at(&path);
        let id = vault
            .create_item(ItemType::Note, ItemBody::new("local"))
            .unwrap()
            .meta
            .id;

        let mut record = SyncRecord {
            item_id: id.clone(),
            revision: 1,
            deleted: false,
            item_type: "note".into(),
            ciphertext: String::new(),
            client_updated_at: now_unix() - 10_000,
            device_id: None,
        };
        // Even with a bogus body, a stale record is skipped before decryption.
        record.ciphertext = crypto::to_base64(b"garbage");
        let outcomes = vault.merge_records(&[record]).unwrap();
        assert_eq!(outcomes, vec![MergeOutcome::Skipped]);
    }

    #[test]
    fn forged_ciphertext_is_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.pmvault");
        let vault = vault_at(&path);
        let id = vault
            .create_item(ItemType::Note, ItemBody::new("x"))
            .unwrap()
            .meta
            .id;

        let record = SyncRecord {
            item_id: id,
            revision: 1,
            deleted: false,
            item_type: "note".into(),
            // Valid base64 but not a ciphertext this key can open.
            ciphertext: crypto::to_base64(&[0u8; 80]),
            client_updated_at: now_unix() + 10_000,
            device_id: None,
        };
        assert!(vault.merge_records(&[record]).is_err());
    }

    #[test]
    fn unknown_item_type_is_ignored() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.pmvault");
        let vault = vault_at(&path);
        let record = SyncRecord {
            item_id: "00000000-0000-4000-8000-000000000000".into(),
            revision: 1,
            deleted: false,
            item_type: "quantum-key".into(),
            ciphertext: crypto::to_base64(&[0u8; 80]),
            client_updated_at: now_unix() + 10_000,
            device_id: None,
        };
        assert_eq!(
            vault.merge_records(&[record]).unwrap(),
            vec![MergeOutcome::UnknownType]
        );
    }
}
