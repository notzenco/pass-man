//! The high-level vault API.
//!
//! [`Vault`] is the only type a UI needs. It owns the unlocked key material and
//! a [`Storage`] handle, and exposes create, unlock, lock, and CRUD operations.
//! Dropping or locking a vault zeroizes the derived keys.

use std::path::Path;

use crate::crypto;
use crate::crypto::keys::SecretKey;
use crate::error::{Error, Result};
use crate::format::{self, KeyWrap, VaultHeader};
use crate::model::{Item, ItemBody, ItemMeta, ItemType};
use crate::storage::{decrypt_item, Storage, StoredItem};

/// A vault that has been created or unlocked and holds live key material.
pub struct Vault {
    header: VaultHeader,
    vault_key: SecretKey,
    storage: Storage,
    dirty: bool,
}

impl Vault {
    /// Create a new vault at `path` protected by `password`.
    ///
    /// Fails if the file already holds an initialized vault.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        let header = VaultHeader::new();
        let storage = Storage::open(path)?;
        let master_key = crypto::derive_master_key(password, &header.kdf_salt, header.kdf_params)?;
        let vault_key = format::new_vault_key();
        let wrap = KeyWrap::wrap_master(&master_key, &vault_key, &header.key_wrap_aad())?;
        storage.write_new_header(&header, &wrap)?;
        Ok(Self {
            header,
            vault_key,
            storage,
            dirty: false,
        })
    }

    /// Open an existing vault with `password`.
    pub fn unlock(path: &Path, password: &str) -> Result<Self> {
        let storage = Storage::open(path)?;
        if !storage.is_initialized()? {
            return Err(Error::Corrupt("file is not a vault".into()));
        }
        let (header, wrap) = storage.read_header()?;
        let master_key = crypto::derive_master_key(password, &header.kdf_salt, header.kdf_params)?;
        let vault_key = wrap.unwrap(&master_key, &header.key_wrap_aad())?;
        Ok(Self {
            header,
            vault_key,
            storage,
            dirty: false,
        })
    }

    /// The vault's stable identifier.
    pub fn vault_id(&self) -> uuid::Uuid {
        self.header.vault_id
    }

    /// The full header, for diagnostics and sync metadata.
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Whether there are unsaved changes. The format writes eagerly, so this
    /// tracks only header-level updates such as password changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Access the underlying storage.
    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Create a new item and return it.
    pub fn create_item(&self, item_type: ItemType, body: ItemBody) -> Result<Item> {
        let now = format::now_unix();
        let id = format::new_item_id();
        let stored = self.seal_body(&id, item_type, &body, now, now, false)?;
        self.storage.upsert_item(&stored)?;
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

    /// Fetch a non-deleted item by id.
    pub fn get_item(&self, id: &str) -> Result<Item> {
        let stored = self
            .storage
            .get_stored(id)?
            .ok_or_else(|| Error::ItemNotFound(id.into()))?;
        if stored.deleted {
            return Err(Error::ItemNotFound(id.into()));
        }
        decrypt_item(&self.header, &self.vault_key, &stored)
    }

    /// List all non-deleted items, oldest first.
    pub fn list_items(&self) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        for stored in self.storage.list_stored()? {
            if stored.deleted {
                continue;
            }
            items.push(decrypt_item(&self.header, &self.vault_key, &stored)?);
        }
        Ok(items)
    }

    /// Replace an item's type and body, bumping `updated_at`.
    pub fn update_item(&self, id: &str, item_type: ItemType, body: ItemBody) -> Result<Item> {
        let existing = self
            .storage
            .get_stored(id)?
            .ok_or_else(|| Error::ItemNotFound(id.into()))?;
        if existing.deleted {
            return Err(Error::ItemNotFound(id.into()));
        }
        let now = format::now_unix();
        let stored = self.seal_body(id, item_type, &body, existing.created_at, now, false)?;
        self.storage.upsert_item(&stored)?;
        Ok(Item {
            meta: ItemMeta {
                id: id.to_string(),
                item_type,
                created_at: existing.created_at,
                updated_at: now,
                deleted: false,
            },
            body,
        })
    }

    /// Mark an item deleted, leaving a tombstone for sync.
    pub fn delete_item(&self, id: &str) -> Result<()> {
        let existing = self
            .storage
            .get_stored(id)?
            .ok_or_else(|| Error::ItemNotFound(id.into()))?;
        let now = format::now_unix();
        self.storage.upsert_item(&StoredItem {
            id: existing.id,
            item_type: existing.item_type,
            ciphertext: existing.ciphertext,
            created_at: existing.created_at,
            updated_at: now,
            deleted: true,
        })?;
        Ok(())
    }

    /// Change the master password by re-wrapping the vault key.
    ///
    /// Item rows are untouched. The caller must supply the current password so a
    /// vault left unlocked cannot be silently taken over.
    pub fn change_password(&self, current: &str, new_password: &str) -> Result<()> {
        let master_old =
            crypto::derive_master_key(current, &self.header.kdf_salt, self.header.kdf_params)?;
        // Prove the supplied password is correct before re-wrapping.
        KeyWrap {
            key_id: format::KEY_ID_MASTER.to_string(),
            sealed: self.storage.read_header()?.1.sealed,
        }
        .unwrap(&master_old, &self.header.key_wrap_aad())?;

        let mut new_header = self.header.clone();
        new_header.kdf_salt = crypto::random_salt().to_vec();
        new_header.updated_at = format::now_unix();
        let master_new =
            crypto::derive_master_key(new_password, &new_header.kdf_salt, new_header.kdf_params)?;
        let wrap = KeyWrap::wrap_master(&master_new, &self.vault_key, &new_header.key_wrap_aad())?;
        self.storage.write_header_meta(&new_header, &wrap)?;
        Ok(())
    }

    /// Derive the per-item key for `id` from the unlocked vault key.
    pub(crate) fn vault_key_derive(&self, id: &str) -> SecretKey {
        self.vault_key.derive_item_key(id)
    }

    /// Seal an item body into a storable row.
    fn seal_body(
        &self,
        id: &str,
        item_type: ItemType,
        body: &ItemBody,
        created_at: i64,
        updated_at: i64,
        deleted: bool,
    ) -> Result<StoredItem> {
        let aad = self.header.item_aad(id, item_type.as_str());
        let item_key = self.vault_key.derive_item_key(id);
        let plaintext = serde_json::to_vec(body)?;
        let ciphertext = crypto::seal(&item_key, &aad, &plaintext)?;
        Ok(StoredItem {
            id: id.to_string(),
            item_type: item_type.as_str().to_string(),
            ciphertext,
            created_at,
            updated_at,
            deleted,
        })
    }
}

/// Search decrypted items locally. The server cannot do this; v1 filters in the
/// client after unlock.
pub fn search_items<'a>(items: &'a [Item], query: &str) -> Vec<&'a Item> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return items.iter().collect();
    }
    items
        .iter()
        .filter(|item| {
            let b = &item.body;
            b.title.to_lowercase().contains(&q)
                || b.username
                    .as_deref()
                    .is_some_and(|v| v.to_lowercase().contains(&q))
                || b.url
                    .as_deref()
                    .is_some_and(|v| v.to_lowercase().contains(&q))
                || b.tags.iter().any(|t| t.to_lowercase().contains(&q))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_vault() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.pmvault");
        (dir, path)
    }

    fn login(title: &str, password: &str) -> ItemBody {
        let mut body = ItemBody::new(title);
        body.username = Some("alice".into());
        body.password = Some(password.into());
        body
    }

    #[test]
    fn create_unlock_roundtrip() {
        let (_dir, path) = temp_vault();
        let vault = Vault::create(&path, "master-password").unwrap();
        let id = vault
            .create_item(ItemType::Login, login("Email", "s3cret"))
            .unwrap()
            .meta
            .id;
        drop(vault);

        let vault = Vault::unlock(&path, "master-password").unwrap();
        let item = vault.get_item(&id).unwrap();
        assert_eq!(item.body.title, "Email");
        assert_eq!(item.body.password.as_deref(), Some("s3cret"));
    }

    #[test]
    fn wrong_password_fails() {
        let (_dir, path) = temp_vault();
        Vault::create(&path, "correct").unwrap();
        assert!(matches!(
            Vault::unlock(&path, "wrong"),
            Err(Error::BadCredentials)
        ));
    }

    #[test]
    fn crud_lifecycle() {
        let (_dir, path) = temp_vault();
        let vault = Vault::create(&path, "pw").unwrap();
        let created = vault
            .create_item(ItemType::Login, login("GitHub", "old"))
            .unwrap();
        let id = created.meta.id.clone();

        let mut body = login("GitHub", "new");
        body.tags = vec!["work".into()];
        let updated = vault.update_item(&id, ItemType::Login, body).unwrap();
        assert!(updated.meta.updated_at >= created.meta.updated_at);

        let items = vault.list_items().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].body.password.as_deref(), Some("new"));

        vault.delete_item(&id).unwrap();
        assert!(matches!(vault.get_item(&id), Err(Error::ItemNotFound(_))));
        assert!(vault.list_items().unwrap().is_empty());
    }

    #[test]
    fn tombstones_are_retained_for_sync() {
        let (_dir, path) = temp_vault();
        let vault = Vault::create(&path, "pw").unwrap();
        let id = vault
            .create_item(ItemType::Note, ItemBody::new("temp"))
            .unwrap()
            .meta
            .id;
        vault.delete_item(&id).unwrap();
        let stored = vault.storage().get_stored(&id).unwrap().unwrap();
        assert!(stored.deleted);
    }

    #[test]
    fn password_change_preserves_items() {
        let (_dir, path) = temp_vault();
        let vault = Vault::create(&path, "old-pw").unwrap();
        let id = vault
            .create_item(ItemType::Login, login("Bank", "hunter2"))
            .unwrap()
            .meta
            .id;
        vault.change_password("old-pw", "new-pw").unwrap();
        drop(vault);

        assert!(Vault::unlock(&path, "old-pw").is_err());
        let vault = Vault::unlock(&path, "new-pw").unwrap();
        assert_eq!(
            vault.get_item(&id).unwrap().body.password.as_deref(),
            Some("hunter2")
        );
    }

    #[test]
    fn password_change_requires_current_password() {
        let (_dir, path) = temp_vault();
        let vault = Vault::create(&path, "old-pw").unwrap();
        assert!(matches!(
            vault.change_password("not-it", "new-pw"),
            Err(Error::BadCredentials)
        ));
    }

    #[test]
    fn search_matches_expected_fields() {
        let (_dir, path) = temp_vault();
        let vault = Vault::create(&path, "pw").unwrap();
        let mut work = login("Work VPN", "x");
        work.tags = vec!["corp".into()];
        vault.create_item(ItemType::Login, work).unwrap();
        vault
            .create_item(ItemType::Note, ItemBody::new("Shopping list"))
            .unwrap();

        let items = vault.list_items().unwrap();
        assert_eq!(search_items(&items, "vpn").len(), 1);
        assert_eq!(search_items(&items, "corp").len(), 1);
        assert_eq!(search_items(&items, "alice").len(), 1);
        assert_eq!(search_items(&items, "").len(), 2);
        assert_eq!(search_items(&items, "absent").len(), 0);
    }
}
