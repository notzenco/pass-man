//! SQLite storage backend.
//!
//! SQLite is used purely as a crash-safe, append-oriented byte container. The
//! application never depends on SQLite encryption; all secrets are already
//! sealed by [`crate::crypto`] before reaching this layer.

use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto;
use crate::error::{Error, Result};
use crate::format::{KeyWrap, VaultHeader, FORMAT_VERSION};
use crate::model::{Item, ItemBody, ItemMeta, ItemType};

/// One row as stored, before decryption.
#[derive(Debug, Clone)]
pub struct StoredItem {
    pub id: String,
    pub item_type: String,
    pub ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
}

/// Thin wrapper over a SQLite connection.
pub struct Storage {
    conn: Connection,
}

impl Storage {
    /// Open or create a vault file at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an in-memory vault. Used by tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS vault_meta (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS items (
                id          TEXT PRIMARY KEY NOT NULL,
                item_type   TEXT NOT NULL,
                ciphertext  BLOB NOT NULL,
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL,
                deleted     INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS items_updated_at ON items(updated_at);
            CREATE TABLE IF NOT EXISTS sync_state (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            "#,
        )?;
        Ok(Self { conn })
    }

    /// Whether a vault header has been written yet.
    pub fn is_initialized(&self) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM vault_meta WHERE key = 'format_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    fn put_meta_blob(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO vault_meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    fn get_meta_blob(&self, key: &str) -> Result<Vec<u8>> {
        let value: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        value.ok_or_else(|| Error::Corrupt(format!("missing vault_meta key `{key}`")))
    }

    /// Write a new header and its wrapped key. Fails if one already exists.
    pub fn write_new_header(&self, header: &VaultHeader, wrap: &KeyWrap) -> Result<()> {
        if self.is_initialized()? {
            return Err(Error::InvalidField("vault already initialized".into()));
        }
        self.write_header_meta(header, wrap)
    }

    /// Replace the header metadata, used on password change.
    pub fn write_header_meta(&self, header: &VaultHeader, wrap: &KeyWrap) -> Result<()> {
        header.validate()?;
        let tx = self.conn.unchecked_transaction()?;
        self.put_meta_blob("format_version", &header.format_version.to_le_bytes())?;
        self.put_meta_blob("vault_id", header.vault_id.as_bytes())?;
        self.put_meta_blob("kdf_algorithm", header.kdf_algorithm.as_bytes())?;
        self.put_meta_blob("kdf_salt", &header.kdf_salt)?;
        self.put_meta_blob("kdf_m_cost", &header.kdf_params.m_cost.to_le_bytes())?;
        self.put_meta_blob("kdf_t_cost", &header.kdf_params.t_cost.to_le_bytes())?;
        self.put_meta_blob("kdf_p_cost", &header.kdf_params.p_cost.to_le_bytes())?;
        self.put_meta_blob("key_wrap_id", wrap.key_id.as_bytes())?;
        self.put_meta_blob("key_wrap", &wrap.sealed)?;
        self.put_meta_blob("created_at", &header.created_at.to_le_bytes())?;
        self.put_meta_blob("updated_at", &header.updated_at.to_le_bytes())?;
        tx.commit()?;
        Ok(())
    }

    /// Touch the header's `updated_at`.
    pub fn touch_header(&self, updated_at: i64) -> Result<()> {
        self.put_meta_blob("updated_at", &updated_at.to_le_bytes())
    }

    /// Read and validate the header plus its key wrap.
    pub fn read_header(&self) -> Result<(VaultHeader, KeyWrap)> {
        let version_bytes = self.get_meta_blob("format_version")?;
        let format_version = read_u32(&version_bytes, "format_version")?;
        if format_version > FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: format_version,
                supported: FORMAT_VERSION,
            });
        }

        let vault_id_bytes = self.get_meta_blob("vault_id")?;
        let vault_id = uuid::Uuid::from_slice(&vault_id_bytes)
            .map_err(|_| Error::Corrupt("bad vault_id".into()))?;

        let kdf_algorithm = String::from_utf8(self.get_meta_blob("kdf_algorithm")?)
            .map_err(|_| Error::Corrupt("bad kdf_algorithm".into()))?;
        let kdf_salt = self.get_meta_blob("kdf_salt")?;
        let kdf_params = crypto::KdfParams {
            m_cost: read_u32(&self.get_meta_blob("kdf_m_cost")?, "kdf_m_cost")?,
            t_cost: read_u32(&self.get_meta_blob("kdf_t_cost")?, "kdf_t_cost")?,
            p_cost: read_u32(&self.get_meta_blob("kdf_p_cost")?, "kdf_p_cost")?,
        };
        let created_at = read_i64(&self.get_meta_blob("created_at")?, "created_at")?;
        let updated_at = read_i64(&self.get_meta_blob("updated_at")?, "updated_at")?;

        let key_id = String::from_utf8(self.get_meta_blob("key_wrap_id")?)
            .map_err(|_| Error::Corrupt("bad key_wrap_id".into()))?;
        let sealed = self.get_meta_blob("key_wrap")?;

        let header = VaultHeader {
            format_version,
            vault_id,
            kdf_algorithm,
            kdf_salt,
            kdf_params,
            created_at,
            updated_at,
        };
        header.validate()?;
        Ok((header, KeyWrap { key_id, sealed }))
    }

    /// Insert or replace an item row.
    pub fn upsert_item(&self, item: &StoredItem) -> Result<()> {
        self.conn.execute(
            "INSERT INTO items(id, item_type, ciphertext, created_at, updated_at, deleted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                item_type  = excluded.item_type,
                ciphertext = excluded.ciphertext,
                updated_at = excluded.updated_at,
                deleted    = excluded.deleted",
            params![
                item.id,
                item.item_type,
                item.ciphertext,
                item.created_at,
                item.updated_at,
                item.deleted as i64,
            ],
        )?;
        Ok(())
    }

    /// Fetch one row, including tombstones.
    pub fn get_stored(&self, id: &str) -> Result<Option<StoredItem>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, item_type, ciphertext, created_at, updated_at, deleted
                 FROM items WHERE id = ?1",
                params![id],
                row_to_stored,
            )
            .optional()?;
        Ok(row)
    }

    /// List every row, including tombstones, ordered by id for determinism.
    pub fn list_stored(&self) -> Result<Vec<StoredItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, item_type, ciphertext, created_at, updated_at, deleted
             FROM items ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], row_to_stored)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// List rows changed strictly after `since`, ordered by update time.
    pub fn list_stored_since(&self, since: i64) -> Result<Vec<StoredItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, item_type, ciphertext, created_at, updated_at, deleted
             FROM items WHERE updated_at > ?1 ORDER BY updated_at, id",
        )?;
        let rows = stmt
            .query_map(params![since], row_to_stored)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Hard-delete a row. Sync should prefer tombstones via [`Self::upsert_item`].
    pub fn delete_item_hard(&self, id: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM items WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    /// Read a `sync_state` entry.
    pub fn get_sync_state(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let value: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM sync_state WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    /// Write a `sync_state` entry.
    pub fn put_sync_state(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_state(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

fn row_to_stored(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredItem> {
    Ok(StoredItem {
        id: row.get(0)?,
        item_type: row.get(1)?,
        ciphertext: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        deleted: row.get::<_, i64>(5)? != 0,
    })
}

fn read_u32(bytes: &[u8], field: &str) -> Result<u32> {
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| Error::Corrupt(format!("field `{field}` has wrong length")))?;
    Ok(u32::from_le_bytes(arr))
}

fn read_i64(bytes: &[u8], field: &str) -> Result<i64> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| Error::Corrupt(format!("field `{field}` has wrong length")))?;
    Ok(i64::from_le_bytes(arr))
}

/// Decrypt a stored row into a full item. Shared by `Vault`.
pub(crate) fn decrypt_item(
    header: &VaultHeader,
    vault_key: &crate::crypto::keys::SecretKey,
    stored: &StoredItem,
) -> Result<Item> {
    let item_type = ItemType::parse(&stored.item_type)
        .ok_or_else(|| Error::Corrupt(format!("unknown item type `{}`", stored.item_type)))?;
    let aad = header.item_aad(&stored.id, &stored.item_type);
    let item_key = vault_key.derive_item_key(&stored.id);
    let plaintext = crypto::open(&item_key, &aad, &stored.ciphertext)?;
    let body: ItemBody = serde_json::from_slice(&plaintext)?;
    Ok(Item {
        meta: ItemMeta {
            id: stored.id.clone(),
            item_type,
            created_at: stored.created_at,
            updated_at: stored.updated_at,
            deleted: stored.deleted,
        },
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let storage = Storage::open_in_memory().unwrap();
        assert!(!storage.is_initialized().unwrap());

        let header = VaultHeader::new();
        let key = crypto::random_key();
        let vault_key = crypto::random_key();
        let wrap = KeyWrap::wrap_master(&key, &vault_key, &header.key_wrap_aad()).unwrap();
        storage.write_new_header(&header, &wrap).unwrap();
        assert!(storage.is_initialized().unwrap());

        let (read, read_wrap) = storage.read_header().unwrap();
        assert_eq!(read.vault_id, header.vault_id);
        assert_eq!(read.kdf_params, header.kdf_params);
        let unwrapped = read_wrap.unwrap(&key, &read.key_wrap_aad()).unwrap();
        assert_eq!(unwrapped.expose(), vault_key.expose());
    }

    #[test]
    fn double_initialize_is_rejected() {
        let storage = Storage::open_in_memory().unwrap();
        let header = VaultHeader::new();
        let master = crypto::random_key();
        let vault_key = crypto::random_key();
        let wrap = KeyWrap::wrap_master(&master, &vault_key, &header.key_wrap_aad()).unwrap();
        storage.write_new_header(&header, &wrap).unwrap();
        assert!(storage.write_new_header(&header, &wrap).is_err());
    }

    #[test]
    fn item_roundtrip_through_storage() {
        let storage = Storage::open_in_memory().unwrap();
        let header = VaultHeader::new();
        let vault_key = crypto::random_key();
        let id = crate::format::new_item_id();
        let aad = header.item_aad(&id, "login");
        let item_key = vault_key.derive_item_key(&id);
        let body = ItemBody::new("Email");
        let ciphertext =
            crypto::seal(&item_key, &aad, &serde_json::to_vec(&body).unwrap()).unwrap();

        storage
            .upsert_item(&StoredItem {
                id: id.clone(),
                item_type: "login".into(),
                ciphertext,
                created_at: 1,
                updated_at: 1,
                deleted: false,
            })
            .unwrap();

        let stored = storage.get_stored(&id).unwrap().unwrap();
        let item = decrypt_item(&header, &vault_key, &stored).unwrap();
        assert_eq!(item.body, body);
        assert_eq!(item.meta.item_type, ItemType::Login);
    }

    #[test]
    fn moved_ciphertext_fails_to_decrypt() {
        let header = VaultHeader::new();
        let vault_key = crypto::random_key();
        let id = crate::format::new_item_id();
        let other_id = crate::format::new_item_id();
        let item_key = vault_key.derive_item_key(&id);
        let body = ItemBody::new("secret");
        let ciphertext = crypto::seal(
            &item_key,
            &header.item_aad(&id, "login"),
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();

        // Attacker moves the row to a different id without re-encrypting.
        let stored = StoredItem {
            id: other_id,
            item_type: "login".into(),
            ciphertext,
            created_at: 1,
            updated_at: 1,
            deleted: false,
        };
        assert!(decrypt_item(&header, &vault_key, &stored).is_err());
    }
}
