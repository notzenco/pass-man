//! Server-side persistence.
//!
//! The database stores accounts and encrypted records only. It never stores
//! master passwords or any key material that could decrypt a record body; the
//! `ciphertext` column is opaque to this server.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{ApiError, ApiResult};

/// A registered account. The password verifier is an Argon2id PHC string over
/// the account password, used only for login, never for vault decryption.
#[derive(Debug, Clone)]
pub struct Account {
    pub account_id: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: i64,
}

/// A stored record row.
#[derive(Debug, Clone)]
pub struct RecordRow {
    pub revision: i64,
    pub deleted: bool,
    pub item_type: String,
    pub ciphertext: Vec<u8>,
    pub client_updated_at: i64,
    pub device_id: Option<String>,
}

/// A record supplied by a client on push.
#[derive(Debug, Clone)]
pub struct RecordInput {
    pub item_id: String,
    pub deleted: bool,
    pub item_type: String,
    pub ciphertext: Vec<u8>,
    pub client_updated_at: i64,
    pub device_id: Option<String>,
}

/// Handle to the sync database.
pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open or create the database at `path`.
    pub fn open(path: &std::path::Path) -> ApiResult<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an in-memory database, used by tests.
    pub fn open_in_memory() -> ApiResult<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> ApiResult<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS accounts (
                account_id    TEXT PRIMARY KEY NOT NULL,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at    INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token       TEXT PRIMARY KEY NOT NULL,
                account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vaults (
                vault_id    TEXT PRIMARY KEY NOT NULL,
                account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
                created_at  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS records (
                vault_id          TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
                item_id           TEXT NOT NULL,
                revision          INTEGER NOT NULL,
                deleted           INTEGER NOT NULL,
                item_type         TEXT NOT NULL,
                ciphertext        BLOB NOT NULL,
                client_updated_at INTEGER NOT NULL,
                device_id         TEXT,
                PRIMARY KEY (vault_id, item_id)
            );
            CREATE TABLE IF NOT EXISTS vault_revision (
                vault_id  TEXT PRIMARY KEY NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
                revision  INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(Self { conn })
    }

    /// Create an account, returning it. Errors if the email is taken.
    pub fn create_account(&self, email: &str, password_hash: &str) -> ApiResult<Account> {
        let account_id = uuid::Uuid::new_v4().to_string();
        let now = unix_now();
        self.conn
            .execute(
                "INSERT INTO accounts(account_id, email, password_hash, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![account_id, email, password_hash, now],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(err, _)
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    ApiError::Conflict("email already registered")
                }
                other => ApiError::Db(other),
            })?;
        Ok(Account {
            account_id,
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            created_at: now,
        })
    }

    /// Look up an account by email.
    pub fn find_account_by_email(&self, email: &str) -> ApiResult<Option<Account>> {
        let account = self
            .conn
            .query_row(
                "SELECT account_id, email, password_hash, created_at
                 FROM accounts WHERE email = ?1",
                params![email],
                |row| {
                    Ok(Account {
                        account_id: row.get(0)?,
                        email: row.get(1)?,
                        password_hash: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(account)
    }

    /// Store a session token for `account_id`.
    pub fn create_session(&self, token: &str, account_id: &str, ttl_secs: i64) -> ApiResult<()> {
        let now = unix_now();
        self.conn.execute(
            "INSERT INTO sessions(token, account_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![token, account_id, now, now + ttl_secs],
        )?;
        Ok(())
    }

    /// Resolve a session token to an account id, if unexpired.
    pub fn account_for_session(&self, token: &str) -> ApiResult<Option<String>> {
        let account: Option<String> = self
            .conn
            .query_row(
                "SELECT account_id FROM sessions WHERE token = ?1 AND expires_at > ?2",
                params![token, unix_now()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(account)
    }

    /// Register a vault under an account if not already present.
    pub fn ensure_vault(&self, vault_id: &str, account_id: &str) -> ApiResult<bool> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT account_id FROM vaults WHERE vault_id = ?1",
                params![vault_id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(owner) if owner == account_id => Ok(true),
            Some(_) => Err(ApiError::Forbidden),
            None => {
                self.conn.execute(
                    "INSERT INTO vaults(vault_id, account_id, created_at) VALUES (?1, ?2, ?3)",
                    params![vault_id, account_id, unix_now()],
                )?;
                self.conn.execute(
                    "INSERT OR IGNORE INTO vault_revision(vault_id, revision) VALUES (?1, 0)",
                    params![vault_id],
                )?;
                Ok(true)
            }
        }
    }

    /// Push records, assigning a new revision per record. Returns new revision.
    pub fn push_records(
        &self,
        vault_id: &str,
        inputs: &[RecordInput],
    ) -> ApiResult<Vec<(String, i64)>> {
        let tx = self.conn.unchecked_transaction()?;
        let mut current: i64 = tx
            .query_row(
                "SELECT revision FROM vault_revision WHERE vault_id = ?1",
                params![vault_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);

        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            current += 1;
            tx.execute(
                "INSERT INTO records(vault_id, item_id, revision, deleted, item_type,
                                     ciphertext, client_updated_at, device_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(vault_id, item_id) DO UPDATE SET
                    revision          = excluded.revision,
                    deleted           = excluded.deleted,
                    item_type         = excluded.item_type,
                    ciphertext        = excluded.ciphertext,
                    client_updated_at = excluded.client_updated_at,
                    device_id         = excluded.device_id",
                params![
                    vault_id,
                    input.item_id,
                    current,
                    input.deleted as i64,
                    input.item_type,
                    input.ciphertext,
                    input.client_updated_at,
                    input.device_id,
                ],
            )?;
            results.push((input.item_id.clone(), current));
        }
        tx.execute(
            "INSERT INTO vault_revision(vault_id, revision) VALUES (?1, ?2)
             ON CONFLICT(vault_id) DO UPDATE SET revision = excluded.revision",
            params![vault_id, current],
        )?;
        tx.commit()?;
        Ok(results)
    }

    /// Pull records with revision greater than `since`.
    pub fn pull_records(&self, vault_id: &str, since: i64) -> ApiResult<Vec<(String, RecordRow)>> {
        let mut stmt = self.conn.prepare(
            "SELECT item_id, revision, deleted, item_type, ciphertext,
                    client_updated_at, device_id
             FROM records WHERE vault_id = ?1 AND revision > ?2 ORDER BY revision",
        )?;
        let rows = stmt
            .query_map(params![vault_id, since], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    RecordRow {
                        revision: row.get(1)?,
                        deleted: row.get::<_, i64>(2)? != 0,
                        item_type: row.get(3)?,
                        ciphertext: row.get(4)?,
                        client_updated_at: row.get(5)?,
                        device_id: row.get(6)?,
                    },
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Current highest revision for a vault.
    pub fn current_revision(&self, vault_id: &str) -> ApiResult<i64> {
        let revision: Option<i64> = self
            .conn
            .query_row(
                "SELECT revision FROM vault_revision WHERE vault_id = ?1",
                params![vault_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(revision.unwrap_or(0))
    }
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(id: &str, updated: i64) -> RecordInput {
        RecordInput {
            item_id: id.to_string(),
            deleted: false,
            item_type: "login".into(),
            ciphertext: vec![1, 2, 3],
            client_updated_at: updated,
            device_id: Some("d1".into()),
        }
    }

    #[test]
    fn account_email_is_unique() {
        let db = Db::open_in_memory().unwrap();
        db.create_account("a@b.c", "hash").unwrap();
        assert!(matches!(
            db.create_account("a@b.c", "hash"),
            Err(ApiError::Conflict(_))
        ));
    }

    #[test]
    fn vault_ownership_is_enforced() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_account("a@b.c", "h").unwrap();
        let b = db.create_account("d@e.f", "h").unwrap();
        db.ensure_vault("v1", &a.account_id).unwrap();
        assert!(matches!(
            db.ensure_vault("v1", &b.account_id),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn revisions_increase_and_pull_is_incremental() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_account("a@b.c", "h").unwrap();
        db.ensure_vault("v1", &a.account_id).unwrap();

        let pushed = db.push_records("v1", &[input("i1", 1)]).unwrap();
        assert_eq!(pushed[0].1, 1);
        db.push_records("v1", &[input("i2", 2)]).unwrap();
        assert_eq!(db.current_revision("v1").unwrap(), 2);

        let all = db.pull_records("v1", 0).unwrap();
        assert_eq!(all.len(), 2);
        let incremental = db.pull_records("v1", 1).unwrap();
        assert_eq!(incremental.len(), 1);
        assert_eq!(incremental[0].0, "i2");
    }

    #[test]
    fn pushing_same_item_only_bumps_revision() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_account("a@b.c", "h").unwrap();
        db.ensure_vault("v1", &a.account_id).unwrap();
        db.push_records("v1", &[input("i1", 1)]).unwrap();
        db.push_records("v1", &[input("i1", 2)]).unwrap();
        assert_eq!(db.pull_records("v1", 0).unwrap().len(), 1);
        assert_eq!(db.current_revision("v1").unwrap(), 2);
    }
}
