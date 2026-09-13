//! Errors returned by the pass-man core.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong in the core.
#[derive(Debug, Error)]
pub enum Error {
    #[error("vault is locked")]
    Locked,

    #[error("incorrect master password or corrupted vault")]
    BadCredentials,

    #[error("vault file is corrupted: {0}")]
    Corrupt(String),

    #[error("unsupported vault format version {found}; this build supports up to {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("item {0} not found")]
    ItemNotFound(String),

    #[error("invalid vault field `{0}`")]
    InvalidField(String),

    #[error("cryptographic operation failed")]
    Crypto,

    #[error("ciphertext too short")]
    ShortCiphertext,

    #[error("database error: {0}")]
    #[cfg(feature = "storage")]
    Database(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
