//! pass-man core: vault format, cryptography, and data model.
//!
//! This crate is the single source of truth for how secrets are encrypted and
//! stored. Platform shells (desktop, mobile, browser extension) and the CLI all
//! depend on it rather than reimplementing any of it. The normative byte-level
//! specification lives in `docs/FORMAT.md`.
//!
//! ```no_run
//! use pm_core::{ItemBody, ItemType, PortableVault};
//!
//! # fn main() -> pm_core::Result<()> {
//! let (mut vault, _blob) = PortableVault::create("master-password")?;
//! let mut body = ItemBody::new("Example");
//! body.username = Some("alice".into());
//! body.password = Some("hunter2".into());
//! vault.create_item(ItemType::Login, body)?;
//! let blob = vault.to_blob("master-password")?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod format;
pub mod generator;
pub mod model;
pub mod portable;
#[cfg(feature = "storage")]
pub mod storage;
#[cfg(feature = "storage")]
pub mod sync;
pub mod totp;
#[cfg(feature = "storage")]
pub mod vault;

pub use crypto::KdfParams;
pub use error::{Error, Result};
pub use format::{KeyWrap, VaultHeader, FORMAT_VERSION};
pub use generator::{entropy_bits, generate, PasswordOptions};
pub use model::{CustomField, Item, ItemBody, ItemMeta, ItemType};
pub use portable::{PortableBlob, PortableRecord, PortableVault};
#[cfg(feature = "storage")]
pub use sync::{MergeOutcome, SyncRecord};
pub use totp::{TotpAlgorithm, TotpParams};
#[cfg(feature = "storage")]
pub use vault::{search_items, Vault};
