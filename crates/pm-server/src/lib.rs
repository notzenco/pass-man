//! pass-man sync server library.
//!
//! The server stores accounts and end-to-end encrypted vault records. It cannot
//! decrypt item contents or master passwords; see `docs/FORMAT.md` §6.

#![forbid(unsafe_code)]

pub mod api;
pub mod auth;
pub mod db;
pub mod error;

pub use api::{router, AppState};
pub use db::Db;
pub use error::{ApiError, ApiResult};
