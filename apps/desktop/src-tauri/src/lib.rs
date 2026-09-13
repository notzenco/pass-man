//! Tauri command surface for the pass-man desktop app.
//!
//! Every command is a thin adapter over `pm-core`. No cryptography or vault
//! logic lives here, so the desktop app cannot diverge from the CLI, mobile
//! bindings, or the browser extension.

use std::path::PathBuf;
use std::sync::Mutex;

use pm_core::model::{CustomField, Item, ItemBody, ItemType};
use pm_core::totp::{self, TotpParams};
use pm_core::{entropy_bits, generate, search_items, PasswordOptions, SyncRecord, Vault};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

/// Application state holding at most one unlocked vault.
///
/// The vault owns the derived keys; locking drops it, which zeroizes them.
#[derive(Default)]
struct AppState {
    vault: Mutex<Option<Vault>>,
    // Remembered so the UI can unlock again after a lock without re-picking a file.
    vault_path: Mutex<Option<PathBuf>>,
}

impl AppState {
    fn with_vault<T>(&self, f: impl FnOnce(&Vault) -> Result<T, String>) -> Result<T, String> {
        let guard = self
            .vault
            .lock()
            .map_err(|_| "state poisoned".to_string())?;
        let vault = guard
            .as_ref()
            .ok_or_else(|| "vault is locked".to_string())?;
        f(vault)
    }
}

fn map_err(err: pm_core::Error) -> String {
    err.to_string()
}

/// A vault row reduced to the fields the list view needs, with no secrets.
#[derive(Serialize)]
struct ItemSummary {
    id: String,
    item_type: String,
    title: String,
    username: Option<String>,
    url: Option<String>,
    favorite: bool,
    tags: Vec<String>,
    updated_at: i64,
    has_totp: bool,
}

impl From<&Item> for ItemSummary {
    fn from(item: &Item) -> Self {
        Self {
            id: item.meta.id.clone(),
            item_type: item.meta.item_type.as_str().to_string(),
            title: item.body.title.clone(),
            username: item.body.username.clone(),
            url: item.body.url.clone(),
            favorite: item.body.favorite,
            tags: item.body.tags.clone(),
            updated_at: item.meta.updated_at,
            has_totp: item
                .body
                .totp_secret
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
        }
    }
}

#[derive(Serialize)]
struct VaultInfo {
    vault_id: String,
    format_version: u32,
    kdf_algorithm: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize)]
struct UnlockResult {
    vault_id: String,
    item_count: usize,
}

#[derive(Deserialize)]
struct ItemInput {
    item_type: String,
    title: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    totp_secret: Option<String>,
    #[serde(default)]
    fields: Vec<FieldInput>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    favorite: bool,
}

#[derive(Deserialize)]
struct FieldInput {
    name: String,
    value: String,
    #[serde(default)]
    hidden: bool,
}

impl ItemInput {
    fn into_body(self) -> ItemBody {
        ItemBody {
            title: self.title,
            username: self.username,
            password: self.password,
            url: self.url,
            notes: self.notes,
            totp_secret: self.totp_secret,
            fields: self
                .fields
                .into_iter()
                .map(|f| CustomField {
                    name: f.name,
                    value: f.value,
                    hidden: f.hidden,
                })
                .collect(),
            tags: self.tags,
            favorite: self.favorite,
            ..ItemBody::default()
        }
    }

    fn parse_type(&self) -> Result<ItemType, String> {
        ItemType::parse(&self.item_type)
            .ok_or_else(|| format!("unknown item type `{}`", self.item_type))
    }
}

/// Default vault path in the app data directory.
fn default_vault_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot resolve app data dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("default.pmvault"))
}

/// Resolve which vault file to act on: the open one, else the default.
fn resolve_path(state: &AppState, app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if let Some(path) = state
        .vault_path
        .lock()
        .map_err(|_| "state poisoned")?
        .clone()
    {
        return Ok(path);
    }
    default_vault_path(app)
}

#[tauri::command]
fn vault_exists(app: tauri::AppHandle, state: State<AppState>) -> Result<bool, String> {
    let path = resolve_path(&state, &app)?;
    if !path.exists() {
        return Ok(false);
    }
    // A file being present is not enough: a partial or stray file should send
    // the user to the create screen rather than the unlock screen.
    match pm_core::storage::Storage::open(&path) {
        Ok(storage) => storage.is_initialized().map_err(map_err),
        Err(_) => Ok(false),
    }
}

#[tauri::command]
fn create_vault(
    app: tauri::AppHandle,
    state: State<AppState>,
    password: String,
) -> Result<UnlockResult, String> {
    let path = resolve_path(&state, &app)?;
    let vault = Vault::create(&path, &password).map_err(map_err)?;
    let info = UnlockResult {
        vault_id: vault.vault_id().to_string(),
        item_count: 0,
    };
    *state.vault_path.lock().map_err(|_| "state poisoned")? = Some(path);
    *state.vault.lock().map_err(|_| "state poisoned")? = Some(vault);
    Ok(info)
}

#[tauri::command]
fn unlock_vault(
    app: tauri::AppHandle,
    state: State<AppState>,
    password: String,
    path: Option<String>,
) -> Result<UnlockResult, String> {
    let path = match path {
        Some(p) => PathBuf::from(p),
        None => resolve_path(&state, &app)?,
    };
    let vault = Vault::unlock(&path, &password).map_err(map_err)?;
    let count = vault.list_items().map_err(map_err)?.len();
    let info = UnlockResult {
        vault_id: vault.vault_id().to_string(),
        item_count: count,
    };
    *state.vault_path.lock().map_err(|_| "state poisoned")? = Some(path);
    *state.vault.lock().map_err(|_| "state poisoned")? = Some(vault);
    Ok(info)
}

/// Drop the unlocked vault, zeroizing its keys.
#[tauri::command]
fn lock_vault(state: State<AppState>) -> Result<(), String> {
    *state.vault.lock().map_err(|_| "state poisoned")? = None;
    Ok(())
}

#[tauri::command]
fn is_locked(state: State<AppState>) -> Result<bool, String> {
    Ok(state.vault.lock().map_err(|_| "state poisoned")?.is_none())
}

#[tauri::command]
fn vault_info(state: State<AppState>) -> Result<VaultInfo, String> {
    state.with_vault(|vault| {
        let header = vault.header();
        Ok(VaultInfo {
            vault_id: header.vault_id.to_string(),
            format_version: header.format_version,
            kdf_algorithm: header.kdf_algorithm.clone(),
            created_at: header.created_at,
            updated_at: header.updated_at,
        })
    })
}

#[tauri::command]
fn list_items(state: State<AppState>, query: Option<String>) -> Result<Vec<ItemSummary>, String> {
    state.with_vault(|vault| {
        let items = vault.list_items().map_err(map_err)?;
        let filtered = search_items(&items, query.as_deref().unwrap_or(""));
        Ok(filtered.iter().map(|i| ItemSummary::from(*i)).collect())
    })
}

#[tauri::command]
fn get_item(state: State<AppState>, id: String) -> Result<Item, String> {
    state.with_vault(|vault| vault.get_item(&id).map_err(map_err))
}

#[tauri::command]
fn create_item(state: State<AppState>, item: ItemInput) -> Result<String, String> {
    let item_type = item.parse_type()?;
    let body = item.into_body();
    state.with_vault(|vault| Ok(vault.create_item(item_type, body).map_err(map_err)?.meta.id))
}

#[tauri::command]
fn update_item(state: State<AppState>, id: String, item: ItemInput) -> Result<(), String> {
    let item_type = item.parse_type()?;
    let body = item.into_body();
    state.with_vault(|vault| {
        vault.update_item(&id, item_type, body).map_err(map_err)?;
        Ok(())
    })
}

#[tauri::command]
fn delete_item(state: State<AppState>, id: String) -> Result<(), String> {
    state.with_vault(|vault| vault.delete_item(&id).map_err(map_err))
}

#[tauri::command]
fn change_password(
    state: State<AppState>,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    if new_password.len() < 8 {
        return Err("new password must be at least 8 characters".into());
    }
    state.with_vault(|vault| {
        vault
            .change_password(&current_password, &new_password)
            .map_err(map_err)
    })
}

#[tauri::command]
async fn sync_push(
    state: State<'_, AppState>,
    server_url: String,
    token: String,
    device_id: String,
) -> Result<usize, String> {
    let (vault_id, records) = state.with_vault(|vault| {
        Ok((
            vault.vault_id().to_string(),
            vault
                .export_records(Some(device_id.clone()))
                .map_err(map_err)?,
        ))
    })?;
    let count = records.len();
    let url = format!(
        "{}/v1/vaults/{}/records",
        server_url.trim_end_matches('/'),
        vault_id
    );
    let response = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({ "records": records }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("server returned {}", response.status()));
    }
    Ok(count)
}

#[tauri::command]
async fn sync_pull(
    state: State<'_, AppState>,
    server_url: String,
    token: String,
    since: i64,
) -> Result<SyncPullResult, String> {
    let vault_id = state.with_vault(|vault| Ok(vault.vault_id().to_string()))?;
    let url = format!(
        "{}/v1/vaults/{}/records?since={}",
        server_url.trim_end_matches('/'),
        vault_id,
        since
    );
    let response = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("server returned {}", response.status()));
    }
    let payload: ServerPull = response.json().await.map_err(|e| e.to_string())?;
    let records: Vec<SyncRecord> = payload.records;
    let applied = state.with_vault(|vault| {
        let outcomes = vault.merge_records(&records).map_err(map_err)?;
        Ok(outcomes
            .iter()
            .filter(|o| **o == pm_core::MergeOutcome::Applied)
            .count())
    })?;
    Ok(SyncPullResult {
        fetched: records.len(),
        applied,
        revision: payload.revision,
    })
}

#[derive(Deserialize)]
struct ServerPull {
    records: Vec<SyncRecord>,
    revision: i64,
}

#[derive(Serialize)]
struct SyncPullResult {
    fetched: usize,
    applied: usize,
    revision: i64,
}

#[derive(Deserialize)]
struct GenerateRequest {
    length: usize,
    #[serde(default = "default_true")]
    lowercase: bool,
    #[serde(default = "default_true")]
    uppercase: bool,
    #[serde(default = "default_true")]
    digits: bool,
    #[serde(default = "default_true")]
    symbols: bool,
    #[serde(default)]
    exclude_ambiguous: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
struct GeneratedPassword {
    password: String,
    entropy_bits: f64,
}

/// Generate a password using the shared core. Never stored by this command.
#[tauri::command]
fn generate_password(request: GenerateRequest) -> Result<GeneratedPassword, String> {
    let options = PasswordOptions {
        length: request.length,
        lowercase: request.lowercase,
        uppercase: request.uppercase,
        digits: request.digits,
        symbols: request.symbols,
        exclude_ambiguous: request.exclude_ambiguous,
    };
    let password = generate(&options).map_err(map_err)?;
    Ok(GeneratedPassword {
        password,
        entropy_bits: entropy_bits(&options),
    })
}

#[derive(Serialize)]
struct TotpCode {
    code: String,
    seconds_remaining: u64,
    period: u64,
}

/// Current TOTP code for an item, with time until it rotates.
#[tauri::command]
fn totp_code(state: State<AppState>, id: String) -> Result<TotpCode, String> {
    state.with_vault(|vault| {
        let item = vault.get_item(&id).map_err(map_err)?;
        let stored = item
            .body
            .totp_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "this item has no TOTP secret".to_string())?;
        let (secret, params) = parse_stored_totp(stored).map_err(map_err)?;
        let now = pm_core::format::now_unix().max(0) as u64;
        let code = totp::code_at(&secret, now, params).map_err(map_err)?;
        Ok(TotpCode {
            code,
            seconds_remaining: totp::seconds_remaining(params.period, now),
            period: params.period,
        })
    })
}

/// Accept a raw base32 secret or a full `otpauth://` URI.
fn parse_stored_totp(stored: &str) -> pm_core::Result<(Vec<u8>, TotpParams)> {
    if stored.starts_with("otpauth://") {
        let (secret, params, _) = totp::parse_otpauth_uri(stored)?;
        Ok((secret, params))
    } else {
        Ok((totp::decode_base32(stored)?, TotpParams::default()))
    }
}

/// Run the desktop application.
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            create_vault,
            unlock_vault,
            lock_vault,
            is_locked,
            vault_info,
            list_items,
            get_item,
            create_item,
            update_item,
            delete_item,
            change_password,
            sync_push,
            sync_pull,
            generate_password,
            totp_code,
        ])
        .run(tauri::generate_context!())
        .expect("error while running pass-man desktop");
}
