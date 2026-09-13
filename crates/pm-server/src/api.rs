//! HTTP routes for the sync API.
//!
//! The server is deliberately dumb: it authenticates accounts and stores opaque
//! ciphertext. It never receives a master password and cannot decrypt items.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::db::{Db, RecordInput};
use crate::error::{ApiError, ApiResult};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Db>>,
}

impl AppState {
    /// Build state from a database handle.
    pub fn new(db: Db) -> Self {
        Self {
            db: Arc::new(Mutex::new(db)),
        }
    }
}

/// Build the router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/accounts", post(create_account))
        .route("/v1/sessions", post(create_session))
        .route(
            "/v1/vaults/{vault_id}/records",
            get(pull_records).post(push_records),
        )
        .layer(TraceLayer::new_for_http())
        // Extensions run on arbitrary origins. Auth is bearer-token based, so a
        // permissive CORS policy does not grant access on its own.
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct CredentialsBody {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct AccountResponse {
    account_id: String,
}

/// `POST /v1/accounts` — register.
async fn create_account(
    State(state): State<AppState>,
    Json(body): Json<CredentialsBody>,
) -> ApiResult<(StatusCode, Json<AccountResponse>)> {
    auth::validate_credentials(&body.email, &body.password)?;
    let email = body.email.trim().to_lowercase();
    let hash = auth::hash_password(&body.password)?;
    let db = state.db.lock().expect("db mutex poisoned");
    let account = db.create_account(&email, &hash)?;
    Ok((
        StatusCode::CREATED,
        Json(AccountResponse {
            account_id: account.account_id,
        }),
    ))
}

#[derive(Serialize)]
struct SessionResponse {
    token: String,
    expires_in: i64,
}

/// `POST /v1/sessions` — log in.
async fn create_session(
    State(state): State<AppState>,
    Json(body): Json<CredentialsBody>,
) -> ApiResult<Json<SessionResponse>> {
    let email = body.email.trim().to_lowercase();
    let db = state.db.lock().expect("db mutex poisoned");
    let account = db.find_account_by_email(&email)?;
    let account = auth::authenticate(account, &body.password)?;
    let token = auth::new_session_token();
    db.create_session(&token, &account.account_id, auth::SESSION_TTL_SECS)?;
    Ok(Json(SessionResponse {
        token,
        expires_in: auth::SESSION_TTL_SECS,
    }))
}

fn bearer_token(headers: &HeaderMap) -> ApiResult<String> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    header
        .strip_prefix("Bearer ")
        .map(|t| t.to_string())
        .ok_or(ApiError::Unauthorized)
}

/// Resolve the caller and confirm it owns `vault_id`.
fn authorize(db: &Db, headers: &HeaderMap, vault_id: &str) -> ApiResult<()> {
    let token = bearer_token(headers)?;
    let account_id = db
        .account_for_session(&token)?
        .ok_or(ApiError::Unauthorized)?;
    db.ensure_vault(vault_id, &account_id)?;
    Ok(())
}

#[derive(Deserialize)]
struct PushBody {
    records: Vec<PushRecordBody>,
}

#[derive(Deserialize)]
struct PushRecordBody {
    item_id: String,
    #[serde(default)]
    deleted: bool,
    item_type: String,
    ciphertext: String,
    client_updated_at: i64,
    #[serde(default)]
    device_id: Option<String>,
}

#[derive(Serialize)]
struct PushResponse {
    pushed: Vec<PushedRecord>,
    revision: i64,
}

#[derive(Serialize)]
struct PushedRecord {
    item_id: String,
    revision: i64,
}

/// `POST /v1/vaults/{vault_id}/records` — upload local changes.
async fn push_records(
    State(state): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PushBody>,
) -> ApiResult<Json<PushResponse>> {
    if body.records.len() > 1000 {
        return Err(ApiError::BadRequest("too many records in one push".into()));
    }
    let db = state.db.lock().expect("db mutex poisoned");
    authorize(&db, &headers, &vault_id)?;

    let mut inputs = Vec::with_capacity(body.records.len());
    for record in body.records {
        let ciphertext = pm_core::crypto::from_base64(&record.ciphertext)
            .map_err(|_| ApiError::BadRequest("invalid base64 ciphertext".into()))?;
        if ciphertext.len() > 1024 * 1024 {
            return Err(ApiError::BadRequest("record too large".into()));
        }
        inputs.push(RecordInput {
            item_id: record.item_id,
            deleted: record.deleted,
            item_type: record.item_type,
            ciphertext,
            client_updated_at: record.client_updated_at,
            device_id: record.device_id,
        });
    }

    let pushed = db.push_records(&vault_id, &inputs)?;
    let revision = db.current_revision(&vault_id)?;
    Ok(Json(PushResponse {
        pushed: pushed
            .into_iter()
            .map(|(item_id, revision)| PushedRecord { item_id, revision })
            .collect(),
        revision,
    }))
}

#[derive(Deserialize)]
struct PullQuery {
    #[serde(default)]
    since: i64,
}

#[derive(Serialize)]
struct PullResponse {
    records: Vec<PullRecord>,
    revision: i64,
}

#[derive(Serialize)]
struct PullRecord {
    item_id: String,
    revision: i64,
    deleted: bool,
    item_type: String,
    ciphertext: String,
    client_updated_at: i64,
    device_id: Option<String>,
}

/// `GET /v1/vaults/{vault_id}/records?since=N` — download changes.
async fn pull_records(
    State(state): State<AppState>,
    Path(vault_id): Path<String>,
    Query(query): Query<PullQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<PullResponse>> {
    let db = state.db.lock().expect("db mutex poisoned");
    authorize(&db, &headers, &vault_id)?;
    let rows = db.pull_records(&vault_id, query.since)?;
    let revision = db.current_revision(&vault_id)?;
    Ok(Json(PullResponse {
        records: rows
            .into_iter()
            .map(|(item_id, row)| PullRecord {
                item_id,
                revision: row.revision,
                deleted: row.deleted,
                item_type: row.item_type,
                ciphertext: pm_core::crypto::to_base64(&row.ciphertext),
                client_updated_at: row.client_updated_at,
                device_id: row.device_id,
            })
            .collect(),
        revision,
    }))
}
