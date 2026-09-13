//! End-to-end HTTP tests for the sync API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use pm_server::{router, AppState, Db};
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> axum::Router {
    let db = Db::open_in_memory().unwrap();
    router(AppState::new(db))
}

async fn call(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn register_and_login(app: &axum::Router, email: &str) -> String {
    let (status, _) = call(
        app,
        json_request(
            "POST",
            "/v1/accounts",
            json!({"email": email, "password": "a-long-password"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = call(
        app,
        json_request(
            "POST",
            "/v1/sessions",
            json!({"email": email, "password": "a-long-password"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body["token"].as_str().unwrap().to_string()
}

fn authed(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn healthz_is_public() {
    let app = app();
    let (status, _) = call(
        &app,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn duplicate_registration_conflicts() {
    let app = app();
    register_and_login(&app, "user@example.com").await;
    let (status, _) = call(
        &app,
        json_request(
            "POST",
            "/v1/accounts",
            json!({"email": "user@example.com", "password": "a-long-password"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn wrong_password_is_unauthorized() {
    let app = app();
    let (status, _) = call(
        &app,
        json_request(
            "POST",
            "/v1/accounts",
            json!({"email": "u@e.com", "password": "a-long-password"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = call(
        &app,
        json_request(
            "POST",
            "/v1/sessions",
            json!({"email": "u@e.com", "password": "wrong-password"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn short_password_is_rejected() {
    let app = app();
    let (status, _) = call(
        &app,
        json_request(
            "POST",
            "/v1/accounts",
            json!({"email": "u@e.com", "password": "short"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn records_require_auth() {
    let app = app();
    let (status, _) = call(
        &app,
        json_request("GET", "/v1/vaults/some-vault/records", json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn push_and_pull_roundtrip() {
    let app = app();
    let token = register_and_login(&app, "sync@example.com").await;

    let (status, body) = call(
        &app,
        authed(
            "POST",
            "/v1/vaults/vault-1/records",
            &token,
            json!({
                "records": [{
                    "item_id": "item-1",
                    "item_type": "login",
                    "ciphertext": pm_core::crypto::to_base64(b"opaque-bytes"),
                    "client_updated_at": 100,
                    "device_id": "device-a"
                }]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revision"], 1);

    let (status, body) = call(
        &app,
        authed(
            "GET",
            "/v1/vaults/vault-1/records?since=0",
            &token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["item_id"], "item-1");

    // Incremental pull returns nothing after the high-water mark.
    let (_, body) = call(
        &app,
        authed(
            "GET",
            "/v1/vaults/vault-1/records?since=1",
            &token,
            json!({}),
        ),
    )
    .await;
    assert!(body["records"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn another_account_cannot_touch_the_vault() {
    let app = app();
    let owner_token = register_and_login(&app, "owner@example.com").await;
    call(
        &app,
        authed(
            "POST",
            "/v1/vaults/shared-vault/records",
            &owner_token,
            json!({"records": []}),
        ),
    )
    .await;

    let intruder_token = register_and_login(&app, "intruder@example.com").await;
    let (status, _) = call(
        &app,
        authed(
            "GET",
            "/v1/vaults/shared-vault/records?since=0",
            &intruder_token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_base64_is_rejected() {
    let app = app();
    let token = register_and_login(&app, "b64@example.com").await;
    let (status, _) = call(
        &app,
        authed(
            "POST",
            "/v1/vaults/v/records",
            &token,
            json!({
                "records": [{
                    "item_id": "i",
                    "item_type": "login",
                    "ciphertext": "not base64!!!",
                    "client_updated_at": 1
                }]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn server_stores_ciphertext_verbatim() {
    let app = app();
    let token = register_and_login(&app, "verbatim@example.com").await;
    let secret = b"\x00\x01\x02 raw ciphertext \xff";
    let encoded = pm_core::crypto::to_base64(secret);

    call(
        &app,
        authed(
            "POST",
            "/v1/vaults/v/records",
            &token,
            json!({"records": [{
                "item_id": "i",
                "item_type": "note",
                "ciphertext": encoded,
                "client_updated_at": 7
            }]}),
        ),
    )
    .await;

    let (_, body) = call(
        &app,
        authed("GET", "/v1/vaults/v/records?since=0", &token, json!({})),
    )
    .await;
    let returned = body["records"][0]["ciphertext"].as_str().unwrap();
    assert_eq!(returned, encoded);
    assert_eq!(pm_core::crypto::from_base64(returned).unwrap(), secret);
}
