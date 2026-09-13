//! WASM bindings for the pass-man core.
//!
//! The browser extension cannot run SQLite, so it uses the portable in-memory
//! vault and serializes it into `chrome.storage.local`. All cryptography still
//! happens in the audited Rust core, compiled to `wasm32-unknown-unknown`.

use wasm_bindgen::prelude::*;

use pm_core::model::{CustomField, ItemBody, ItemType};
use pm_core::PortableVault;

fn err(e: pm_core::Error) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn parse_type(s: &str) -> Result<ItemType, JsValue> {
    ItemType::parse(s).ok_or_else(|| JsValue::from_str(&format!("unknown item type `{s}`")))
}

/// An unlocked vault exposed to JavaScript.
#[wasm_bindgen]
pub struct WasmVault {
    inner: PortableVault,
}

#[wasm_bindgen]
impl WasmVault {
    /// Create a new vault. Returns the vault plus its serialized blob via
    /// [`WasmVault::export`]. The password is not retained.
    pub fn create(password: &str) -> Result<WasmVault, JsValue> {
        let (inner, _blob) = PortableVault::create(password).map_err(err)?;
        Ok(Self { inner })
    }

    /// Unlock from a serialized blob.
    pub fn unlock(blob: &str, password: &str) -> Result<WasmVault, JsValue> {
        let inner = PortableVault::unlock(blob, password).map_err(err)?;
        Ok(Self { inner })
    }

    /// Serialize the vault, re-wrapped for `password`.
    pub fn export(&self, password: &str) -> Result<String, JsValue> {
        self.inner.to_blob(password).map_err(err)
    }

    /// The vault id.
    #[wasm_bindgen(getter)]
    pub fn vault_id(&self) -> String {
        self.inner.vault_id().to_string()
    }

    /// List items as a JSON string.
    pub fn list_items(&self) -> Result<String, JsValue> {
        let items = self.inner.list_items().map_err(err)?;
        serde_json::to_string(&items).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Fetch one item as a JSON string.
    pub fn get_item(&self, id: &str) -> Result<String, JsValue> {
        let item = self.inner.get_item(id).map_err(err)?;
        serde_json::to_string(&item).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create an item from a JSON body. Returns the new item id.
    pub fn create_item(&mut self, item_type: &str, body_json: &str) -> Result<String, JsValue> {
        let item_type = parse_type(item_type)?;
        let body = parse_body(body_json)?;
        let item = self.inner.create_item(item_type, body).map_err(err)?;
        Ok(item.meta.id)
    }

    /// Update an item from a JSON body.
    pub fn update_item(
        &mut self,
        id: &str,
        item_type: &str,
        body_json: &str,
    ) -> Result<(), JsValue> {
        let item_type = parse_type(item_type)?;
        let body = parse_body(body_json)?;
        self.inner.update_item(id, item_type, body).map_err(err)?;
        Ok(())
    }

    /// Delete an item, leaving a tombstone.
    pub fn delete_item(&mut self, id: &str) -> Result<(), JsValue> {
        self.inner.delete_item(id).map_err(err)
    }

    /// Export all records (including tombstones) as JSON, for sync push.
    pub fn export_records(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.records()).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Merge remote records from JSON. Returns how many were applied.
    pub fn merge_records(&mut self, records_json: &str) -> Result<usize, JsValue> {
        let records: Vec<pm_core::PortableRecord> =
            serde_json::from_str(records_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.inner.merge(&records).map_err(err)
    }
}

/// Generate a password. `options_json` is a JSON object matching
/// `pm_core::PasswordOptions`; omitted fields use their defaults.
#[wasm_bindgen]
pub fn generate_password(options_json: &str) -> Result<String, JsValue> {
    let options: pm_core::PasswordOptions = if options_json.trim().is_empty() {
        pm_core::PasswordOptions::default()
    } else {
        serde_json::from_str(options_json).map_err(|e| JsValue::from_str(&e.to_string()))?
    };
    pm_core::generate(&options).map_err(err)
}

/// Entropy in bits for the given options.
#[wasm_bindgen]
pub fn password_entropy_bits(options_json: &str) -> Result<f64, JsValue> {
    let options: pm_core::PasswordOptions = if options_json.trim().is_empty() {
        pm_core::PasswordOptions::default()
    } else {
        serde_json::from_str(options_json).map_err(|e| JsValue::from_str(&e.to_string()))?
    };
    Ok(pm_core::entropy_bits(&options))
}

/// Current TOTP code from a raw base32 secret or an `otpauth://` URI.
/// Returns a JSON object `{ code, secondsRemaining, period }`.
#[wasm_bindgen]
pub fn totp_now(secret: &str) -> Result<String, JsValue> {
    use pm_core::totp::{self, TotpParams};

    let (secret_bytes, params) = if secret.starts_with("otpauth://") {
        let (s, p, _) = totp::parse_otpauth_uri(secret).map_err(err)?;
        (s, p)
    } else {
        (
            totp::decode_base32(secret).map_err(err)?,
            TotpParams::default(),
        )
    };
    let now = pm_core::format::now_unix().max(0) as u64;
    let code = totp::code_at(&secret_bytes, now, params).map_err(err)?;
    let payload = serde_json::json!({
        "code": code,
        "secondsRemaining": totp::seconds_remaining(params.period, now),
        "period": params.period,
    });
    Ok(payload.to_string())
}

fn parse_body(json: &str) -> Result<ItemBody, JsValue> {
    // Accept either a full body object or a loose object; unknown members are
    // preserved by the core's flattened `extra` map.
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut body: ItemBody =
        serde_json::from_value(value).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if body.fields.is_empty() {
        body.fields = Vec::<CustomField>::new();
    }
    Ok(body)
}
