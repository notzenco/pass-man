//! The plaintext data model stored inside encrypted item bodies.
//!
//! These structs are serialized to JSON and then encrypted; see
//! `docs/FORMAT.md` §4.3. Unknown fields are preserved on read so a newer client
//! can add data without an old client destroying it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The kind of an item. Stored as plaintext metadata and bound into the AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemType {
    Login,
    Note,
    Card,
    Identity,
}

impl ItemType {
    /// Stable identifier written to the database and used as AAD.
    pub fn as_str(self) -> &'static str {
        match self {
            ItemType::Login => "login",
            ItemType::Note => "note",
            ItemType::Card => "card",
            ItemType::Identity => "identity",
        }
    }

    /// Parse the identifier from the database.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "login" => Some(ItemType::Login),
            "note" => Some(ItemType::Note),
            "card" => Some(ItemType::Card),
            "identity" => Some(ItemType::Identity),
            _ => None,
        }
    }
}

/// An arbitrary named field on an item, e.g. a security question answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub hidden: bool,
}

/// The decrypted content of one item.
///
/// `extra` captures fields this version does not know about. It is written back
/// verbatim so that forward-compatible additions survive an older client's
/// read-modify-write cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemBody {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Unknown JSON members, preserved verbatim. `flatten` captures them so an
    /// older client never drops fields written by a newer one.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl ItemBody {
    /// A minimal empty item used as a starting point.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            username: None,
            password: None,
            url: None,
            notes: None,
            totp_secret: None,
            fields: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            extra: BTreeMap::new(),
        }
    }
}

impl Default for ItemBody {
    fn default() -> Self {
        Self::new("")
    }
}

/// The plaintext metadata of an item, safe to store unencrypted.
///
/// Secrets live only in [`ItemBody`]; this carries routing and sync fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemMeta {
    pub id: String,
    pub item_type: ItemType,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
}

/// An item plus its decrypted body, returned by `get` and `list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    #[serde(flatten)]
    pub meta: ItemMeta,
    pub body: ItemBody,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_type_roundtrip() {
        for t in [
            ItemType::Login,
            ItemType::Note,
            ItemType::Card,
            ItemType::Identity,
        ] {
            assert_eq!(ItemType::parse(t.as_str()), Some(t));
        }
        assert_eq!(ItemType::parse("bogus"), None);
    }

    #[test]
    fn unknown_fields_survive_a_roundtrip() {
        let json = r#"{"title":"t","future_field":{"nested":1}}"#;
        let mut body: ItemBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.title, "t");
        assert_eq!(body.extra.len(), 1);

        body.title = "renamed".into();
        let out = serde_json::to_string(&body).unwrap();
        assert!(out.contains("future_field"));
        assert!(out.contains("renamed"));
    }

    #[test]
    fn omitted_optionals_are_not_serialized() {
        let body = ItemBody::new("just a title");
        let out = serde_json::to_string(&body).unwrap();
        assert_eq!(out, r#"{"title":"just a title","favorite":false}"#);
    }
}
