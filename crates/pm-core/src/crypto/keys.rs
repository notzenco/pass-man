//! Key types and derivation.
//!
//! Keys are 32-byte secrets that zeroize on drop. The only way to read them is
//! [`SecretKey::expose`], which keeps accidental logging and serialization hard.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::KEY_LEN;

/// A 32-byte symmetric key that is wiped from memory when dropped.
///
/// Deliberately does not implement `Clone`, `Display`, `Debug`, or `Serialize`.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Wrap raw bytes as a key. The caller is responsible for the bytes'
    /// provenance; the source buffer is not cleared.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key bytes. Callers must not copy or log them.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive a per-item key from this key.
    ///
    /// Matches `docs/FORMAT.md` §3: `HKDF-SHA256(vault_key,
    /// info = "pmvault/v1/item/" || item_id)`.
    pub fn derive_item_key(&self, item_id: &str) -> Self {
        self.derive(b"pmvault/v1/item/", item_id.as_bytes())
    }

    /// Derive a subkey with the given info prefix and suffix.
    fn derive(&self, info_prefix: &[u8], info_suffix: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut info = Vec::with_capacity(info_prefix.len() + info_suffix.len());
        info.extend_from_slice(info_prefix);
        info.extend_from_slice(info_suffix);
        let mut out = [0u8; KEY_LEN];
        // expand only fails when the output length exceeds 255 * HashLen.
        hk.expand(&info, &mut out)
            .expect("32 bytes is a valid HKDF output length");
        Self(out)
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from(byte: u8) -> SecretKey {
        SecretKey::from_bytes([byte; KEY_LEN])
    }

    #[test]
    fn item_keys_differ_per_item() {
        let vault = key_from(7);
        assert_ne!(
            vault.derive_item_key("a").expose(),
            vault.derive_item_key("b").expose()
        );
    }

    #[test]
    fn item_key_is_deterministic() {
        let vault = key_from(7);
        assert_eq!(
            vault.derive_item_key("same").expose(),
            vault.derive_item_key("same").expose()
        );
    }

    #[test]
    fn debug_does_not_leak() {
        let key = key_from(0xab);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("ab"));
        assert_eq!(rendered, "SecretKey(<redacted>)");
    }
}
