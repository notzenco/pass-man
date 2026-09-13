# Architecture

## The one rule

All cryptography, the vault format, and the data model live in `pm-core`. Every
client — CLI, desktop, extension, and future mobile apps — is a thin adapter.
No client reimplements key derivation, sealing, or the AAD construction. This is
what makes it possible to reason about security once instead of five times.

```
                    ┌──────────────────────────────────────────────┐
                    │                  pm-core                     │
                    │  crypto · format · model · generator · totp  │
                    │  storage (SQLite) · portable (in-mem)        │
                    │  sync records                                │
                    └──────────────────────────────────────────────┘
                       ▲          ▲          ▲          ▲
             ┌─────────┘          │          │          └──────────┐
             │                    │          │                     │
        pm-cli              Tauri desktop   core-wasm          (future)
     (native Rust)          (native Rust)  (browser)      mobile via UniFFI
```

## Why a Rust core

- One implementation of the security-critical code to review and audit.
- Memory safety without a garbage collector, which matters for a process that
  holds decrypted key material.
- It compiles to every target we need: native binaries, `wasm32-unknown-unknown`
  for the extension, and `aarch64`/`armv7` static libraries for mobile FFI.

## Two container backends, one crypto layer

`pm-core` has two ways to hold items, and they use identical keys, AAD, and
cipher operations:

- `storage` (feature-gated, default in native clients): a SQLite file, used for
  the durable `.pmvault` vault. SQLite is treated as a crash-safe byte container;
  secrets are sealed before they reach it.
- `portable`: an in-memory map that serializes to JSON, used where SQLite cannot
  run (the browser extension, compiled to WASM). The serialized form is fully
  encrypted.

Both produce the same ciphertext byte layout, so a record exported from one can
be merged into the other.

## Key hierarchy

```
master password
  └─ Argon2id ──► master key ──unwraps──► vault key ──HKDF(item id)──► item key
```

- The master key is derived on unlock and never stored.
- The vault key is random, stored only wrapped. Changing the master password
  re-wraps this key and touches no item rows.
- Each item has its own key. This is groundwork for per-item sharing later, and
  it means one compromised item key does not expose the rest.

Details and byte layouts are normative in [`FORMAT.md`](FORMAT.md).

## Sync without trusting the server

The server stores per-item records that are byte-identical ciphertexts to what is
in the local vault. Because the AAD binds the vault id, item id, and item type,
a record cannot be moved to another item or vault and still decrypt. The merge
path verifies authentication before accepting any remote record, so a malicious
server can withhold records (availability) but cannot forge or alter them
(integrity).

v1 conflict resolution is last-writer-wins per item, by server-assigned revision.

## Generated secrets and one-time codes

These are derived, not stored, so they live in `pm-core` and are exposed by every
client identically:

- **Password generator** (`generator.rs`) samples from the OS CSPRNG. It uses
  rejection sampling over a byte-per-index range rather than `% alphabet_len`,
  because the latter biases toward the start of the alphabet. It guarantees at
  least one character from each requested class and then shuffles, so the result
  satisfies password policies without a predictable character position.
- **TOTP** (`totp.rs`) implements RFC 6238 directly on `hmac` plus `sha1`/`sha2`,
  with dynamic truncation per RFC 4226. It deliberately avoids a third-party TOTP
  crate so there is one less dependency in the trust path, and is checked against
  the RFC 6238 test vectors. A stored secret may be a raw base32 string or a full
  `otpauth://` URI; both are accepted.

Neither feature is part of the on-disk format: the generator produces a value the
user may store, and TOTP computes from the `totp_secret` already in an item body.

## Client notes

### Desktop (Tauri 2)

The Rust side owns an `Option<Vault>` behind a mutex. Every command is a small
adapter over `pm-core`; locking the vault drops it, which zeroizes the keys. The
frontend never sees key material.

The frontend is a plain Vite app. When it runs inside Tauri it calls the Rust
commands; when it is served in a browser (the dev/test harness) it falls back to
an in-memory mock backend behind the same interface. This lets the entire UI be
driven and tested deterministically without the native shell. The mock is marked
`PREVIEW` in the title bar, stores cleartext, and is never part of a real vault.

### Browser extension (MV3)

The background service worker is the only context that unlocks the vault. The
popup asks it to list and reveal; content scripts receive only the single
credential being filled into the page. The vault is auto-locked after idle time.
The WASM binary is bundled from `packages/core-wasm`.

### CLI

Reads passwords interactively when a TTY is present and from stdin otherwise, so
it works both for humans and in scripts.

## Planned

- Mobile apps (iOS/Android) via UniFFI over `pm-core`.
- Recovery key: a second wrap of the vault key, already reserved in the format.
- Item sharing: exchange item keys wrapped to recipient public keys.
- Argon2 parameter migration as hardware improves.
- An independent security audit before any production claim.
