# pass-man vault format, version 1

Status: **draft**. This document is normative for `pm-core`. Any change to the
byte layout or algorithms below requires a format version bump.

## 1. Goals and non-goals

Goals:

- All user secrets are encrypted with an authenticated cipher before they touch
  disk or the network.
- The master password is never stored. Unlocking derives keys in memory only.
- The vault file is a single self-contained artifact that can be backed up,
  synced by any file transport, or restored offline.
- Each item has an independent data key so that future sharing can grant access
  to one item without re-encrypting others.
- A server that stores sync records learns nothing about item contents.

Non-goals for v1:

- Multi-user sharing and item-level key exchange (design leaves room; not
  implemented yet).
- Server-side search. v1 decrypts items locally on unlock.
- Post-quantum algorithms. The header reserves an algorithm identifier so this
  can change without breaking old vaults.

## 2. Cryptographic primitives

| Purpose | Algorithm | Identifier |
| --- | --- | --- |
| Password KDF | Argon2id | `argon2id-v1` |
| Key separation | HKDF-SHA256 | `hkdf-sha256-v1` |
| Authenticated encryption | XChaCha20-Poly1305 (IETF, 24-byte nonce) | `xchacha20poly1305-v1` |
| Random | OS CSPRNG (`getrandom`) | n/a |

All keys are 32 bytes. All nonces are 24 random bytes drawn from the OS CSPRNG
for every encryption operation. Nonces are stored alongside the ciphertext.

### 2.1 Why XChaCha20-Poly1305

The 192-bit nonce makes random nonce generation safe without a counter or
coordination between devices, which matters for a sync system where two devices
may encrypt independently. It is constant-time in software and has no timing
side channels on platforms without AES acceleration.

## 3. Key hierarchy

```
master_password
      |
      | Argon2id(salt, m, t, p)
      v
  master_key (32B)                       derived fresh on every unlock, never stored
      |
      | XChaCha20-Poly1305 open
      v
  vault_key (32B)  <-- random, generated once at vault creation, stored wrapped
      |
      | HKDF-SHA256(info = "pmvault/v1/item/" || item_id)
      v
  item_key (32B)                          derived per item, never stored
```

- `master_key` is derived with Argon2id over the master password using the salt
  and parameters recorded in the vault header. It exists only in memory while
  the vault is unlocked and is zeroized on lock.
- `vault_key` is generated from the OS CSPRNG at creation. It is stored in the
  header only in *wrapped* (encrypted) form under `master_key`. Because item
  data is encrypted under keys derived from `vault_key`, the master password can
  be changed by re-wrapping `vault_key` alone, without touching item rows.
- `item_key` is derived on demand via HKDF-SHA256 with the UTF-8 info string
  `pmvault/v1/item/` followed by the item's 36-character lowercase UUID in
  canonical hyphenated form. HKDF info is the item id, so two items never share
  a data key, and the derivation is deterministic and reproducible from
  `vault_key` alone.

### 3.1 Changing the master password

1. Unlock with the old password to obtain `master_key_old` and `vault_key`.
2. Generate a new salt and new KDF parameters.
3. Derive `master_key_new`.
4. Wrap the same `vault_key` under `master_key_new`, write the new salt,
   parameters, and wrapped key, increment `updated_at`.
5. Zeroize `master_key_old`.

No item rows change. This is the whole reason for the two-level hierarchy.

### 3.2 Recovery key (planned)

The header reserves space for a second `vault_key` wrap under a
high-entropy recovery key shown to the user once at creation. Format v1 readers
must ignore wraps whose `key_id` they do not recognize.

## 4. Vault file

A vault is a SQLite 3 database. SQLite is used as a durable, crash-safe,
append-oriented container; the application treats it as an opaque byte store and
never relies on SQLite's encryption features. The file extension is `.pmvault`.

### 4.1 Schema

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE vault_meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE items (
    id          TEXT PRIMARY KEY NOT NULL,   -- lowercase UUIDv4
    item_type   TEXT NOT NULL,               -- login | note | card | identity
    ciphertext  BLOB NOT NULL,               -- nonce || AEAD(JSON body)
    created_at  INTEGER NOT NULL,            -- unix seconds, plaintext metadata
    updated_at  INTEGER NOT NULL,            -- unix seconds, plaintext metadata
    deleted     INTEGER NOT NULL DEFAULT 0   -- tombstone for sync
);

CREATE INDEX items_updated_at ON items(updated_at);

CREATE TABLE sync_state (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
```

`vault_meta` holds at least the following keys. Values are binary in a
self-describing little-endian layout; strings are UTF-8 without a terminator.

| Key | Encoding | Meaning |
| --- | --- | --- |
| `format_version` | u32 LE | `1` for this document |
| `vault_id` | 16 bytes | random UUIDv4 at creation, plaintext |
| `kdf_algorithm` | UTF-8 | `argon2id-v1` |
| `kdf_salt` | 16 bytes | random, regenerated on password change |
| `kdf_m_cost` | u32 LE | Argon2id memory in KiB |
| `kdf_t_cost` | u32 LE | Argon2id iterations |
| `kdf_p_cost` | u32 LE | Argon2id parallelism |
| `key_wrap` | see 4.2 | wrapped `vault_key` under `master_key` |
| `created_at` | i64 LE | unix seconds |
| `updated_at` | i64 LE | unix seconds |

### 4.2 Key wrap encoding

`key_wrap` is:

```
offset  size  field
0       1     key_id length (currently 1, value "m")
1       n     key_id bytes, UTF-8 ("m" = master password)
1+n     24    nonce
25+n    48    XChaCha20-Poly1305(vault_key)   // 32B key + 16B tag
```

AAD for the wrap is the UTF-8 string `pmvault/v1/key-wrap` followed by
`vault_id`.

### 4.3 Item body

The ciphertext column is `nonce (24) || AEAD(plaintext)`. AAD is:

```
"pmvault/v1/item" || vault_id (16B) || item_id (36B UTF-8) || item_type (UTF-8)
```

Binding `item_id` and `item_type` as AAD means an attacker with write access to
the database cannot move a ciphertext to a different row or change its type
without the decryption failing.

Plaintext is UTF-8 JSON:

```jsonc
{
  "title": "Example",
  "username": "alice",
  "password": "correct horse battery staple",
  "url": "https://example.com",
  "notes": "recovery codes in the safe",
  "totp_secret": "JBSWY3DPEHPK3PXP",
  "fields": [{ "name": "PIN", "value": "1234", "hidden": true }],
  "tags": ["work"],
  "favorite": false
}
```

Readers must ignore unknown fields so minor additions do not require a version
bump. Removing or repurposing a field does.

`totp_secret` may be either a raw base32 secret (spaces, dashes, and missing
padding tolerated) or a full `otpauth://totp/...` URI whose `digits`, `period`,
and `algorithm` parameters override the client defaults. The stored value is the
secret material; the current one-time code is derived by the client on demand and
is never persisted. Likewise, generated passwords are produced by the client and
stored like any other password; generation is not part of the format.

## 5. Default Argon2id parameters

| Parameter | Value | Rationale |
| --- | --- | --- |
| `m_cost` | 65536 KiB (64 MiB) | OWASP-recommended floor |
| `t_cost` | 3 | OWASP-recommended |
| `p_cost` | 1 | Keeps mobile and WASM single-threaded |

These are recorded in the header and may be raised over time. A reader must
honor the parameters in the file, not its defaults, so that vaults created with
weaker parameters still open.

## 6. Sync records

The server never sees a vault file. It stores per-item records derived from it:

```jsonc
{
  "item_id": "uuid",
  "revision": 42,             // server-assigned, strictly increasing
  "deleted": false,
  "nonce": "base64",          // equals the vault nonce for this item
  "ciphertext": "base64",     // identical bytes to the vault ciphertext column
  "client_updated_at": 1710000000,
  "device_id": "uuid"
}
```

The server:

- assigns `revision` on write and returns records ordered by revision;
- stores `ciphertext` opaquely and cannot decrypt it, because the AAD binds the
  `vault_id` and `item_id` which the server holds but the key is client-side;
- sees per-item sizes, update times, and device ids. This is metadata leakage
  documented in §7.

Clients pull `GET /v1/vaults/{vault_id}/records?since=<revision>` and push
`POST /v1/vaults/{vault_id}/records`. Conflict resolution in v1 is
last-writer-wins per item by server revision; the losing revision is discarded.

## 7. Threat model summary

In scope:

- Lost or stolen device, stolen vault file, malicious file-sync provider, and a
  malicious or compromised sync server, all of which must not reveal secrets
  without the master password.
- Database tampering: AEAD plus AAD binding of ids and types detects edited,
  moved, or truncated records.
- Offline brute force: Argon2id with a per-vault salt.

Out of scope for v1:

- A compromised client device with malware that reads process memory or
  keystrokes while the vault is unlocked.
- Traffic analysis of sync timing and record sizes.
- Denial of service and record destruction by a malicious server (availability,
  not confidentiality).

## 8. Versioning rules

- `format_version` is a u32 and currently `1`.
- A reader must refuse to open a vault whose `format_version` is greater than it
  supports, with a clear "upgrade the app" error, rather than guessing.
- A writer may upgrade an older vault in place only after a successful backup,
  and must then write the new `format_version`.
- Algorithm identifiers are strings, not numbers, so an unknown algorithm is a
  hard, explicit error rather than a misparse.
