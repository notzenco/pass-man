# Security

## Status

pass-man is early-stage software. The design follows current best practice and
the core is tested, but **it has not been independently audited**. Do not trust
it with secrets you cannot afford to lose yet. If you are evaluating it, read
[`docs/FORMAT.md`](docs/FORMAT.md), which is the normative specification.

## Reporting a vulnerability

Do not open a public issue for a security problem. Report it privately to the
maintainers with enough detail to reproduce: affected version or commit, the
command or flow, and the impact. We aim to acknowledge within 72 hours. Please
give us a reasonable window to ship a fix before public disclosure.

## What pass-man protects against

- **Stolen vault file.** The `.pmvault` file and any copy of it are useless
  without the master password.
- **Malicious file-sync provider.** Same as above; the file is encrypted
  end-to-end before it leaves the device.
- **Malicious or compromised sync server.** The server stores only opaque
  ciphertext. It cannot decrypt items; the keys never leave the client.
- **Tampering with stored data.** Every item is sealed with XChaCha20-Poly1305,
  and the vault id, item id, and item type are bound in as authenticated data.
  Edited, moved, truncated, or retyped records fail to decrypt. There is a test
  that moves a ciphertext to another item id and asserts decryption fails.
- **Offline brute force.** Argon2id with a per-vault random salt and 64 MiB /
  3 iterations by default. Parameters are recorded in the file so stronger
  settings created later still open.
- **Server-side credential theft.** The server stores account passwords only as
  Argon2id PHC hashes. Account passwords are separate from vault master
  passwords and cannot decrypt any vault.

## What pass-man does not protect against

- **A compromised device with malware.** If an attacker can read your memory or
  keystrokes while the vault is unlocked, they get your secrets. Lock the vault
  when you are not using it.
- **Metadata leakage to the sync server.** The server sees vault ids, item ids,
  item types, record sizes, update times, and device ids. It does not see titles,
  usernames, passwords, or URLs.
- **Traffic analysis.** Sync timing and volume are visible to anyone watching
  the network.
- **Denial of service or record deletion by the server.** A malicious server can
  withhold or drop records. That harms availability, not confidentiality; keep
  local backups.
- **Weak master passwords.** The KDF raises the cost of guessing, but a short or
  common password remains guessable. Use a long, unique passphrase.
- **Loss of the master password.** There is no recovery path yet (a recovery key
  is designed and reserved in the format but not implemented). Lose the password
  and the data is gone.

## Design invariants

These are enforced in code and covered by tests:

- No plaintext secret is ever written to disk, logs, or the network by the Rust
  core or sync server. (The browser preview mock, which runs only without the
  Tauri runtime, stores cleartext in `localStorage`.) The smoke test greps both the vault file and the server database for known plaintext and
  fails on any hit.
- The master password is never persisted, only used to derive a key in memory.
- Key material is held in a type that zeroizes on drop and deliberately does not
  implement `Clone`, `Display`, `Debug`, or `Serialize`.
- Changing the master password re-wraps the vault key and does not rewrite or
  re-encrypt any item.
- Vaults with a newer format version are refused with an explicit error rather
  than parsed on a guess. Unknown algorithms are hard errors, not silent
  fallbacks.
- `#![forbid(unsafe_code)]` in `pm-core` and `pm-server`.
- The password generator draws from the OS CSPRNG and rejects biased samples; it
  never uses `% alphabet_len` modulo reduction.
- TOTP is implemented on `hmac` and `sha1`/`sha2` in-tree and validated against
  the RFC 6238 test vectors, with codes compared without early exit.

## Cryptographic choices

| Purpose | Algorithm |
| --- | --- |
| Password hashing (vault) | Argon2id |
| Password hashing (server accounts) | Argon2id via PHC strings |
| Key separation | HKDF-SHA256 |
| Authenticated encryption | XChaCha20-Poly1305 |
| Password generation | OS CSPRNG with rejection sampling |
| One-time codes | TOTP (RFC 6238) over HMAC-SHA-1 / HMAC-SHA-256 |

XChaCha20-Poly1305 is chosen over AES-GCM because its 192-bit nonce makes random
nonces safe without coordination between devices, and it is constant-time in
software on platforms without AES acceleration.
