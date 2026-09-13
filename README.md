# pass-man

A cross-platform, end-to-end encrypted password manager. One audited Rust core
is shared by the CLI, desktop app, browser extension, and future mobile apps, so
the cryptography and vault format exist in exactly one place.

> Status: early. The core format, crypto, CLI, sync server, desktop app, and
> browser extension are implemented and tested, including a password generator
> and TOTP codes. Mobile shells and item sharing are planned. Treat the format as
> v1 draft and not yet independently audited.

## Features

- **Login, note, card, and identity items** with custom fields, tags, and
  favorites.
- **Password generator** with configurable length, character classes, and an
  option to exclude look-alike characters. Uniform sampling with rejection, not
  modulo arithmetic, so there is no character bias.
- **TOTP one-time codes** (RFC 6238, SHA-1 and SHA-256) with a live countdown.
  Accepts a raw base32 secret or a full `otpauth://` URI.
- **Local search, reveal/copy, and one-click locking** across every client.
- **End-to-end encrypted sync** to a self-hostable server that only ever holds
  opaque ciphertext.

## Layout

| Path | What it is |
| --- | --- |
| `crates/pm-core` | Vault format, cryptography, generator, TOTP, data model, sync records. The single source of truth. |
| `crates/pm-cli` | `pm`, a scriptable command-line client. |
| `crates/pm-server` | Self-hostable sync server holding accounts and opaque ciphertext. |
| `packages/core-wasm` | WASM bindings over the portable vault, for the browser extension. |
| `apps/desktop` | Tauri 2 desktop app (Windows, macOS, Linux), plus a browser preview harness. |
| `extensions/browser` | Manifest V3 extension (Chrome, Edge, Firefox). |
| `docs/FORMAT.md` | Normative on-disk and wire format specification. |
| `docs/ARCHITECTURE.md` | How the pieces fit together and why. |
| `SECURITY.md` | Threat model, what is protected, and how to report issues. |
| `CONTRIBUTING.md` | Ground rules and the checks to run before a pull request. |

## Design in one paragraph

Your master password derives a key with Argon2id, which unwraps a random vault
key, which derives a separate key per item with HKDF. Items are sealed with
XChaCha20-Poly1305, with the vault id, item id, and item type bound in as
authenticated data so records cannot be moved, retyped, or tampered with. The
server only ever stores one-way-hashed account passwords and opaque ciphertext;
it never sees a master password and cannot decrypt an item. The full details are
in [`docs/FORMAT.md`](docs/FORMAT.md).

## Quick start

Prerequisites: Rust stable, Node 20+ with pnpm, and the platform dependencies
for [Tauri 2](https://v2.tauri.app/start/prerequisites/).

### CLI

```sh
cargo build -p pm-cli
export PM_VAULT=~/personal.pmvault

./target/debug/pm init
./target/debug/pm add "Example Login" -u alice -p 'hunter2' --url https://example.com
./target/debug/pm add "GitHub" -u alice --generate --totp JBSWY3DPEHPK3PXP
./target/debug/pm gen -l 24 --no-ambiguous
./target/debug/pm totp GitHub
./target/debug/pm list
./target/debug/pm show <item-id>
```

Passwords are read interactively and hidden. When stdin is piped the CLI reads a
line instead, which is what makes it scriptable. `pm add --generate` fills the
password for you, and `pm totp <id-or-title>` prints the current one-time code.

### Sync server

```sh
cargo build -p pm-server
PM_DB=./pm-server.db PM_BIND=127.0.0.1:8080 ./target/debug/pm-server
```

The server exposes:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/accounts` | Register `{ email, password }`. |
| `POST` | `/v1/sessions` | Log in, returns a bearer token. |
| `GET` | `/v1/vaults/{id}/records?since=N` | Pull records changed after revision `N`. |
| `POST` | `/v1/vaults/{id}/records` | Push records; server assigns revisions. |

### Desktop app

```sh
pnpm install
pnpm desktop:dev        # Tauri dev window
pnpm desktop:build      # packaged app
```

`pnpm --filter @pass-man/desktop dev` also serves the exact same frontend at
`http://localhost:1420` in a plain browser. When the Tauri runtime is absent the
app uses an in-memory mock backend (marked `PREVIEW` in the title bar), which is
how the UI is developed and tested without rebuilding the Rust shell. The mock
stores data in cleartext and is not a security boundary.

Keyboard shortcuts: `Cmd/Ctrl+N` new item, `Cmd/Ctrl+L` lock, `Cmd/Ctrl+F` or
`Cmd/Ctrl+K` search, `Esc` close dialog.

### Browser extension

```sh
pnpm wasm:build         # compile the Rust core to WASM
pnpm extension:build    # output in extensions/browser/dist
```

Then load `extensions/browser/dist` as an unpacked extension.

## Development

```sh
cargo fmt --all -- --check                              # formatting
cargo test --workspace                                  # Rust tests
cargo clippy --workspace --all-targets -- -D warnings   # lints
cargo check -p pm-core-wasm --target wasm32-unknown-unknown
pnpm typecheck                                          # TypeScript across all JS packages
pnpm -r build                                           # build desktop + extension bundles
```

## Security notes

- No plaintext ever reaches disk or the network; tests assert this directly.
- The master password is never stored, only used to derive a key in memory.
- Changing the master password re-wraps the vault key and leaves items untouched.
- `#![forbid(unsafe_code)]` in the core and server crates.
- The password generator draws from the OS CSPRNG and rejects biased samples.
- TOTP is implemented directly on `hmac` and `sha1`/`sha2`; there is no
  third-party TOTP crate in the trust path. The implementation is checked
  against the RFC 6238 test vectors.
- The format reserves a recovery-key slot and algorithm identifiers so the
  cryptography can be upgraded without breaking existing vaults.

See [`SECURITY.md`](SECURITY.md) before relying on this for real secrets.

## License

AGPL-3.0-or-later. See `Cargo.toml` and `package.json` for the machine-readable
declaration.

