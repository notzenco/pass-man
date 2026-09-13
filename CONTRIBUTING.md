# Contributing

## Before you start

Read [`docs/FORMAT.md`](docs/FORMAT.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
The format document is normative: if a change alters the byte layout, algorithms,
or the AAD construction, it requires a format version bump and a spec update in
the same change.

## Ground rules

- Security-critical logic belongs in `pm-core` and must not be duplicated in a
  client. Clients are adapters.
- Do not weaken an existing invariant to make a change easier. If two rules
  conflict, say which one you followed and why.
- No new `unsafe`. The core and server crates forbid it.
- Never log or serialize key material. Use `SecretKey`, which redacts its `Debug`
  output and zeroizes on drop.

## Checks

Run all of these before opening a pull request:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm install
pnpm typecheck
pnpm --filter @pass-man/desktop build
pnpm --filter @pass-man/extension build
```

For changes to the WASM core:

```sh
cargo check -p pm-core-wasm --target wasm32-unknown-unknown
pnpm wasm:build
```

## Working on the desktop UI

The desktop frontend is a plain Vite app that talks to the Rust core through
Tauri. When it is served in a browser it falls back to an in-memory mock backend
behind the same interface, so the whole UI can be developed and tested without
rebuilding the native shell:

```sh
pnpm --filter @pass-man/desktop dev   # http://localhost:1420
```

The mock is marked `PREVIEW` in the title bar and stores cleartext. It is a test
harness only and must never be treated as a vault.

## Commits

Use Conventional Commits, for example `fix(crypto): reject truncated ciphertext`.
Imperative, lowercase subject of at most 72 characters without a trailing period.
Mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Do not add
authorship trailers.

## Tests

New behavior needs a test. Security-relevant behavior needs a test that would
fail if the protection were removed — for example, the existing test that moves
a ciphertext to a different item id and asserts decryption fails. Prefer
round-trip tests that go through the real public API rather than asserting on
internals.
