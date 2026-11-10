# Changelog

All notable changes to IronVise (formerly EctoLedger) are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - Unreleased

First release since 0.6.3. The product name is IronVise. Existing ledgers, signing keys, data directories, environment variables, and
signed formats remain compatible. CLI invocations and SDK imports move to the
IronVise names; the former executable and SDK import aliases are removed. See [docs/reference/compatibility.md](docs/reference/compatibility.md).

### Added

- CLI: `hook` (Claude Code, Codex, and Antigravity CLI), `mcp-proxy`, `proxy`
  (recording only), `verify-ledger`, `issuer-key`, `data-receipts`,
  `import-openshell`, and `webhook-key`.
- SQLite parity for the cognitive loop, snapshots, certificate export,
  `anchor-session`, and live webhook delivery.
- `verify_intent` / `verifyIntent` in both SDKs: ask whether an action would
  be permitted without executing or recording it.
- Documented `.elc` certificate format and an independent verifier.
- Measured semantic-guard corpus, recorded in [docs/reference/testing.md](docs/reference/testing.md).

### Changed

- Python distribution is now `ironvise`, with the complete implementation in
  `ironvise_sdk`. The legacy Python namespace is removed.
- The container image is now `ghcr.io/ectospace/ironvise` and the compose
  service is `ironvise`. Images up to 0.6.3 stay at `ghcr.io/ectospace/ectoledger`.
- `LLM_PROVIDER` replaces `LLM_BACKEND` (the old name still works as an alias).
- `LedgerTool` (LangChain) is removed in favour of the fail-closed
  `LedgerCallbackHandler`.
- Crate licence metadata matches the BUSL-1.1 `LICENSE`. Verification tooling
  is covered by the Additional Use Grant.
- `GUARD_REQUIRED` is resolved most-restrictive-wins between the environment
  and `.ectoledger/settings.json`.

### Removed

- The legacy CLI executable and Windows launcher, Python import shims, and
  obsolete branding assets. Ship one CLI and one implementation per SDK.
- TypeScript's old npm package/API names; use `ironvise` and `IronViseClient`.

- EVM anchoring. `anchor-session --chain` accepts only `bitcoin`
  (OpenTimestamps). The `evm` feature, anchor contract, and `EVM_*` settings
  are gone.
- `audit --auto-anchor-interval` and `--auto-anchor-chain` (they never anchored).

### Fixed

- Session lookup by ID now finds sessions beyond the newest 500 records.
- Token creation rejects expiry dates outside the supported range instead of
  panicking or creating unusable tokens.
- Demo resets roll back both data deletion and immutability-trigger changes
  if any step fails, on SQLite and PostgreSQL.
- Trusted-proxy rate limiting reads forwarding-header chains right to left,
  including repeated headers, instead of accepting a forged earlier address.
- Both SDKs handle CRLF/CR SSE frames, Unicode, and multiline data correctly, close
  streams when explicitly stopped, and reject invalid retry/timeout settings.
  Python's retry backoff remains bounded for large retry counts.
- History ignores stale filter and session responses and keeps certificate
  and report exports tied to the session that requested them. Queued callbacks
  from a replaced SSE connection cannot affect its replacement.
- A `KeyRotation` event could authorise the key that signed it (F-5).
- A session with its signatures deleted, or its key cleared, verified clean (F-4).
- Signatures could be detached from the events they covered (F-1), and a sealed
  session could be truncated without detection (F-2).
- Clients could append server-owned enforcement records.
- OS sandbox failures (Landlock, Seatbelt, Job Objects) now abort the action
  by default instead of continuing unsandboxed.
- A Windows `cmd.exe` builtin wrapper let `&`, `|`, and `>` run a second command.
- A SQLite path on Windows could lose its drive letter.
- Remote enclave attestation (COSE signature, certificate chain, nonce) is
  verified before the session key is trusted.
- Webhook signatures, hook and SDK requests, and provider reasoning are bound
  to one receiver or one session so they cannot be replayed elsewhere.
- The container image includes `guard-worker` and `verify-cert`, and its
  licence label is BUSL-1.1.

### Security

- Dependency updates for rustls, zip (via the vendored `pg-embed`),
  rustls-webpki, webpki-roots, tokio, and pulldown-cmark.
- Removed experimental SP1 proving and the `zk` build feature to eliminate
  crypto-bigint 0.5.5 and RUSTSEC-2026-0387 from the dependency graph.
  `prove-audit` now refuses with an explanation and points to standard `.elc`
  certificate export. Existing certificate formats remain compatible.
- Fixed Rust compiler warnings in the vendored GLib backport so its optimized
  iterator regression and Linux builds pass with warnings denied.
- Bundled SQLite updated to 3.54.1 (libsqlite3-sys 0.39.1) for
  RUSTSEC-2026-0459, through a vendored `sqlx-sqlite` that only widens its
  version range. `verify-ledger` opens ledger files from other people, so the
  fix matters there. The optional `sqlcipher` build still bundles SQLite 3.53.4.

## [0.6.3] - 2026-03-11

### Changed

- README, website, and SDK descriptions, so the product is understandable
  without a security background.

## [0.6.2] - 2026-03-08

### Added

- Pluggable ledger backends: PostgreSQL for production commands, SQLite for
  local `serve`, `replay`, `report`, and certificate checks, selected with
  `DATABASE_URL`.
- Tauri 2 desktop app (observer, policy editor, tripwire config, metrics,
  tokens, webhooks, setup wizard) on macOS, Windows, and Linux.
- Python SDK (LangChain and AutoGen adapters) and TypeScript SDK.
- Four-layer check of each proposed intent: policy engine, semantic guard,
  strict schema, and tripwire.
- Optional Firecracker microVM tier for `run_command` on Linux.
- Optional SP1 proofs (`prove-audit`, `--features zk`) and EVM anchoring
  (removed again in 0.8.0).
- W3C Verifiable Credentials and an ISO/IEC 42001 policy pack.
- Signed webhooks, agent signing-key rotation, and a zero-config demo launcher.

[Unreleased]: https://github.com/EctoSpace/IronVise/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/EctoSpace/IronVise/compare/v0.6.3...v0.8.0
[0.6.3]: https://github.com/EctoSpace/IronVise/releases/tag/v0.6.3
[0.6.2]: https://github.com/EctoSpace/IronVise/releases/tag/v0.6.2
