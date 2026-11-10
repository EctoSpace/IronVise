# IronVise v0.8 naming and upgrades

IronVise is the new name for EctoLedger. The only CLI executable is `ironvise`.
Release CLI archives contain `ironvise`, `guard-worker`, and `verify-cert`.
Windows uses the complete `ironvise-win.ps1` launcher. The old executable,
launcher, Python import namespace and npm API aliases are no longer shipped.
Update scripts and imports before upgrading: Python imports `ironvise_sdk`;
TypeScript imports `IronViseClient` from the `ironvise` package. Both SDK
distributions are named `ironvise`.

Back up the database and its signing keys together before upgrading. Stop the
old application, install the candidate, then start it with the same working
directory and configuration. Existing migrations run as before. Never delete
an old data directory to resolve an upgrade problem. Keep the previous binary
and backup for recovery; do not downgrade an already migrated database without
checking migration compatibility.

A signing key file written by 0.6.3 opens with the same password
(`ECTO_KEY_PASSWORD`, `--key-password-fd`, or the prompt). The file is still
`session-<session id>.key` in the data directory's `keys` folder. After it
opens, 0.8 rewrites it in the current format and keeps the original beside it
as `session-<session id>.key.v063.bak`. The Ed25519 key itself does not change.

The following names deliberately remain stable in v0.8:

| Contract | Retained spelling / behavior |
| --- | --- |
| Rust libraries and host package | `ectoledger`, `ectoledger_*`, `ectoledger-*`; use `cargo run -p ectoledger --bin ironvise` |
| Python distribution and imports | `ironvise`, `ironvise_sdk`; one implementation, with no legacy namespace |
| npm distribution and imports | `ironvise`, `IronViseClient`, `IronViseApiError`, `IronViseUsageError`; no legacy API aliases |
| Configuration | All `ECTOLEDGER_*`, `ECTO_*`, `DATABASE_URL` and other existing environment variables and config files |
| Storage and secrets | Existing `.ectoledger` directories, database names, keyring services, stored provider keys and key files |
| Desktop upgrade identity | `io.ectoledger.agent-ledger` and MSI upgrade code `B8F3E9A1-4D72-4F5A-9C8E-1A2B3C4D5E6F` |
| Certificates and signatures | `.elc`, schema fields, certificate type names, signing bytes, genesis text, hashes, VC types and proof formats |
| Webhooks / SIEM | Existing header names, HMAC domain separators, CEF/LEEF vendor identifiers and receiver configuration |
| Agent hooks | Existing named hooks remain recognized; installing with `ironvise` replaces the old command instead of adding a duplicate |
| Public endpoints | Existing public GitHub URLs and website route, until a public rename is published |

The project contact address is now `ironvise@ectospace.com`.

The container image is now `ghcr.io/ectospace/ironvise`. Images up to 0.6.3
remain available at `ghcr.io/ectospace/ectoledger`.

The desktop product and executable are now `IronVise` / `ironvise-gui`. Installers
must be rehearsed on each platform to verify upgrade behavior; preserving bundle
identity alone does not establish that every installer will replace the old
application path. On macOS, retain the data directory when removing a superseded
`EctoLedger.app`. Do not run both desktop versions against the same ledger.

The Linux `.deb` is named `iron-vise`. Version 0.6.3 shipped as `ecto-ledger`.
The 0.8 package declares Debian `Replaces`, `Conflicts`, and `Provides` for
`ecto-ledger`, so installing it removes the 0.6.3 package instead of leaving
both installed. The release workflow does not build an RPM. The RPM settings
declare the same replacement (`Obsoletes`, `Conflicts`, and `Provides`) for a
build that turns that target on.

The desktop data directory follows the bundle identifier
`io.ectoledger.agent-ledger`, which is unchanged. On Linux that is
`~/.local/share/io.ectoledger.agent-ledger`, on Windows
`%APPDATA%\io.ectoledger.agent-ledger`, and on macOS
`~/Library/Application Support/io.ectoledger.agent-ledger`. Replacing the
package does not move or delete that directory.

The Windows `.msi` and `.exe` install the desktop app. They do not add
`ironvise` to PATH. The CLI on Windows is the release zip
`ironvise-x86_64-pc-windows-msvc.zip`, which contains `ironvise.exe`,
`guard-worker.exe`, and `verify-cert.exe`.

Linux release artifacts (`.deb`, `.AppImage`, and the CLI `.tar.gz`) are built
on Ubuntu 22.04. They need glibc 2.35 or newer, so they run on Ubuntu 22.04,
Debian 12, and later. The official 0.6.3 Linux binaries needed glibc 2.38 or
2.39 and do not run on Ubuntu 22.04. Compiling on a newer distro produces a
binary that needs that distro's glibc. The release jobs that compile those
artifacts stay on `ubuntu-22.04`.

No key rotation, certificate conversion, signature format change or data-path
migration is required by the rename. Historical release notes and signed
fixtures retain their original names. The Python distribution is now named
`ironvise`; the container registry location remains unchanged. No packages are
published by a local build. New registry locations and domains will be announced
only after they are reserved, published and verified.
