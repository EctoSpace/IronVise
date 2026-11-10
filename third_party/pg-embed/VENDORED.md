# Vendored pg-embed 1.0.0

This directory is a copy of [`pg-embed` 1.0.0](https://crates.io/crates/pg-embed/1.0.0)
(<https://github.com/faokunega/pg-embed>, MIT/Apache-2.0, see `LICENSE`), wired in
through `[patch.crates-io]` in the root `Cargo.toml`.

**Why:** pg-embed 1.0.0 is the latest release and requires `zip = "8"`. zip 8.x is
affected by RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369 (fixed in
zip 9.0.0), which fails the `cargo audit` gate. pg-embed never calls the affected
`extract()` paths, but the lockfile is what the audit reads.

**Changes from upstream (only these):**

- `Cargo.toml`: `zip` 8 -> 9 with `default-features = false, features = ["deflate"]`;
  the crates.io-normalized manifest is replaced by a hand-written one; integration
  tests (`tests/`, `migration_test/`), assets and the upstream lockfile are not copied;
  `publish = false`.
- `README.md`: documentation links point to the upstream v1.0.0 tag because the handbooks are not vendored.
- `src/pg_unpack.rs`: `ZipFile::name()` returns a `Result` in zip 9; an entry whose
  name cannot be decoded is skipped (it cannot be the `.txz` tarball). No other source change.

**Removing it:** once an upstream pg-embed release accepts zip >= 9, delete this
directory and the `[patch.crates-io]` entry, and drop it from `[workspace] exclude`.
