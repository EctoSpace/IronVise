# sqlx-sqlite 0.9.0 dependency-range backport

Source: crates.io sqlx-sqlite 0.9.0, retaining its MIT and Apache-2.0 licenses.
Original crates.io archive SHA-256: `488e99c397a62007e4229aec669a179816339afc6d2620ca6fa420dbee2e982c`.

The only change is in Cargo.toml: the `libsqlite3-sys` requirement is widened
from `>=0.30.1, <0.38.0` to `>=0.30.1, <0.40.0`, so the build can use
libsqlite3-sys 0.39.1, which bundles SQLite 3.54.1 and fixes RUSTSEC-2026-0459
(SQLite before 3.54.0 can return uninitialized page-cache memory when a database
is opened with a `-wal` file of a different page size). `ironvise verify-ledger`
opens ledger files that other people hand over, so this path is reachable.
No source file changed and no advisory ignore is used.

The optional `sqlcipher` feature still builds `sqlcipher-src` 4.19.0, which
bundles SQLite 3.53.4 and is affected until SQLCipher ships a fixed release.

Remove this patch when a sqlx release accepts libsqlite3-sys 0.39 or later.
