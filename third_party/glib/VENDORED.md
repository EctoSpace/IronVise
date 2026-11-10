# glib 0.18.5 security backport

Source: crates.io glib 0.18.5, retaining its MIT license and COPYRIGHT.
The security change in src/variant_iter.rs makes the C out-pointer mutable and passes
`&mut p`, matching https://github.com/gtk-rs/gtk-rs-core/pull/1343 for
RUSTSEC-2024-0429. No version inflation or advisory ignore is used.
GTK3/Tauri requires the 0.18 API; glib >=0.20 is not a drop-in update.
Version-only scanners may still identify this version; cargo audit may omit path dependencies.
A clean scanner result does not validate a backport. The source backport must be reviewed
and Linux optimized iterator tests run before shipping Linux installers.
Remove this patch when the supported Tauri GTK stack includes the fix.

Rust 1.99 compatibility: explicit lifetimes in borrowed return types and trait
paths, plus removal of redundant trait-object parentheses. These mechanical
compiler suggestions keep the path dependency building under `-D warnings`;
they do not suppress lints or change the iterator backport.

Original crates.io archive SHA-256: `233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`.
The added `tests/ironvise_variant_iter.rs` exercises next, next_back, nth,
nth_back and last with an optimized build.
