//! Applied migrations are immutable. This test enforces it.
//!
//! sqlx records a checksum for every migration it applies. If a migration file
//! changes afterwards, `sqlx::migrate!().run()` refuses to start with
//! `VersionMismatch` - so editing a shipped migration does not cause a subtle
//! problem later, it stops every existing deployment from booting.
//!
//! That happened between public v0.6.3 and this tree. Those two files shipped
//! as ASCII, then a later edit changed only a comment:
//!
//!   20260222000011  "NULL to 'proposed'"  became a unicode arrow
//!   20260223000012  "abc..."               became a unicode ellipsis
//!
//! The SQL that runs was unchanged. sqlx hashes the whole file, so every
//! database created by 0.6.3 refused to open (`VersionMismatch`: "migration
//! ... was previously applied but has been modified"). The files are restored
//! to the public tag bytes (commit cf7d29df91738d983fcef0635539b02aac6a847d).
//!
//! `CHECKSUMS.json` pins SHA-256 of every migration that exists now.
//! `V063_CHECKSUMS.json` pins the sqlx SHA-384 of every migration that tag
//! shipped. Adding a migration is fine: add it to `CHECKSUMS.json` in the same
//! commit. Changing one that already exists is not, no matter how cosmetic.
//! Do not update `V063_CHECKSUMS.json` to match an edit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!("../migrations/CHECKSUMS.json");

fn migrations_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

/// Every `.sql` under `migrations/`, relative path → SHA-256 of its bytes.
fn on_disk() -> BTreeMap<String, String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).expect("reading migrations") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "sql") {
                let bytes = std::fs::read(&path).expect("reading migration");
                let rel = path
                    .strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, hex::encode(Sha256::digest(&bytes)));
            }
        }
    }
    let root = migrations_root();
    let mut out = BTreeMap::new();
    walk(&root, &root, &mut out);
    out
}

fn manifest() -> BTreeMap<String, String> {
    serde_json::from_str(MANIFEST).expect("CHECKSUMS.json parses")
}

#[test]
fn no_applied_migration_has_been_edited() {
    let disk = on_disk();
    let pinned = manifest();

    let changed: Vec<_> = pinned
        .iter()
        .filter_map(|(name, want)| {
            disk.get(name)
                .filter(|got| *got != want)
                .map(|got| format!("  {name}\n    pinned {want}\n    found  {got}"))
        })
        .collect();

    assert!(
        changed.is_empty(),
        "\nA migration file has changed after being pinned:\n\n{}\n\n\
         sqlx checksums applied migrations, so this breaks startup for every \
         existing deployment with `VersionMismatch` - including for a change \
         confined to a comment.\n\n\
         Revert the edit. If the migration genuinely must change, it needs a \
         NEW migration file; the old one stays exactly as it shipped.\n",
        changed.join("\n\n")
    );
}

#[test]
fn no_migration_has_been_deleted() {
    let disk = on_disk();
    let missing: Vec<_> = manifest()
        .keys()
        .filter(|name| !disk.contains_key(*name))
        .cloned()
        .collect();

    assert!(
        missing.is_empty(),
        "migration files were deleted, which strands every database that \
         already applied them: {missing:?}"
    );
}

#[test]
fn every_migration_is_pinned() {
    // A new migration is fine; an unpinned one means the manifest was not
    // updated, and the guard would silently stop covering it.
    let pinned = manifest();
    let unpinned: Vec<_> = on_disk()
        .keys()
        .filter(|name| !pinned.contains_key(*name))
        .cloned()
        .collect();

    assert!(
        unpinned.is_empty(),
        "new migrations are not pinned in migrations/CHECKSUMS.json: {unpinned:?}\n\
         Add them in the same commit that adds the migration."
    );
}
