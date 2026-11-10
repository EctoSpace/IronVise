//! Running the embedded migrations, tolerant of line endings only.
//!
//! sqlx records a SHA-384 of each migration's text when it applies it, and on
//! every later start refuses to run if the embedded text hashes differently
//! (`VersionMismatch`). The text a binary embeds depends on the checkout it was
//! built from: 0.6.x had no `.gitattributes`, so the official 0.6.3 Windows
//! release (built from a CRLF checkout) recorded checksums of CRLF text, while
//! 0.8 embeds LF everywhere. Without this, every Windows ledger from 0.6.3
//! would fail to open in 0.8.
//!
//! Before migrating, a recorded checksum that equals the embedded migration
//! with the *other* line endings is rewritten to the embedded checksum. Only
//! that exact case: a migration whose text really changed still fails, so this
//! does not weaken the immutability check (`tests/migration_immutability.rs`).
//!
//! Two files that shipped in public v0.6.3 were later edited inside comments
//! (an ASCII "to" became a unicode arrow, and "abc..." became an ellipsis).
//! sqlx hashes the whole file, so that edit made every 0.6.3 database refuse
//! to open. Those files are restored to the tag bytes. Later schema changes
//! stay in newer migration files. `V063_CHECKSUMS.json` is the SHA-384 sqlx
//! records for every migration that tag shipped.

use sha2::{Digest, Sha384};
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{PgPool, SqlitePool};

/// The checksum to record instead of `stored`, if `stored` is this
/// migration's SQL with different line endings; `None` otherwise.
pub fn line_ending_repair(sql: &str, embedded: &[u8], stored: &[u8]) -> Option<Vec<u8>> {
    if stored == embedded {
        return None;
    }
    let lf = sql.replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    [lf, crlf]
        .iter()
        .any(|variant| Sha384::digest(variant.as_bytes()).as_slice() == stored)
        .then(|| embedded.to_vec())
}

/// Pairs of (version, new checksum) for the recorded rows that need repair.
fn repairs(migrator: &Migrator, recorded: &[(i64, Vec<u8>)]) -> Vec<(i64, Vec<u8>)> {
    recorded
        .iter()
        .filter_map(|(version, stored)| {
            let m = migrator
                .migrations
                .iter()
                .find(|m| m.version == *version && !m.migration_type.is_down_migration())?;
            line_ending_repair(m.sql.as_str(), &m.checksum, stored).map(|new| (*version, new))
        })
        .collect()
}

fn report(fixed: usize) {
    if fixed > 0 {
        tracing::warn!(
            "{fixed} migration checksum(s) were recorded from a build with different line \
             endings (an older Windows build); updated them. The ledger's contents are unchanged."
        );
    }
}

/// Repair line-ending-only checksum differences, then run the SQLite migrations.
pub async fn migrate_sqlite(pool: &SqlitePool) -> Result<(), MigrateError> {
    let migrator = sqlx::migrate!("./migrations/sqlite");
    let exists: Option<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_optional(pool)
    .await?;
    if exists.is_some() {
        let recorded: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations")
                .fetch_all(pool)
                .await?;
        let fixes = repairs(&migrator, &recorded);
        for (version, checksum) in &fixes {
            sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = ?")
                .bind(checksum)
                .bind(version)
                .execute(pool)
                .await?;
        }
        report(fixes.len());
    }
    migrator.run(pool).await
}

/// Repair line-ending-only checksum differences, then run the PostgreSQL migrations.
pub async fn migrate_postgres(pool: &PgPool) -> Result<(), MigrateError> {
    let migrator = sqlx::migrate!("./migrations");
    let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations')::text")
        .fetch_one(pool)
        .await?;
    if exists.is_some() {
        let recorded: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations")
                .fetch_all(pool)
                .await?;
        let fixes = repairs(&migrator, &recorded);
        for (version, checksum) in &fixes {
            sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
                .bind(checksum)
                .bind(version)
                .execute(pool)
                .await?;
        }
        report(fixes.len());
    }
    migrator.run(pool).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(s: &str) -> Vec<u8> {
        Sha384::digest(s.as_bytes()).to_vec()
    }

    #[test]
    fn a_crlf_checksum_is_repaired_to_the_embedded_lf_one() {
        let sql = "CREATE TABLE t (\n  id INTEGER\n);\n";
        let crlf = sql.replace('\n', "\r\n");
        assert_eq!(
            line_ending_repair(sql, &sha(sql), &sha(&crlf)),
            Some(sha(sql))
        );
    }

    #[test]
    fn an_lf_checksum_is_repaired_when_the_build_embedded_crlf() {
        let lf = "CREATE TABLE t (\n  id INTEGER\n);\n";
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(
            line_ending_repair(&crlf, &sha(&crlf), &sha(lf)),
            Some(sha(&crlf))
        );
    }

    #[test]
    fn a_matching_checksum_needs_nothing() {
        let sql = "SELECT 1;\n";
        assert_eq!(line_ending_repair(sql, &sha(sql), &sha(sql)), None);
    }

    #[test]
    fn a_really_changed_migration_is_not_repaired() {
        let sql = "CREATE TABLE t (id INTEGER);\n";
        let edited = "CREATE TABLE t (id INTEGER, x TEXT);\r\n";
        assert_eq!(line_ending_repair(sql, &sha(sql), &sha(edited)), None);
    }
}

#[cfg(test)]
#[path = "migrations_upgrade_test.rs"]
mod upgrade_test;
