//! A ledger whose migrations were recorded by a build with other line endings
//! (the official 0.6.3 Windows release embedded CRLF) must still open, keep
//! its data, and get its recorded checksums updated. A migration whose text
//! really changed must still be refused.

use sha2::{Digest, Sha384};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;

async fn raw(path: &std::path::Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}", path.display()))
        .await
        .unwrap()
}

/// Rewrite every recorded checksum to the CRLF form of its migration, as a
/// ledger written by the 0.6.3 Windows release has them.
async fn record_as_crlf(path: &std::path::Path) -> usize {
    let migrator = sqlx::migrate!("./migrations/sqlite");
    let pool = raw(path).await;
    let mut n = 0;
    for m in migrator
        .migrations
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
    {
        let crlf = m.sql.as_str().replace("\r\n", "\n").replace('\n', "\r\n");
        let sum = Sha384::digest(crlf.as_bytes()).to_vec();
        assert_ne!(
            sum.as_slice(),
            &*m.checksum,
            "migration {} has no newline?",
            m.version
        );
        n += sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = ?")
            .bind(sum)
            .bind(m.version)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected() as usize;
    }
    pool.close().await;
    n
}

#[tokio::test]
async fn a_ledger_recorded_with_crlf_checksums_opens_and_keeps_its_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    // A ledger with one session in it, migrated by this build.
    let pool = ectoledger::pool::create_sqlite_pool(&path).await.unwrap();
    let (session, _key) = pool
        .create_session("line endings", "test", "n/a", None)
        .await
        .unwrap();
    drop(pool);

    let rewritten = record_as_crlf(&path).await;
    assert!(rewritten > 0, "no migrations recorded");

    // Before the fix this failed with VersionMismatch on migration 1.
    let pool = ectoledger::pool::create_sqlite_pool(&path)
        .await
        .expect("a CRLF-recorded ledger must open");
    let sessions = pool.list_sessions().await.unwrap();
    assert!(
        sessions.iter().any(|s| s.id == session.id),
        "the session survived"
    );
    drop(pool);

    // The recorded checksums are the embedded ones now.
    let migrator = sqlx::migrate!("./migrations/sqlite");
    let check = raw(&path).await;
    for m in migrator
        .migrations
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
    {
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = ?")
                .bind(m.version)
                .fetch_one(&check)
                .await
                .unwrap();
        assert_eq!(stored.as_slice(), &*m.checksum, "migration {}", m.version);
    }
}

#[tokio::test]
async fn a_really_changed_migration_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    drop(ectoledger::pool::create_sqlite_pool(&path).await.unwrap());

    let pool = raw(&path).await;
    let edited = Sha384::digest(b"CREATE TABLE something_else (x INTEGER);\r\n").to_vec();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = (SELECT MIN(version) FROM _sqlx_migrations)")
        .bind(edited)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let err = ectoledger::pool::create_sqlite_pool(&path)
        .await
        .err()
        .expect("a changed migration must not be repaired away");
    assert!(
        err.to_string()
            .to_lowercase()
            .contains("previously applied")
            || err.to_string().to_lowercase().contains("mismatch")
            || err.to_string().to_lowercase().contains("modified"),
        "unexpected error: {err}"
    );
}

/// The same repair on PostgreSQL, against the integration database. Leaves
/// the checksums as the embedded ones, which is what the other tests expect.
#[cfg(feature = "integration")]
#[tokio::test]
#[serial_test::serial]
async fn postgres_crlf_checksums_are_repaired() {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set; run ./scripts/test-integration.sh");
    let pg = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    ectoledger::migrations::migrate_postgres(&pg).await.unwrap();

    let migrator = sqlx::migrate!("./migrations");
    for m in migrator
        .migrations
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
    {
        let crlf = m.sql.as_str().replace("\r\n", "\n").replace('\n', "\r\n");
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
            .bind(Sha384::digest(crlf.as_bytes()).to_vec())
            .bind(m.version)
            .execute(&pg)
            .await
            .unwrap();
    }
    // Plain sqlx refuses this ledger; the helper repairs and migrates. The
    // refused run gets a connection of its own, closed after: sqlx leaves its
    // advisory lock held when a run fails, and on a pooled connection that
    // lock makes the helper below wait forever.
    {
        use sqlx::Connection;
        let mut conn = sqlx::PgConnection::connect(&url).await.unwrap();
        assert!(
            migrator.run(&mut conn).await.is_err(),
            "the CRLF checksums must trip sqlx"
        );
        conn.close().await.unwrap();
    }
    ectoledger::migrations::migrate_postgres(&pg)
        .await
        .expect("a CRLF-recorded PostgreSQL ledger must open");
    assert!(
        migrator.run(&pg).await.is_ok(),
        "checksums are the embedded ones again"
    );
}
