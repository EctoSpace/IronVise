//! `--features sqlcipher` against real SQLCipher: the file is ciphertext,
//! every pooled connection is keyed, the read-only path opens it, the key
//! leaves the environment, and the file does not open without it.
//!
//! Run: `cargo test -p ectoledger --features sqlcipher --test sqlcipher`
#![cfg(feature = "sqlcipher")]

use ectoledger::pool::{DatabasePool, create_sqlite_pool, open_sqlite_pool_read_only};
use sqlx::sqlite::SqlitePoolOptions;

const KEY: &str = "a-test-passphrase-long-enough";
const GOAL: &str = "plaintext-marker-that-must-not-reach-disk";

#[tokio::test]
async fn an_encrypted_ledger_is_keyed_on_every_connection_and_scrubbed_from_the_env() {
    // SAFETY: set before any other thread reads the environment; this test
    // binary has only this test.
    unsafe { std::env::set_var("ECTOLEDGER_SQLCIPHER_KEY", KEY) };
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ledger.db");

    let DatabasePool::Sqlite(pool) = create_sqlite_pool(&path).await.expect("pool") else {
        panic!("expected SQLite");
    };
    assert!(
        std::env::var("ECTOLEDGER_SQLCIPHER_KEY").is_err(),
        "the key must leave the environment, or every child process inherits it"
    );

    // Hold all five connections at once, so each is a separate one the pool
    // opened; every one must read the encrypted file.
    let mut held = Vec::new();
    for _ in 0..5 {
        let mut conn = pool.acquire().await.expect("acquire");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master")
            .fetch_one(&mut *conn)
            .await
            .expect("a keyed connection reads the schema");
        assert!(n > 0);
        held.push(conn);
    }
    drop(held);

    let backend = DatabasePool::Sqlite(pool.clone());
    backend
        .create_session(GOAL, "test", "n/a", None)
        .await
        .expect("session");
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .expect("checkpoint");
    pool.close().await;

    let bytes = std::fs::read(&path).expect("read file");
    assert!(!bytes.starts_with(b"SQLite format 3"), "plaintext header");
    assert!(
        !bytes.windows(GOAL.len()).any(|w| w == GOAL.as_bytes()),
        "the goal is on disk in the clear"
    );

    // The read-only path is keyed too (the key is remembered, not re-read).
    let DatabasePool::Sqlite(ro) = open_sqlite_pool_read_only(&path).await.expect("read-only")
    else {
        panic!("expected SQLite");
    };
    let goal: String = sqlx::query_scalar("SELECT goal FROM agent_sessions")
        .fetch_one(&ro)
        .await
        .expect("read-only read");
    assert_eq!(goal, GOAL);
    ro.close().await;

    // Without the key the file is not a database.
    let bare = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}?mode=ro", path.display()))
        .await
        .expect("connect opens lazily");
    assert!(
        sqlx::query("SELECT count(*) FROM sqlite_master")
            .execute(&bare)
            .await
            .is_err()
    );
}
