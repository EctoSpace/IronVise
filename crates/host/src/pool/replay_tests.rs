use super::*;

/// The replay record is in the database, not in memory: a restart does not
/// reopen the window for a request already acted on.
#[tokio::test]
async fn a_consumed_request_stays_consumed_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let pool = create_sqlite_pool(&path).await.unwrap();
    assert!(
        pool.consume_request("hook:s", "toolu_1", "caller")
            .await
            .unwrap()
    );
    assert!(
        !pool
            .consume_request("hook:s", "toolu_1", "caller")
            .await
            .unwrap()
    );
    assert!(
        pool.consume_request("hook:other", "toolu_1", "caller")
            .await
            .unwrap()
    );
    drop(pool);

    let reopened = create_sqlite_pool(&path).await.unwrap();
    assert!(
        !reopened
            .consume_request("hook:s", "toolu_1", "caller")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn purging_keeps_ids_inside_the_retention_window() {
    let pool = create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    pool.consume_request("s", "fresh", "c").await.unwrap();
    let DatabasePool::Sqlite(p) = &pool else {
        unreachable!()
    };
    sqlx::query(
        "INSERT INTO consumed_requests (scope, request_id, caller, consumed_at) \
         VALUES ('s', 'old', 'c', strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-31 days'))",
    )
    .execute(p)
    .await
    .unwrap();
    assert_eq!(pool.purge_consumed_requests().await.unwrap(), 1);
    assert!(
        !pool.consume_request("s", "fresh", "c").await.unwrap(),
        "kept"
    );
    assert!(
        pool.consume_request("s", "old", "c").await.unwrap(),
        "forgotten"
    );
}
