use super::*;
use crate::schema::EventPayload;

#[tokio::test]
async fn a_failed_sqlite_reset_preserves_the_ledger_and_immutability() {
    let pool = create_sqlite_pool(Path::new(":memory:")).await.unwrap();
    let (session, key) = pool
        .create_session("reset test", "test", "test", None)
        .await
        .unwrap();
    pool.append_event(
        EventPayload::Thought {
            content: "keep me".into(),
        },
        Some(session.id),
        Some("reset test"),
        Some(&key),
    )
    .await
    .unwrap();
    let db = pool.as_sqlite().unwrap();
    sqlx::query("CREATE TRIGGER reject_reset BEFORE DELETE ON agent_sessions BEGIN SELECT RAISE(ABORT, 'injected reset failure'); END")
        .execute(db).await.unwrap();
    assert!(pool.reset_demo_data().await.is_err());
    assert_eq!(
        pool.get_events_by_session(session.id).await.unwrap().len(),
        1
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('agent_events_no_update','agent_events_no_delete','agent_event_signatures_no_update','agent_event_signatures_no_delete')")
        .fetch_one(db).await.unwrap();
    assert_eq!(count, 4, "rollback must restore every immutability trigger");
    assert!(
        sqlx::query("UPDATE agent_events SET content_hash = 'corrupt'")
            .execute(db)
            .await
            .is_err()
    );
    sqlx::query("DROP TRIGGER reject_reset")
        .execute(db)
        .await
        .unwrap();
    pool.reset_demo_data().await.unwrap();
    assert!(pool.list_sessions().await.unwrap().is_empty());
    assert!(
        pool.get_events_by_session(session.id)
            .await
            .unwrap()
            .is_empty()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'agent_%_no_%'",
    )
    .fetch_one(db)
    .await
    .unwrap();
    assert_eq!(count, 4);
}
