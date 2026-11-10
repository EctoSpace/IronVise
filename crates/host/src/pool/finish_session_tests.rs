use super::*;
use uuid::Uuid;

async fn sqlite_pool() -> DatabasePool {
    create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .expect("sqlite pool")
}

async fn status_of(pool: &DatabasePool, id: Uuid) -> String {
    pool.list_sessions()
        .await
        .expect("list")
        .into_iter()
        .find(|s| s.id == id)
        .expect("session")
        .status
}

/// Asserted against a pool that was actually opened, not a hand-built
/// struct: the other capability tests construct `PoolCapabilities` by hand,
/// so they would keep passing if `capabilities()` itself reported the wrong
/// backend.
#[tokio::test]
async fn a_live_sqlite_pool_reports_sqlite_capabilities() {
    let pool = sqlite_pool().await;
    let caps = pool.capabilities();
    assert_eq!(caps.ledger_backend, "sqlite");
    // SQLite reached parity in 0.8.0 - the cognitive loop, exports and
    // webhooks all run on it now. This asserts that parity rather than
    // the degraded set SQLite used to report.
    assert!(caps.agent_supported);
    assert!(caps.exports_supported);
    assert!(caps.webhooks_live);
}

#[tokio::test]
async fn finish_session_if_running_does_not_unseal_via_the_pool() {
    let pool = sqlite_pool().await;
    let (session, _) = pool
        .create_session("pool seal", "mock", "mock-v1", None)
        .await
        .expect("create");
    pool.finish_session(session.id, "completed")
        .await
        .expect("seal");
    pool.finish_session_if_running(session.id, "failed")
        .await
        .expect("no-op");
    assert_eq!(status_of(&pool, session.id).await, "completed");
}

#[tokio::test]
async fn finish_session_if_running_still_marks_a_running_session() {
    let pool = sqlite_pool().await;
    let (session, _) = pool
        .create_session("pool running", "mock", "mock-v1", None)
        .await
        .expect("create");
    pool.finish_session_if_running(session.id, "failed")
        .await
        .expect("finish");
    assert_eq!(status_of(&pool, session.id).await, "failed");
}
