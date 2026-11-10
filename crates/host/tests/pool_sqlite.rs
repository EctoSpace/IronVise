//! `DatabasePool` on SQLite: the methods the server and agent loop call that
//! no other test reaches directly.

use ectoledger::pool::{DatabasePool, create_sqlite_pool, is_postgres_url};
use ectoledger::schema::EventPayload;
use std::path::Path;
use uuid::Uuid;

async fn memory_pool() -> DatabasePool {
    create_sqlite_pool(Path::new(":memory:"))
        .await
        .expect("create in-memory sqlite pool")
}

async fn session(pool: &DatabasePool, goal: &str) -> (Uuid, ed25519_dalek::SigningKey) {
    let (row, key) = pool
        .create_session(goal, "mock", "mock-v1", Some("policy-hash-1"))
        .await
        .expect("create session");
    (row.id, key)
}

async fn append(
    pool: &DatabasePool,
    id: Uuid,
    goal: &str,
    key: &ed25519_dalek::SigningKey,
    payload: EventPayload,
) -> ectoledger::schema::AppendedEvent {
    pool.append_event(payload, Some(id), Some(goal), Some(key))
        .await
        .expect("append event")
}

fn http_get(url: &str) -> EventPayload {
    EventPayload::Action {
        name: "http_get".to_string(),
        params: serde_json::json!({ "url": url }),
    }
}

fn observation(content: &str) -> EventPayload {
    EventPayload::Observation {
        content: content.to_string(),
    }
}

#[tokio::test]
async fn a_sqlite_pool_reports_full_capabilities() {
    let caps = memory_pool().await.capabilities();
    assert_eq!(caps.ledger_backend, "sqlite");
    assert!(caps.agent_supported && caps.exports_supported && caps.webhooks_live);
}

#[test]
fn only_postgres_schemes_count_as_postgres_urls() {
    assert!(is_postgres_url("postgres://u:p@localhost/db"));
    assert!(is_postgres_url(" PostgreSQL://host/db"));
    assert!(!is_postgres_url("sqlite://ledger.db"));
    assert!(!is_postgres_url("sqlite::memory:"));
    assert!(!is_postgres_url("http://postgres.example"));
}

#[tokio::test]
async fn a_session_keeps_its_goal_status_and_policy_hash() {
    let pool = memory_pool().await;
    let (id, _) = session(&pool, "review the nginx config").await;

    assert_eq!(
        pool.session_goal_and_status(id).await.unwrap(),
        Some(("review the nginx config".to_string(), "running".to_string()))
    );
    assert_eq!(
        pool.get_session_policy_hash(id).await.unwrap().as_deref(),
        Some("policy-hash-1")
    );
    assert_eq!(
        pool.session_goal_and_status(Uuid::new_v4()).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn the_goal_hash_matches_only_the_goal_the_session_started_with() {
    let pool = memory_pool().await;
    let (id, _) = session(&pool, "audit TLS on the public endpoint").await;

    assert!(
        pool.verify_goal_hash(id, "audit TLS on the public endpoint")
            .await
            .unwrap()
    );
    assert!(
        !pool
            .verify_goal_hash(id, "audit TLS on the public endpoint!")
            .await
            .unwrap()
    );
    assert!(
        !pool
            .verify_goal_hash(Uuid::new_v4(), "anything")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_session_created_with_a_did_records_it() {
    let pool = memory_pool().await;
    let (row, _) = pool
        .create_session_with_did("goal", "mock", "mock-v1", None, Some("did:key:z6Mk-test"))
        .await
        .unwrap();
    let listed = pool.list_sessions().await.unwrap();
    let stored = listed.iter().find(|s| s.id == row.id).expect("listed");
    assert_eq!(stored.session_did.as_deref(), Some("did:key:z6Mk-test"));
}

#[tokio::test]
async fn running_sessions_are_listed_until_they_finish() {
    let pool = memory_pool().await;
    let (a, _) = session(&pool, "a").await;
    let (b, _) = session(&pool, "b").await;
    pool.finish_session(a, "completed").await.unwrap();

    let running = pool.list_running_session_ids().await.unwrap();
    assert!(running.contains(&b));
    assert!(!running.contains(&a));
}

#[tokio::test]
async fn a_session_page_filters_by_status_and_pages_newest_first() {
    let pool = memory_pool().await;
    let mut ids = Vec::new();
    for goal in ["first", "second", "third"] {
        ids.push(session(&pool, goal).await.0);
        // created_at orders the page; keep the three apart.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    pool.finish_session(ids[0], "completed").await.unwrap();

    let running = pool
        .list_sessions_filtered(Some("running"), 10, 0)
        .await
        .unwrap();
    assert_eq!(
        running.iter().map(|s| s.goal.as_str()).collect::<Vec<_>>(),
        ["third", "second"]
    );

    let first_page = pool.list_sessions_filtered(None, 2, 0).await.unwrap();
    let second_page = pool.list_sessions_filtered(None, 2, 2).await.unwrap();
    assert_eq!(
        first_page
            .iter()
            .map(|s| s.goal.as_str())
            .collect::<Vec<_>>(),
        ["third", "second"]
    );
    assert_eq!(
        second_page
            .iter()
            .map(|s| s.goal.as_str())
            .collect::<Vec<_>>(),
        ["first"]
    );
}

#[tokio::test]
async fn an_executing_action_is_dangling_until_it_completes_or_fails() {
    let pool = memory_pool().await;
    let goal = "check the API";
    let (id, key) = session(&pool, goal).await;
    let done = append(&pool, id, goal, &key, http_get("https://example.com/a")).await;
    let failed = append(&pool, id, goal, &key, http_get("https://example.com/b")).await;
    pool.mark_action_executing(done.id).await.unwrap();
    pool.mark_action_executing(failed.id).await.unwrap();
    assert_eq!(
        pool.get_dangling_actions().await.unwrap(),
        [done.id, failed.id]
    );

    pool.mark_action_completed(done.id).await.unwrap();
    pool.mark_action_failed(failed.id, "connection refused")
        .await
        .unwrap();
    assert!(pool.get_dangling_actions().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_completed_http_get_is_answered_from_its_recorded_observation() {
    let pool = memory_pool().await;
    let goal = "check the API";
    let (id, key) = session(&pool, goal).await;
    let action = append(
        &pool,
        id,
        goal,
        &key,
        http_get("https://example.com/status"),
    )
    .await;
    append(&pool, id, goal, &key, observation("200 OK: healthy")).await;

    // Not cached until the action is recorded as completed.
    pool.mark_action_executing(action.id).await.unwrap();
    assert_eq!(
        pool.find_cached_http_get("https://example.com/status")
            .await
            .unwrap(),
        None
    );

    pool.mark_action_completed(action.id).await.unwrap();
    assert_eq!(
        pool.find_cached_http_get("https://example.com/status")
            .await
            .unwrap()
            .as_deref(),
        Some("200 OK: healthy")
    );
    assert_eq!(
        pool.find_cached_http_get("https://example.com/other")
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn events_since_an_id_are_returned_in_order_and_can_be_scoped_to_a_session() {
    let pool = memory_pool().await;
    let (a, key_a) = session(&pool, "a").await;
    let (b, key_b) = session(&pool, "b").await;
    let first = append(&pool, a, "a", &key_a, observation("a1")).await;
    let b1 = append(&pool, b, "b", &key_b, observation("b1")).await;
    let a2 = append(&pool, a, "a", &key_a, observation("a2")).await;

    let all: Vec<i64> = pool
        .stream_events_since(first.id, None)
        .await
        .unwrap()
        .iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(all, [b1.id, a2.id]);

    let only_a: Vec<i64> = pool
        .stream_events_since(0, Some(a))
        .await
        .unwrap()
        .iter()
        .map(|e| e.id)
        .collect();
    assert!(only_a.contains(&first.id) && only_a.contains(&a2.id));
    assert!(!only_a.contains(&b1.id));
}

#[tokio::test]
async fn an_event_range_is_inclusive_by_sequence() {
    let pool = memory_pool().await;
    let goal = "g";
    let (id, key) = session(&pool, goal).await;
    let one = append(&pool, id, goal, &key, observation("one")).await;
    let two = append(&pool, id, goal, &key, observation("two")).await;
    append(&pool, id, goal, &key, observation("three")).await;

    let range: Vec<i64> = pool
        .get_events_range(one.sequence, two.sequence)
        .await
        .unwrap()
        .iter()
        .map(|e| e.sequence)
        .collect();
    assert_eq!(range, [one.sequence, two.sequence]);
}

#[tokio::test]
async fn a_compliance_bundle_lists_every_event_hash_of_its_session_only() {
    let pool = memory_pool().await;
    let (a, key_a) = session(&pool, "a").await;
    let (b, key_b) = session(&pool, "b").await;
    let a1 = append(&pool, a, "a", &key_a, observation("a1")).await;
    append(&pool, b, "b", &key_b, observation("b1")).await;

    let bundle = pool.prove_compliance_for_session(a).await.unwrap();
    let hashes: Vec<&str> = bundle["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["content_hash"].as_str().unwrap())
        .collect();
    assert_eq!(bundle["session_id"], a.to_string());
    assert_eq!(bundle["event_count"], hashes.len());
    assert!(hashes.contains(&a1.content_hash.as_str()));
    let b_events = pool.get_events_by_session(b).await.unwrap();
    assert!(
        b_events
            .iter()
            .all(|e| !hashes.contains(&e.content_hash.as_str()))
    );
}

#[tokio::test]
async fn a_new_ledger_has_no_snapshot() {
    assert!(
        memory_pool()
            .await
            .get_latest_snapshot()
            .await
            .unwrap()
            .is_none()
    );
}
