mod common;

use common::{assert_chain_valid, reset_ledger, spawn_test_pool};
use ectoledger::ledger;
use ectoledger::schema::EventPayload;
use serial_test::serial;

#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn genesis_valid() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    let appended = ledger::ensure_genesis(&pool).await.expect("ensure_genesis");
    assert_eq!(appended.sequence, 0);
    assert_chain_valid(&pool, 0, 0).await;
}

#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn chain_of_10_valid() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("ensure_genesis");
    for i in 1..=10 {
        ledger::append_event(
            &pool,
            EventPayload::Thought {
                content: format!("step {i}"),
            },
            None,
            None,
            None,
        )
        .await
        .expect("append");
    }
    assert_chain_valid(&pool, 0, 10).await;
}

#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn tampered_hash_detected() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("ensure_genesis");
    ledger::append_event(
        &pool,
        EventPayload::Thought {
            content: "one".to_string(),
        },
        None,
        None,
        None,
    )
    .await
    .expect("append");
    // Tamper: change content_hash of the last event.
    // The append-only trigger blocks UPDATE in normal operation (by design), so we
    // temporarily disable it for this test to simulate an out-of-band tampering
    // scenario (e.g., a compromised DB admin) that verify_chain must detect.
    sqlx::query("ALTER TABLE agent_events DISABLE TRIGGER ALL")
        .execute(&pool)
        .await
        .expect("disable trigger");
    sqlx::query("UPDATE agent_events SET content_hash = 'tampered' WHERE sequence = 1")
        .execute(&pool)
        .await
        .expect("update");
    sqlx::query("ALTER TABLE agent_events ENABLE TRIGGER ALL")
        .execute(&pool)
        .await
        .expect("enable trigger");
    let valid = ledger::verify_chain(&pool, 0, 1).await.expect("verify");
    assert!(!valid);
}

/// Canonical v2 hash equality across paths, Postgres leg: an event appended
/// through the Postgres backend must store exactly the hash produced by
/// `compute_content_hash_v2` over (previous_hash, sequence, payload_json,
/// session_id, created_at) - the same formula the SQLite backend and the SP1
/// guest use - and the shared multi-scheme verifier must identify it as V2.
#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn content_hash_matches_canonical_v2_formula() {
    use ectoledger::hash::{HashScheme, compute_content_hash_v2, verify_content_hash_any_scheme};

    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("ensure_genesis");

    let (session, key) = ledger::create_session(&pool, "hash equality", "test", "mock-v1", None)
        .await
        .expect("create_session");
    let payload = EventPayload::Thought {
        content: "canonical".to_string(),
    };
    let payload_json = serde_json::to_string(&payload).expect("serialize");
    let appended = ledger::append_event(&pool, payload, Some(session.id), None, Some(&key))
        .await
        .expect("append");

    let sid = session.id.to_string();
    let ts = appended.created_at.to_rfc3339();
    let expected = compute_content_hash_v2(
        &appended.previous_hash,
        appended.sequence,
        &payload_json,
        Some(&sid),
        &ts,
    );
    assert_eq!(
        appended.content_hash, expected,
        "Postgres-stored hash must equal the canonical v2 formula"
    );
    assert_eq!(
        verify_content_hash_any_scheme(
            &appended.previous_hash,
            appended.sequence,
            &payload_json,
            Some(&sid),
            Some(&ts),
            &appended.content_hash,
        ),
        Some(HashScheme::V2),
        "guest verifier must identify the stored hash as canonical v2"
    );

    // Read the row back and verify through the chain verifier as well.
    assert_chain_valid(&pool, 0, appended.sequence).await;
}

// F-4 on PostgreSQL: an absent signature is not a pass.
//
// The SQLite leg is pinned in `ledger/sqlite.rs`; the two backends share the
// rule through `ledger::SignatureCoverage`, and these check the Postgres
// verifier actually applies it.

async fn signed_pg_session(pool: &sqlx::PgPool) -> uuid::Uuid {
    ledger::ensure_genesis(pool).await.expect("ensure_genesis");
    let (session, sk) = ledger::create_session(pool, "f-4 goal", "test", "test", None)
        .await
        .expect("create_session");
    ledger::append_event(
        pool,
        EventPayload::Action {
            name: "run_command".into(),
            params: serde_json::json!({ "command": "ls" }),
        },
        Some(session.id),
        Some("f-4 goal"),
        Some(&sk),
    )
    .await
    .expect("append signed");
    session.id
}

const TABLES_DISABLE: [&str; 3] = [
    "ALTER TABLE agent_events DISABLE TRIGGER ALL",
    "ALTER TABLE agent_event_signatures DISABLE TRIGGER ALL",
    "ALTER TABLE agent_sessions DISABLE TRIGGER ALL",
];
const TABLES_ENABLE: [&str; 3] = [
    "ALTER TABLE agent_events ENABLE TRIGGER ALL",
    "ALTER TABLE agent_event_signatures ENABLE TRIGGER ALL",
    "ALTER TABLE agent_sessions ENABLE TRIGGER ALL",
];

/// Runs the tampering `sql`, a test's own statement, with the append-only
/// triggers switched off.
async fn with_triggers_off(pool: &sqlx::PgPool, sql: &str) {
    for statement in TABLES_DISABLE {
        sqlx::query(statement).execute(pool).await.expect("disable");
    }
    sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
        .execute(pool)
        .await
        .expect("tamper");
    for statement in TABLES_ENABLE {
        sqlx::query(statement).execute(pool).await.expect("enable");
    }
}

#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn pg_an_untampered_signed_session_verifies() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    let sid = signed_pg_session(&pool).await;
    let v = ledger::postgres::verify_session_detailed(&pool, sid)
        .await
        .unwrap();
    assert!(v.is_verified(), "{v}");
}

#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn pg_deleting_every_signature_is_detected() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    let sid = signed_pg_session(&pool).await;
    with_triggers_off(&pool, "DELETE FROM agent_event_signatures").await;
    let v = ledger::postgres::verify_session_detailed(&pool, sid)
        .await
        .unwrap();
    assert!(
        matches!(v, ledger::SessionVerdict::MissingSignature { .. }),
        "{v}"
    );
}

#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn pg_clearing_the_session_key_is_detected() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    let sid = signed_pg_session(&pool).await;
    with_triggers_off(&pool, "UPDATE agent_sessions SET session_public_key = NULL").await;
    let v = ledger::postgres::verify_session_detailed(&pool, sid)
        .await
        .unwrap();
    assert!(
        matches!(v, ledger::SessionVerdict::UnauthorisedKey { .. }),
        "{v}"
    );
}

#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn pg_a_client_appended_event_is_counted_not_failed() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    let sid = signed_pg_session(&pool).await;
    ledger::append_event(
        &pool,
        EventPayload::Thought {
            content: "client note".into(),
        },
        Some(sid),
        None,
        None,
    )
    .await
    .expect("append unsigned");
    assert_eq!(
        ledger::postgres::verify_session_detailed(&pool, sid)
            .await
            .unwrap(),
        ledger::SessionVerdict::Verified {
            signatures: 1,
            unsigned: 1
        }
    );
}

/// The Postgres leg of `a_rotation_cannot_authorise_the_key_that_signed_it`:
/// both backends share `ledger::KeyLifecycle`, and this checks the Postgres
/// verifier applies it.
#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn pg_a_rotation_cannot_authorise_the_key_that_signed_it() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    let sid = signed_pg_session(&pool).await;
    let (attacker, attacker_vk) = ectoledger::signing::generate_keypair();
    let rotation = ledger::append_event(
        &pool,
        EventPayload::KeyRotation {
            new_public_key: ectoledger::signing::public_key_hex(&attacker_vk),
            rotation_index: 1,
        },
        Some(sid),
        Some("f-4 goal"),
        Some(&attacker),
    )
    .await
    .expect("append rotation");
    ledger::append_event(
        &pool,
        EventPayload::Thought {
            content: "forged".into(),
        },
        Some(sid),
        Some("f-4 goal"),
        Some(&attacker),
    )
    .await
    .expect("append forged");

    let v = ledger::postgres::verify_session_detailed(&pool, sid)
        .await
        .unwrap();
    assert!(
        matches!(v, ledger::SessionVerdict::UnauthorisedKey { sequence } if sequence == rotation.sequence),
        "{v}"
    );
}

#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn pg_a_consumed_request_is_refused_the_second_time() {
    let (pool, _db) = spawn_test_pool().await;
    let pool = ectoledger::pool::DatabasePool::Postgres(pool);
    let scope = format!("hook:{}", uuid::Uuid::new_v4());
    assert!(pool.consume_request(&scope, "toolu_1", "c").await.unwrap());
    assert!(!pool.consume_request(&scope, "toolu_1", "c").await.unwrap());
    assert!(pool.consume_request(&scope, "toolu_2", "c").await.unwrap());
    pool.purge_consumed_requests().await.unwrap();
    assert!(
        !pool.consume_request(&scope, "toolu_1", "c").await.unwrap(),
        "fresh ids survive a purge"
    );
}

/// VC verification on PostgreSQL finds the session's key here. It must be
/// the key the session was created with, and nothing for an unknown session.
#[tokio::test]
#[serial]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn the_session_key_is_found_as_it_was_recorded() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    let (session, key) = ledger::create_session(&pool, "goal", "test", "n/a", None)
        .await
        .expect("create_session");
    let found = ectoledger::signing::load_session_verifying_key(&pool, session.id).await;
    assert_eq!(
        found.map(|k| k.to_bytes()),
        Some(key.verifying_key().to_bytes())
    );
    assert!(
        ectoledger::signing::load_session_verifying_key(&pool, uuid::Uuid::new_v4())
            .await
            .is_none()
    );
}
