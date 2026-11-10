//! Two instances on one PostgreSQL database: an approval gate opened by the
//! loop on one is seen, and decided, through the other, and a gate is decided
//! once however the instances race.

mod common;

use std::sync::Arc;

use chrono::Utc;
use common::spawn_test_pool;
use ectoledger::approvals::{ApprovalState, DecisionOutcome, PendingApproval};
use ectoledger::pool::DatabasePool;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const TOKEN: &str = "multi-instance-admin";

fn gate(id: &str) -> PendingApproval {
    PendingApproval {
        gate_id: id.to_string(),
        action_name: "run_command".to_string(),
        action_params_summary: r#"{"command":"nmap -sV host"}"#.to_string(),
        created_at: Utc::now(),
    }
}

/// Two instances: separate pools on the same database, as two servers have.
async fn two_instances() -> (ApprovalState, ApprovalState, sqlx::PgPool) {
    let (a, _) = spawn_test_pool().await;
    let (b, _) = spawn_test_pool().await;
    (
        ApprovalState::shared(a),
        ApprovalState::shared(b.clone()),
        b,
    )
}

#[tokio::test]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn a_gate_opened_on_one_instance_is_decided_through_another() {
    let (loop_side, api_side, _) = two_instances().await;
    let session = Uuid::new_v4();
    loop_side.publish(session, gate("g1")).await.unwrap();

    let seen = api_side
        .pending(session)
        .await
        .unwrap()
        .expect("visible on B");
    assert_eq!(seen.gate_id, "g1");
    assert_eq!(seen.action_name, "run_command");

    let outcome = api_side
        .decide(session, "g1".into(), true, Some("scoped".into()))
        .await
        .unwrap();
    assert_eq!(outcome, DecisionOutcome::Recorded);
    assert!(api_side.pending(session).await.unwrap().is_none());

    let decision = loop_side.take(session, "g1").await.unwrap();
    assert_eq!(decision, Some((true, Some("scoped".into()))));
    assert_eq!(
        loop_side.take(session, "g1").await.unwrap(),
        None,
        "consumed once"
    );
}

#[tokio::test]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn racing_decisions_on_two_instances_record_exactly_one() {
    let (a, b, _) = two_instances().await;
    let session = Uuid::new_v4();
    a.publish(session, gate("race")).await.unwrap();

    let (approve, deny) = tokio::join!(
        a.decide(session, "race".into(), true, None),
        b.decide(session, "race".into(), false, None),
    );
    let outcomes = [approve.unwrap(), deny.unwrap()];
    let recorded = outcomes
        .iter()
        .filter(|o| **o == DecisionOutcome::Recorded)
        .count();
    assert_eq!(recorded, 1, "{outcomes:?}");
    assert!(
        outcomes.contains(&DecisionOutcome::NotPending),
        "{outcomes:?}"
    );
}

#[tokio::test]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn a_decision_for_another_gate_or_after_the_timeout_is_refused() {
    let (loop_side, api_side, _) = two_instances().await;
    let session = Uuid::new_v4();
    loop_side.publish(session, gate("current")).await.unwrap();
    let wrong = api_side
        .decide(session, "stale".into(), true, None)
        .await
        .unwrap();
    assert_eq!(wrong, DecisionOutcome::GateMismatch);

    // The loop times out first: the gate is withdrawn, and a late click finds
    // nothing to decide.
    assert_eq!(loop_side.withdraw(session, "current").await.unwrap(), None);
    let late = api_side
        .decide(session, "current".into(), true, None)
        .await
        .unwrap();
    assert_eq!(late, DecisionOutcome::NotPending);

    // A decision that arrived first stands at the timeout.
    loop_side.publish(session, gate("next")).await.unwrap();
    api_side
        .decide(session, "next".into(), false, Some("no".into()))
        .await
        .unwrap();
    let stands = loop_side.withdraw(session, "next").await.unwrap();
    assert_eq!(stands, Some((false, Some("no".into()))));
}

#[tokio::test]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn the_approvals_api_of_another_instance_serves_the_gate() {
    let (loop_side, _, api_pool) = two_instances().await;
    let pool = DatabasePool::Postgres(api_pool);
    let hash = hex::encode(Sha256::digest(TOKEN.as_bytes()));
    pool.insert_token(&hash, "admin", Some("multi-instance test"), None)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let metrics = Arc::new(ectoledger::metrics::Metrics::default());
    tokio::spawn(ectoledger::start_server(pool, metrics, listener));

    let session = Uuid::new_v4();
    loop_side.publish(session, gate("http")).await.unwrap();

    let client = reqwest::Client::new();
    let auth = format!("Bearer {TOKEN}");
    let mut pending = serde_json::Value::Null;
    for _ in 0..100 {
        match client
            .get(format!("{base}/api/approvals/{session}/pending"))
            .header("Authorization", &auth)
            .send()
            .await
        {
            Ok(r) => {
                pending = r.json().await.unwrap();
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert_eq!(pending["pending"]["gate_id"], "http", "{pending}");

    let decided = client
        .post(format!("{base}/api/approvals/{session}"))
        .header("Authorization", &auth)
        .json(&serde_json::json!({ "gate_id": "http", "approved": true, "reason": "ok" }))
        .send()
        .await
        .unwrap();
    assert_eq!(decided.status(), 200);
    let again = client
        .post(format!("{base}/api/approvals/{session}"))
        .header("Authorization", &auth)
        .json(&serde_json::json!({ "gate_id": "http", "approved": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 409, "a gate is decided once");

    let decision = loop_side.take(session, "http").await.unwrap();
    assert_eq!(decision, Some((true, Some("ok".into()))));
}
