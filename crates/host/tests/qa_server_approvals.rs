mod qa_server_common;

use qa_server_common::{bearer, spawn_server_with_approvals};
use uuid::Uuid;

fn pending(gate_id: &str) -> ectoledger::approvals::PendingApproval {
    ectoledger::approvals::PendingApproval {
        gate_id: gate_id.to_string(),
        action_name: "run_command".to_string(),
        action_params_summary: "rm -rf /tmp/qa".to_string(),
        created_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn get_pending_is_null_when_nothing_is_waiting() {
    let harness = spawn_server_with_approvals().await;
    let resp = reqwest::Client::new()
        .get(format!(
            "{}/api/approvals/{}/pending",
            harness.base,
            Uuid::new_v4()
        ))
        .header("Authorization", bearer(qa_server_common::ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["pending"].is_null());
}

#[tokio::test]
async fn non_admin_cannot_decide_an_approval() {
    let harness = spawn_server_with_approvals().await;
    let session_id = Uuid::new_v4();
    harness
        .approval_state
        .set_pending(session_id, pending("gate-1"));
    let resp = reqwest::Client::new()
        .post(format!("{}/api/approvals/{session_id}", harness.base))
        .header("Authorization", bearer("qa-agent-token"))
        .json(&serde_json::json!({ "gate_id": "gate-1", "approved": true, "reason": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn deciding_an_unknown_gate_id_is_a_conflict() {
    let harness = spawn_server_with_approvals().await;
    let session_id = Uuid::new_v4();
    harness
        .approval_state
        .set_pending(session_id, pending("gate-1"));
    let resp = reqwest::Client::new()
        .post(format!("{}/api/approvals/{session_id}", harness.base))
        .header("Authorization", bearer(qa_server_common::ADMIN_TOKEN))
        .json(&serde_json::json!({ "gate_id": "wrong-gate", "approved": true, "reason": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn deciding_for_an_unknown_session_is_a_conflict() {
    let harness = spawn_server_with_approvals().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/approvals/{}", harness.base, Uuid::new_v4()))
        .header("Authorization", bearer(qa_server_common::ADMIN_TOKEN))
        .json(&serde_json::json!({ "gate_id": "gate-1", "approved": true, "reason": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn double_deciding_the_same_gate_is_rejected_the_second_time() {
    let harness = spawn_server_with_approvals().await;
    let session_id = Uuid::new_v4();
    harness
        .approval_state
        .set_pending(session_id, pending("gate-1"));
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "gate_id": "gate-1", "approved": true, "reason": null });

    let first = client
        .post(format!("{}/api/approvals/{session_id}", harness.base))
        .header("Authorization", bearer(qa_server_common::ADMIN_TOKEN))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), reqwest::StatusCode::OK);

    let second = client
        .post(format!("{}/api/approvals/{session_id}", harness.base))
        .header("Authorization", bearer(qa_server_common::ADMIN_TOKEN))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_approve_and_deny_settle_exactly_one_winner() {
    for i in 0..25 {
        let harness = spawn_server_with_approvals().await;
        let session_id = Uuid::new_v4();
        let gate_id = format!("gate-{i}");
        harness
            .approval_state
            .set_pending(session_id, pending(&gate_id));
        let client = reqwest::Client::new();
        let approve = client
            .post(format!("{}/api/approvals/{session_id}", harness.base))
            .header("Authorization", bearer(qa_server_common::ADMIN_TOKEN))
            .json(&serde_json::json!({ "gate_id": gate_id, "approved": true, "reason": null }));
        let deny = client
            .post(format!("{}/api/approvals/{session_id}", harness.base))
            .header("Authorization", bearer(qa_server_common::ADMIN_TOKEN))
            .json(&serde_json::json!({ "gate_id": gate_id, "approved": false, "reason": null }));
        let (approve_resp, deny_resp) = tokio::join!(approve.send(), deny.send());
        let statuses = [approve_resp.unwrap().status(), deny_resp.unwrap().status()];
        let ok_count = statuses
            .iter()
            .filter(|s| **s == reqwest::StatusCode::OK)
            .count();
        let conflict_count = statuses
            .iter()
            .filter(|s| **s == reqwest::StatusCode::CONFLICT)
            .count();
        assert_eq!(
            ok_count, 1,
            "iteration {i}: expected exactly one winner, got {statuses:?}"
        );
        assert_eq!(conflict_count, 1, "iteration {i}: got {statuses:?}");
    }
}
