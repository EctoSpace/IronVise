mod qa_server_common;

use qa_server_common::{ADMIN_TOKEN, bearer, create_recorder_session, spawn_server};

#[tokio::test]
async fn appending_a_server_only_event_kind_is_rejected() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    for kind in ["action", "genesis", "guard_denial", "tripwire_rejection"] {
        let resp = client
            .post(format!("{base}/api/sessions/{session_id}/events"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .json(&serde_json::json!({ "type": kind, "reason": "x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "kind {kind}"
        );
    }
}

#[tokio::test]
async fn appending_a_client_assertable_event_kind_succeeds() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let resp = client
        .post(format!("{base}/api/sessions/{session_id}/events"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "type": "observation", "content": "qa note" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
}

#[tokio::test]
async fn an_untagged_body_is_wrapped_as_an_observation() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let resp = client
        .post(format!("{base}/api/sessions/{session_id}/events"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "anything": "goes here" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
}

#[tokio::test]
async fn repeating_an_idempotency_key_is_a_conflict() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let body = serde_json::json!({ "type": "observation", "content": "once" });

    let first = client
        .post(format!("{base}/api/sessions/{session_id}/events"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .header("Idempotency-Key", "qa-key-1")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), reqwest::StatusCode::CREATED);

    let second = client
        .post(format!("{base}/api/sessions/{session_id}/events"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .header("Idempotency-Key", "qa-key-1")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn appending_to_a_sealed_session_is_a_conflict() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;

    let seal_resp = client
        .post(format!("{base}/api/sessions/{session_id}/seal"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(seal_resp.status(), reqwest::StatusCode::OK);

    let append_resp = client
        .post(format!("{base}/api/sessions/{session_id}/events"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "type": "observation", "content": "too late" }))
        .send()
        .await
        .unwrap();
    assert_eq!(append_resp.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn auditor_cannot_append_events_or_seal() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let auditor = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "auditor").await;

    let append_resp = client
        .post(format!("{base}/api/sessions/{session_id}/events"))
        .header("Authorization", bearer(&auditor))
        .json(&serde_json::json!({ "type": "observation", "content": "x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(append_resp.status(), reqwest::StatusCode::FORBIDDEN);

    let seal_resp = client
        .post(format!("{base}/api/sessions/{session_id}/seal"))
        .header("Authorization", bearer(&auditor))
        .send()
        .await
        .unwrap();
    assert_eq!(seal_resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn verify_intent_is_readable_by_auditors_and_writes_nothing() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let auditor = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "auditor").await;

    let before = events_count(&client, &base, &session_id).await;
    let resp = client
        .post(format!("{base}/api/sessions/{session_id}/verify-intent"))
        .header("Authorization", bearer(&auditor))
        .json(&serde_json::json!({
            "action": "read_file",
            "params": { "path": "/tmp/x" },
            "justification": "qa check",
            "reasoning": "qa",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let after = events_count(&client, &base, &session_id).await;
    assert_eq!(before, after, "verify-intent must not write events");
}

async fn events_count(client: &reqwest::Client, base: &str, session_id: &str) -> usize {
    let resp = client
        .get(format!("{base}/api/events?session_id={session_id}"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    body.as_array().unwrap().len()
}

#[tokio::test]
async fn verify_intent_for_a_nonexistent_session_is_404() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!(
            "{base}/api/sessions/{}/verify-intent",
            uuid::Uuid::new_v4()
        ))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({
            "action": "read_file", "params": {}, "justification": "x", "reasoning": "x",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn verify_intent_for_a_sealed_session_is_a_conflict() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    client
        .post(format!("{base}/api/sessions/{session_id}/seal"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    let resp = client
        .post(format!("{base}/api/sessions/{session_id}/verify-intent"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({
            "action": "read_file", "params": {}, "justification": "x", "reasoning": "x",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn chat_rejects_empty_message() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/chat"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "message": "   " }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auditor_cannot_chat() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let auditor = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "auditor").await;
    let resp = client
        .post(format!("{base}/api/chat"))
        .header("Authorization", bearer(&auditor))
        .json(&serde_json::json!({ "message": "hi" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_chat_rejects_empty_message() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let resp = client
        .post(format!("{base}/api/sessions/{session_id}/chat"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "message": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn metrics_json_is_readable_by_any_role() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let auditor = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "auditor").await;
    let resp = client
        .get(format!("{base}/api/metrics"))
        .header("Authorization", bearer(&auditor))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn security_metrics_is_readable_by_any_role() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let agent = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "agent").await;
    let resp = client
        .get(format!("{base}/api/metrics/security"))
        .header("Authorization", bearer(&agent))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn prometheus_metrics_requires_admin_even_via_query_token() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let agent = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "agent").await;

    let header_resp = client
        .get(format!("{base}/metrics"))
        .header("Authorization", bearer(&agent))
        .send()
        .await
        .unwrap();
    assert_eq!(header_resp.status(), reqwest::StatusCode::FORBIDDEN);

    let query_resp = client
        .get(format!("{base}/metrics?token={agent}"))
        .send()
        .await
        .unwrap();
    assert_eq!(query_resp.status(), reqwest::StatusCode::FORBIDDEN);

    let admin_resp = client
        .get(format!("{base}/metrics"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(admin_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        admin_resp.headers().get("content-type").unwrap(),
        "text/plain; charset=utf-8"
    );
}

#[tokio::test]
async fn metrics_html_negotiation_via_accept_header() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/metrics"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
}

#[tokio::test]
async fn sse_stream_responds_with_event_stream_content_type() {
    let base = spawn_server().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client
        .get(format!("{base}/api/stream"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
}

#[tokio::test]
async fn session_scoped_sse_stream_accepts_a_query_token() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let streaming_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = streaming_client
        .get(format!(
            "{base}/api/sessions/{session_id}/events/stream?token={ADMIN_TOKEN}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}
