//! Who may do what: roles, query tokens, redaction and approvals.

use super::*;

#[tokio::test]
async fn an_unrepresentable_token_expiry_is_rejected_without_breaking_the_server() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    for days in [u32::MAX, 4_000_000] {
        let response = client
            .post(format!("{base}/tokens"))
            .bearer_auth(TEST_TOKEN)
            .json(&serde_json::json!({"role":"agent", "expires_in_days": days}))
            .send()
            .await
            .expect("server should return a response, not panic");
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    let tokens: serde_json::Value = client
        .get(format!("{base}/tokens"))
        .bearer_auth(TEST_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        tokens.as_array().unwrap().len(),
        1,
        "invalid requests must not create tokens"
    );
    let valid = client
        .post(format!("{base}/tokens"))
        .bearer_auth(TEST_TOKEN)
        .json(&serde_json::json!({"role":"agent", "expires_in_days": 30}))
        .send()
        .await
        .unwrap();
    assert_eq!(valid.status(), reqwest::StatusCode::OK);
}

/// A decision answers a gate the loop is waiting on. The handler used to
/// accept one for any gate and write an unsigned ledger record of it: a
/// decision that decided nothing, indistinguishable from one forged in the
/// database. Now it is refused, and nothing is written; the loop writes the
/// signed record when it consumes a real decision.
#[tokio::test]
async fn an_approval_for_a_gate_nobody_asked_is_refused() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/approvals/{id}"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({ "gate_id": "never-asked", "approved": true }))
        .send()
        .await
        .expect("POST /approvals");
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(resp.text().await.unwrap().contains("never-asked"));
}

/// Chat appends `chat_message` events, so the read-only auditor role is
/// refused on both chat routes before anything is written.
#[tokio::test]
async fn an_auditor_cannot_chat() {
    let base = spawn_server().await;
    let auditor = token_with_role(&base, "auditor").await;
    let session = create_recorder_session(&base).await;
    for path in ["chat".to_string(), format!("sessions/{session}/chat")] {
        let r = reqwest::Client::new()
            .post(format!("{base}/{path}"))
            .bearer_auth(&auditor)
            .json(&serde_json::json!({ "message": "hello" }))
            .send()
            .await
            .expect("POST chat");
        assert_eq!(r.status(), reqwest::StatusCode::FORBIDDEN, "{path}");
    }
    let events: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/events?session_id={session}"))
        .header(auth().0, auth().1)
        .send()
        .await
        .expect("GET events")
        .json()
        .await
        .expect("json");
    let chats = events
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|e| e.to_string().contains("chat_message"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(chats, 0, "{events}");
}

/// A token in the URL ends up in logs and `Referer` headers, so `?token=` is
/// taken only where a browser cannot send a header: event streams and the
/// `/metrics` link.
#[tokio::test]
async fn a_query_token_is_accepted_only_on_streams_and_metrics() {
    let base = spawn_server().await;
    let root = base.trim_end_matches("/api");
    let session = create_recorder_session(&base).await;
    let status = |url: String| async move {
        reqwest::Client::new()
            .get(url)
            .send()
            .await
            .expect("GET")
            .status()
    };
    for url in [
        format!("{base}/sessions?token={TEST_TOKEN}"),
        format!("{base}/events?session_id={session}&token={TEST_TOKEN}"),
        format!("{base}/metrics?token={TEST_TOKEN}"),
    ] {
        assert_eq!(status(url.clone()).await, 401, "{url}");
    }
    for url in [
        format!("{base}/stream?token={TEST_TOKEN}"),
        format!("{base}/sessions/{session}/events/stream?token={TEST_TOKEN}"),
        format!("{root}/metrics?token={TEST_TOKEN}"),
    ] {
        assert_eq!(status(url.clone()).await, 200, "{url}");
    }
    let r = reqwest::Client::new()
        .get(format!("{base}/sessions"))
        .header(auth().0, auth().1)
        .send()
        .await
        .expect("GET");
    assert_eq!(r.status(), 200);
}

/// `/api/events` gives agent tokens the payload as the live stream shows it,
/// redacted; admin and auditor tokens review evidence and get it as recorded.
#[tokio::test]
async fn events_are_redacted_for_agent_tokens_only() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let secret = "password=hunter2 from 10.1.2.3";
    let r = reqwest::Client::new()
        .post(format!("{base}/sessions/{id}/events"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({ "event_type": "observation", "payload": { "note": secret } }))
        .send()
        .await
        .expect("append");
    assert!(r.status().is_success(), "{}", r.status());

    let events_as = |token: String| {
        let url = format!("{base}/events?session_id={id}");
        async move {
            reqwest::Client::new()
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .expect("GET events")
                .text()
                .await
                .expect("body")
        }
    };
    let agent = events_as(token_with_role(&base, "agent").await).await;
    assert!(!agent.contains("hunter2"), "{agent}");
    assert!(!agent.contains("10.1.2.3"), "{agent}");
    for token in [
        TEST_TOKEN.to_string(),
        token_with_role(&base, "auditor").await,
    ] {
        let seen = events_as(token).await;
        assert!(
            seen.contains("hunter2") && seen.contains("10.1.2.3"),
            "{seen}"
        );
    }
}
