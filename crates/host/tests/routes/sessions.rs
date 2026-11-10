//! Sessions: sealing, appended events, verification, compliance, recorder
//! sessions, certificates and credentials.

use super::*;

#[tokio::test]
async fn fetching_a_session_by_id_is_not_limited_to_the_newest_page() {
    let pool = ectoledger::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let (old, _) = pool
        .create_session("old session", "test", "test", None)
        .await
        .unwrap();
    for _ in 0..500 {
        pool.create_session("newer session", "test", "test", None)
            .await
            .unwrap();
    }
    let base = spawn_server_with_pool(pool, Arc::new(|| Box::new(TestStubBackend))).await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{base}/sessions/{}", old.id))
        .bearer_auth(TEST_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["id"], old.id.to_string());
    assert_eq!(body["goal"], "old session");
    let missing = client
        .get(format!("{base}/sessions/{}", uuid::Uuid::new_v4()))
        .bearer_auth(TEST_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn seal_session_sets_status_completed() {
    let base = spawn_server().await;
    let id = create_session(&base).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/sessions/{id}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "seal: {}", resp.status());

    let session: serde_json::Value = client
        .get(format!("{base}/sessions/{id}"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["status"].as_str().unwrap_or(""), "completed");
}

/// The seal must survive the cognitive loop ending after it.
///
/// `POST /sessions` always spawns that loop and it outlives the request, so
/// whichever status it writes when it ends lands on top of anything sealed in
/// the meantime. Every terminal branch of the loop therefore has to go through
/// `finish_session_if_running`. Nothing below the HTTP layer can enforce that -
/// the SQL unit tests all pass with `sessions.rs` reverted - which is the whole
/// reason this test exists.
///
/// The loop cannot be waited on directly, and a fixed sleep is what made the
/// first version of this test pass against the bug: the backend fails in 150ms
/// but retries carry the loop to roughly 800ms, so a 600ms wait asserted before
/// the overwrite arrived. A second, unsealed session created just after the
/// subject is the wait condition instead. Its loop is the same work started
/// slightly later, so when it reaches a terminal status the subject's loop has
/// finished too - and if no loop ever terminates, this fails on the timeout
/// rather than passing on a race it did not run.
#[tokio::test]
async fn a_cognitive_loop_that_ends_after_the_seal_cannot_unseal_it() {
    let base = spawn_server_with(Arc::new(|| Box::new(SlowFailingBackend))).await;
    let sealed = create_session(&base).await;
    let control = create_session(&base).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/sessions/{sealed}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "seal: {}", resp.status());

    let mut control_status = String::from("running");
    for _ in 0..200 {
        // Check the subject every time round, not just at the end: this fails
        // on the first bad read, which names when the overwrite landed.
        let subject = status_of(&base, &sealed).await;
        assert_eq!(
            subject, "completed",
            "the cognitive loop overwrote the sealed status with {subject:?}"
        );
        control_status = status_of(&base, &control).await;
        if control_status != "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_ne!(
        control_status, "running",
        "no cognitive loop reached a terminal status within 10s, so this test \
         never exercised the overwrite it exists to catch"
    );

    // The control started after the subject, so the subject's loop has ended
    // by now. The grace covers the two loops contending on one SQLite pool.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let subject = status_of(&base, &sealed).await;
    assert_eq!(
        subject, "completed",
        "the cognitive loop overwrote the sealed status with {subject:?} \
         (control finished as {control_status:?})"
    );
}

#[tokio::test]
async fn seal_session_is_idempotent() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let client = reqwest::Client::new();

    let r1 = client
        .post(format!("{base}/sessions/{id}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(r1.status().is_success());

    let r2 = client
        .post(format!("{base}/sessions/{id}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(r2.status().is_success());
}

#[tokio::test]
async fn append_event_succeeds() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/sessions/{id}/events"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({
            "event_type": "test_event",
            "payload": { "key": "value" }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "append event: {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("id").is_some() || body.get("seq").is_some(),
        "response should contain id or seq: {body}"
    );
}

#[tokio::test]
async fn append_multiple_events_and_verify_chain() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let client = reqwest::Client::new();

    for i in 0..3 {
        let resp = client
            .post(format!("{base}/sessions/{id}/events"))
            .header(auth().0, auth().1)
            .json(&serde_json::json!({
                "event_type": "step",
                "payload": { "index": i }
            }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "append {i}: {}", resp.status());
    }

    let resp = client
        .get(format!("{base}/sessions/{id}/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "verify: {}", resp.status());
}

#[tokio::test]
async fn verify_chain_valid() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/sessions/{id}/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.unwrap();
    let valid = body["valid"]
        .as_bool()
        .or_else(|| body["ok"].as_bool())
        .or_else(|| body["verified"].as_bool());
    assert_eq!(valid, Some(true), "expected valid chain: {body}");
}

#[tokio::test]
async fn prove_compliance_returns_bundle() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/sessions/{id}/compliance"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "compliance: {}", resp.status());

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.is_object() || body.is_array(),
        "compliance should be JSON object/array: {body}"
    );
}

/// `ok` stays the chain alone for existing SDK callers; `signatures` carries
/// verify-session's verdict, which the desktop app shows beside it.
#[tokio::test]
async fn verify_reports_the_chain_and_the_signatures_separately() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/sessions/{id}/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .expect("GET /verify")
        .json()
        .await
        .expect("json");
    assert_eq!(body["ok"], serde_json::json!(true), "{body}");
    assert_eq!(body["signatures"]["verdict"], "verified", "{body}");
    assert_eq!(body["signatures"]["verified"], serde_json::json!(true));
    assert!(
        body["signatures"]["signed"].as_u64().unwrap() >= 1,
        "{body}"
    );
}

/// arXiv 2608.09867: a provider's encrypted reasoning, appended through the
/// SDK route as a raw response or inside an observation's text, is replaced by
/// its hash before it becomes permanent ledger content.
#[tokio::test]
async fn appended_encrypted_reasoning_is_stored_as_a_hash_only() {
    const BLOB: &str = "gAAAAABoSDKciphertext";
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let client = reqwest::Client::new();
    let raw_response = serde_json::json!({
        "output": [{ "type": "reasoning", "encrypted_content": BLOB }],
    });
    let bodies = [
        raw_response.clone(),
        serde_json::json!({ "type": "observation", "content": raw_response.to_string() }),
    ];
    for body in bodies {
        let r = client
            .post(format!("{base}/sessions/{id}/events"))
            .header(auth().0, auth().1)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), reqwest::StatusCode::CREATED);
    }
    let events = client
        .get(format!("{base}/events?session_id={id}"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!events.contains(BLOB), "blob stored: {events}");
    assert_eq!(
        events
            .matches("provider-encrypted reasoning, sha256:")
            .count(),
        2,
        "{events}"
    );
}

#[tokio::test]
async fn an_append_with_a_used_idempotency_key_is_refused() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let append = |key: &'static str| {
        let base = base.clone();
        let id = id.clone();
        async move {
            reqwest::Client::new()
                .post(format!("{base}/sessions/{id}/events"))
                .header(auth().0, auth().1)
                .header("Idempotency-Key", key)
                .json(&serde_json::json!({ "type": "observation", "content": "step" }))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(append("k1").await, reqwest::StatusCode::CREATED);
    assert_eq!(append("k1").await, reqwest::StatusCode::CONFLICT);
    assert_eq!(append("k2").await, reqwest::StatusCode::CREATED);
}

#[tokio::test]
async fn an_append_to_an_unknown_session_is_not_found() {
    let base = spawn_server().await;
    let status = reqwest::Client::new()
        .post(format!("{base}/sessions/{}/events", uuid::Uuid::new_v4()))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({ "type": "observation", "content": "orphan" }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}

/// An SDK recorder records a run it does not run: no LLM, no audit loop, and
/// the session stays open until sealed. Afterwards an append is refused, since
/// it would make the sealed session fail verification.
#[tokio::test]
async fn a_recorder_session_stays_open_until_sealed_then_refuses_appends() {
    let base = spawn_server_with(Arc::new(|| Box::new(SlowFailingBackend))).await;
    let id = create_recorder_session(&base).await;
    let client = reqwest::Client::new();
    let append = || {
        client
            .post(format!("{base}/sessions/{id}/events"))
            .header(auth().0, auth().1)
            .json(&serde_json::json!({ "type": "observation", "content": "tool ran" }))
            .send()
    };
    // Past the point where a loop session on this backend would have failed.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(status_of(&base, &id).await, "running");
    assert_eq!(
        append().await.unwrap().status(),
        reqwest::StatusCode::CREATED
    );

    let sealed = client
        .post(format!("{base}/sessions/{id}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(sealed.status().is_success());
    let refused = append().await.unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::CONFLICT);
    assert!(refused.text().await.unwrap().contains("\"record\": true"));

    let verify: serde_json::Value = client
        .get(format!("{base}/sessions/{id}/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verify["signatures"]["verdict"], "verified", "{verify}");
}

/// The server holds a recorder session's key, so its certificate is signed.
#[tokio::test]
async fn a_recorder_sessions_certificate_is_signed() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let cert: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/certificates/{id}"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        cert["signature"].as_str().is_some_and(|s| !s.is_empty()),
        "{cert}"
    );
}

/// A finished session's VC verifies under the key its `iss` names, which the
/// session authorised; the endpoint says so only when a signature was checked.
#[tokio::test]
async fn a_finished_sessions_vc_verifies_with_a_checked_signature() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    for _ in 0..50 {
        if status_of(&base, &id).await != "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let r = reqwest::Client::new()
        .get(format!("{base}/sessions/{id}/vc/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["valid"], true, "{body}");
    assert_eq!(body["signature_verified"], true, "{body}");
}
