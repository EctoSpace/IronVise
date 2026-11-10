//! `POST /api/chat/stream` and its session variant: the reply arrives as
//! server-sent events while it is generated, and the ledger records the
//! exchange once, complete.

mod qa_server_common;

use async_trait::async_trait;
use ectoledger::llm::{LlmBackend, LlmError, TextStream};
use ectoledger::schema::EventPayload;
use qa_server_common::{
    ADMIN_TOKEN, bearer, ensure_guard_disabled, fresh_pool, seed_token, wait_until_ready,
};
use std::sync::Arc;

/// Streams "Hel", "lo" - or, when `fail` is set, "Hel" and then an error.
struct Streaming {
    fail: bool,
}

#[async_trait]
impl LlmBackend for Streaming {
    async fn propose(
        &self,
        _: &str,
        _: &str,
    ) -> Result<ectoledger_core::intent::ProposedIntent, LlmError> {
        Err(LlmError::EmptyResponse)
    }

    async fn raw_call(&self, _: &str, _: &str) -> Result<String, LlmError> {
        Ok("Hello".into())
    }

    async fn stream_raw(&self, _: &str, _: &str) -> Result<TextStream, LlmError> {
        let second = if self.fail {
            Err(LlmError::Truncated)
        } else {
            Ok("lo".to_string())
        };
        Ok(Box::pin(futures_util::stream::iter(vec![
            Ok("Hel".to_string()),
            second,
        ])))
    }

    fn backend_name(&self) -> &str {
        "streaming-stub"
    }

    fn model_name(&self) -> &str {
        "stub-v1"
    }
}

async fn spawn(fail: bool) -> (String, ectoledger::pool::DatabasePool) {
    ensure_guard_disabled();
    let pool = fresh_pool().await;
    seed_token(&pool, ADMIN_TOKEN, "admin").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(ectoledger::start_server_with_llm(
        pool.clone(),
        Arc::new(ectoledger::metrics::Metrics::default()),
        listener,
        Arc::new(move || Box::new(Streaming { fail })),
    ));
    wait_until_ready(&base).await;
    (base, pool)
}

/// The `(event, data)` pairs of an SSE body.
fn events(body: &str) -> Vec<(String, serde_json::Value)> {
    body.split("\n\n")
        .filter_map(|block| {
            let mut name = None;
            let mut data = None;
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("event:") {
                    name = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("data:") {
                    data = serde_json::from_str(v.trim()).ok();
                }
            }
            Some((name?, data?))
        })
        .collect()
}

async fn chat_messages(pool: &ectoledger::pool::DatabasePool) -> Vec<(String, String)> {
    pool.get_events_range(0, 1_000)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|e| match e.payload {
            EventPayload::ChatMessage { role, content, .. } => Some((role, content)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn the_reply_streams_and_is_recorded_whole() {
    let (base, pool) = spawn(false).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/chat/stream"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "message": "say hello" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let got = events(&resp.text().await.unwrap());
    let names: Vec<_> = got.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["delta", "delta", "done"]);
    assert_eq!(got[0].1["text"], "Hel");
    assert_eq!(got[1].1["text"], "lo");
    assert_eq!(got[2].1["reply"], "Hello");
    assert_eq!(got[2].1["backend"], "streaming-stub");
    assert_eq!(got[2].1["model"], "stub-v1");

    assert_eq!(
        chat_messages(&pool).await,
        [
            ("user".to_string(), "say hello".to_string()),
            ("assistant".to_string(), "Hello".to_string())
        ]
    );
}

#[tokio::test]
async fn a_failure_mid_stream_ends_with_an_error_event_and_no_reply_recorded() {
    let (base, pool) = spawn(true).await;
    let body = reqwest::Client::new()
        .post(format!("{base}/api/chat/stream"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "message": "say hello" }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let got = events(&body);
    let names: Vec<_> = got.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["delta", "error"]);
    assert!(got[1].1["message"].as_str().unwrap().contains("cut off"));
    assert_eq!(
        chat_messages(&pool).await,
        [("user".to_string(), "say hello".to_string())]
    );
}

#[tokio::test]
async fn the_session_stream_records_into_the_session() {
    let (base, pool) = spawn(false).await;
    let client = reqwest::Client::new();
    let session = qa_server_common::create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let body = client
        .post(format!("{base}/api/sessions/{session}/chat/stream"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "message": "hi" }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(events(&body).last().unwrap().0, "done");
    let session: uuid::Uuid = session.parse().unwrap();
    let in_session: Vec<_> = pool
        .get_events_by_session(session)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| matches!(e.payload, EventPayload::ChatMessage { .. }))
        .collect();
    assert_eq!(in_session.len(), 2);
}

#[tokio::test]
async fn an_empty_message_and_the_auditor_are_refused_before_streaming() {
    let (base, _pool) = spawn(false).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/chat/stream"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "message": " " }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let auditor = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "auditor").await;
    let resp = client
        .post(format!("{base}/api/chat/stream"))
        .header("Authorization", bearer(&auditor))
        .json(&serde_json::json!({ "message": "hi" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
