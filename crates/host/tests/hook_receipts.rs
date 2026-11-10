//! The real `ironvise hook` binary after a tool ran (`PostToolUse`): the
//! receipt is built in the hook, so what reaches the Observer is hashes, never
//! what the tool returned, however large that was. The Observer here is a
//! stand-in that keeps every request body it is sent.

use std::process::Stdio;
use std::sync::{Arc, Mutex};

use axum::{Router, http::StatusCode, routing::post};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// A stand-in Observer answering `status`, and the bodies it was sent.
async fn observer(status: StatusCode) -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().route(
        "/api/hook/tool-result",
        post({
            let seen = seen.clone();
            move |body: String| async move {
                seen.lock().unwrap().push(body);
                (status, "{}")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, seen)
}

/// Run the hook on `input` against `url`; its exit code and stderr.
async fn hook(url: &str, input: &Value) -> (i32, String) {
    hook_with_token(url, input, "t").await
}

async fn hook_with_token(url: &str, input: &Value, token: &str) -> (i32, String) {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ironvise"))
        .arg("hook")
        .env("ECTOLEDGER_URL", url)
        .env("ECTOLEDGER_TOKEN", token)
        .env_remove("CLAUDE_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ectoledger hook");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.to_string().as_bytes()).await.unwrap();
    drop(stdin);
    let out = child.wait_with_output().await.unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Claude Code's `PostToolUse` payload for a `Read` of `content`.
fn read_result(content: &str) -> Value {
    json!({
        "hook_event_name": "PostToolUse",
        "session_id": "s1",
        "tool_use_id": "toolu_1",
        "tool_name": "Read",
        "tool_input": { "file_path": "/p/config.ini" },
        "tool_response": { "type": "text",
                           "file": { "filePath": "/p/config.ini", "content": content } },
    })
}

fn sha256(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

#[tokio::test]
async fn only_hashes_leave_the_hook() {
    let (url, seen) = observer(StatusCode::OK).await;
    let content = "db_password=example\n";
    let (code, stderr) = hook(&url, &read_result(content)).await;
    assert_eq!(code, 0, "{stderr}");

    let bodies = seen.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    assert!(!bodies[0].contains("db_password"), "{}", bodies[0]);
    let sent: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(sent["receipt"]["type"], "data_receipt");
    assert_eq!(sent["receipt"]["text_sha256"], json!([sha256(content)]));
    assert_eq!(sent["receipt"]["source"], "/p/config.ini");
    assert_eq!(sent["tool_use_id"], "toolu_1");
}

/// A result far over the Observer's 1 MiB body limit still gets its receipt,
/// and the request that carries it stays a few hundred bytes.
#[tokio::test]
async fn a_large_result_costs_a_small_receipt() {
    let (url, seen) = observer(StatusCode::OK).await;
    let content = "x".repeat(4 * 1024 * 1024);
    let (code, stderr) = hook(&url, &read_result(&content)).await;
    assert_eq!(code, 0, "{stderr}");
    let bodies = seen.lock().unwrap().clone();
    assert!(bodies[0].len() < 1024, "{} bytes sent", bodies[0].len());
    let sent: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(sent["receipt"]["text_sha256"], json!([sha256(&content)]));
    assert_eq!(sent["receipt"]["text_bytes"], content.len());
}

/// The tool has run, so nothing can be blocked: a receipt the Observer did not
/// take is exit 1, which Claude Code shows the user, not exit 2.
#[tokio::test]
async fn a_receipt_that_was_not_recorded_is_reported() {
    let (url, _) = observer(StatusCode::INTERNAL_SERVER_ERROR).await;
    let (code, stderr) = hook(&url, &read_result("a")).await;
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("was NOT recorded"), "{stderr}");

    let (code, stderr) = hook("http://127.0.0.1:9", &read_result("a")).await;
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("was NOT recorded"), "{stderr}");
}

/// Without a token the receipt cannot be recorded; that is reported the same
/// way, since the tool has already run.
#[tokio::test]
async fn a_receipt_without_a_token_is_reported_not_blocked() {
    let (url, seen) = observer(StatusCode::OK).await;
    let (code, stderr) = hook_with_token(&url, &read_result("a"), "").await;
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("was NOT recorded"), "{stderr}");
    assert!(seen.lock().unwrap().is_empty());
}
