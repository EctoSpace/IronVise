//! With `GUARD_REQUIRED`, the Claude Code hook and the SDK's verify-intent are
//! judged by the real `guard-worker`, which the server starts once and shares.
//! The guard's model is a stand-in that refuses anything mentioning
//! `secret-plan`, so an allow and a guard denial can both be seen, recorded,
//! and reported in `coverage`.

use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const TOKEN: &str = "hook-guard-token";

async fn guard_model() -> String {
    let app = Router::new().route(
        "/api/chat",
        post(|Json(req): Json<Value>| async move {
            let asked = req["messages"].to_string();
            let answer = if asked.contains("secret-plan") {
                "DENY: reads the secret plan, which the goal does not need"
            } else {
                "ALLOW"
            };
            Json(json!({ "message": { "role": "assistant", "content": answer }, "done": true }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

async fn server() -> String {
    let pool = ectoledger::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let hash = hex::encode(Sha256::digest(TOKEN.as_bytes()));
    pool.insert_token(&hash, "admin", Some("test"), None)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/api");
    let metrics = Arc::new(ectoledger::metrics::Metrics::default());
    tokio::spawn(async move {
        ectoledger::start_server_with_llm(pool, metrics, listener, Arc::new(|| unreachable!()))
            .await
            .unwrap()
    });
    wait_for_server(addr).await;
    base
}

async fn wait_for_server(addr: std::net::SocketAddr) {
    for _ in 0..500 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server at {addr} did not become ready");
}

async fn call(base: &str, path: &str, body: Value) -> Value {
    reqwest::Client::new()
        .post(format!("{base}/{path}"))
        .bearer_auth(TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_hook_and_verify_intent_are_judged_by_the_shared_guard() {
    let model = guard_model().await;
    // SAFETY: the only test in this binary, before the server starts.
    unsafe {
        std::env::set_var("GUARD_REQUIRED", "true");
        std::env::set_var("GUARD_LLM_BACKEND", "ollama");
        std::env::set_var("GUARD_LLM_MODEL", "mock");
        std::env::set_var("OLLAMA_BASE_URL", &model);
        std::env::set_var("ECTO_GUARD_WORKER", env!("CARGO_BIN_EXE_guard-worker"));
    }
    let base = server().await;
    let hook = |command: &str, id: &str| {
        json!({ "session_id": "guarded", "tool_name": "Bash", "tool_use_id": id,
                "tool_input": { "command": command } })
    };

    let allowed = call(&base, "hook/tool-call", hook("ls", "toolu_1")).await;
    assert_eq!(allowed["decision"], "allow", "{allowed}");
    assert!(
        allowed["coverage"]["evaluated"]
            .as_array()
            .unwrap()
            .contains(&json!("guard")),
        "{allowed}"
    );

    let denied = call(
        &base,
        "hook/tool-call",
        hook("cat secret-plan.txt", "toolu_2"),
    )
    .await;
    assert_eq!(denied["decision"], "deny", "{denied}");
    assert_eq!(denied["stage"], "guard", "{denied}");
    assert!(
        denied["reason"].as_str().unwrap().contains("secret plan"),
        "{denied}"
    );

    // The denial is in the ledger as the guard's, and the session verifies.
    let ledger_id = denied["ledger_session_id"].as_str().unwrap();
    let events: Value = reqwest::Client::new()
        .get(format!("{base}/events?session_id={ledger_id}"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(events.to_string().contains("guard_denial"), "{events}");

    // verify-intent uses the same worker.
    let session = call(
        &base,
        "sessions",
        json!({ "goal": "list files", "record": true }),
    )
    .await;
    let sid = session["id"].as_str().unwrap();
    let verdict = call(
        &base,
        &format!("sessions/{sid}/verify-intent"),
        json!({ "action": "run_command", "params": { "command": "cat secret-plan.txt" },
                "justification": "checking the guard sees this" }),
    )
    .await;
    assert_eq!(verdict["decision"], "deny", "{verdict}");
    assert_eq!(verdict["stage"], "guard", "{verdict}");
}
