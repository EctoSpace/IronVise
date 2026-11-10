//! The real `ironvise audit` binary on Linux with the default `sandbox`
//! feature: its own seccomp filter must leave room for everything an audit
//! does. SQLite commits, the key file, the guard worker and a sandboxed
//! `run_command` each failed under the filter before, and no unit test runs
//! the binary with the filter installed.
#![cfg(all(target_os = "linux", feature = "sandbox"))]

use axum::{Json, Router, routing::get, routing::post};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// An Ollama stand-in: proposals come from `turns`, the guard's raw calls
/// (no `format: json`) are answered ALLOW.
async fn mock_ollama(turns: Vec<Value>) -> String {
    let turns = Arc::new(Mutex::new(VecDeque::from(turns)));
    let app = Router::new()
        .route("/api/tags", get(|| async { Json(json!({ "models": [{ "name": "mock" }] })) }))
        .route(
            "/api/chat",
            post(move |Json(req): Json<Value>| {
                let turns = turns.clone();
                async move {
                    let content = if req["format"] != "json" {
                        "ALLOW".to_string()
                    } else {
                        let next = turns.lock().unwrap().pop_front();
                        next.unwrap_or_else(|| {
                            json!({ "action": "complete", "params": { "findings": [] },
                                    "justification": "Nothing further to do.", "reasoning": "Done." })
                        })
                        .to_string()
                    };
                    Json(json!({ "message": { "role": "assistant", "content": content }, "done": true }))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

#[tokio::test]
async fn an_audit_with_guard_and_run_command_completes_under_the_filter() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("config.ini"), "db_password=example\n").unwrap();
    let ollama = mock_ollama(vec![
        json!({ "action": "run_command", "params": { "command": "ls -la" },
                "justification": "List the project files.", "reasoning": "First step." }),
        json!({ "action": "complete", "params": { "findings": [] },
                "justification": "Listed the files.", "reasoning": "Done." }),
    ])
    .await;
    let db = dir.path().join("ledger.db");

    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_ironvise"))
        .args(["audit", "List the project files"])
        .current_dir(&project)
        .env("DATABASE_URL", format!("sqlite:{}", db.display()))
        .env("LLM_PROVIDER", "ollama")
        .env("OLLAMA_BASE_URL", &ollama)
        .env("OLLAMA_MODEL", "mock")
        .env("GUARD_REQUIRED", "true")
        .env("GUARD_LLM_BACKEND", "ollama")
        .env("GUARD_LLM_MODEL", "mock")
        .env("ECTO_KEY_PASSWORD", "a-password-long-enough")
        // A free port, not the default 3000, which a running server or app
        // may hold.
        .env("ECTO_BIND_PORT", free_port().to_string())
        .env_remove("ECTO_DATA_DIR")
        .env_remove("RUST_LOG")
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .expect("run ectoledger audit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "audit failed: {stderr}");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=ro", db.display()))
        .await
        .unwrap();
    let payloads: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM agent_events ORDER BY sequence")
            .fetch_all(&pool)
            .await
            .unwrap();
    let all = payloads.join("\n");
    assert!(!all.contains("guard_denial"), "the guard failed: {all}");
    assert!(all.contains(r#""name":"run_command""#), "{all}");
    assert!(
        all.contains("exit_code: Some(0)") && all.contains("config.ini"),
        "{all}"
    );
    assert!(all.contains("Audit complete"), "{all}");

    // The id `verify-session` and `report` need is on stdout, whatever
    // RUST_LOG says: before, nothing a new user saw named the session.
    let session_id: String = sqlx::query_scalar("SELECT id FROM agent_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("Session {session_id} started.")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("ironvise verify-session {session_id}")),
        "{stdout}"
    );

    let keys: Vec<_> = std::fs::read_dir(project.join(".ectoledger/keys"))
        .expect("key dir")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(keys.len(), 1, "{keys:?}");
    let meta = std::fs::metadata(&keys[0]).unwrap();
    assert!(meta.len() > 0, "the key file is empty");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

/// A port nothing is listening on right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free local port")
}
