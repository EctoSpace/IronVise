//! Antigravity CLI's hook, end to end: its own payload into the real
//! `ironvise hook` binary, the Observer's decision back out in Antigravity's
//! shape, and a failure that refuses the call under either reading of its
//! undocumented exit-code contract.

mod qa_server_common;

use std::process::Stdio;

use qa_server_common::{ADMIN_TOKEN, bearer, spawn_server};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

/// Antigravity's `PreToolUse` payload for one tool call in `workspace`.
fn call(conversation: &str, workspace: &std::path::Path, tool: &str, args: Value) -> Value {
    json!({
        "toolCall": { "name": tool, "args": args },
        "stepIdx": 0,
        "conversationId": conversation,
        "workspacePaths": [workspace],
        "transcriptPath": "/tmp/transcript.jsonl",
        "artifactDirectoryPath": "/tmp/artifacts",
        "modelName": "gemini-3.8-flash",
    })
}

/// Run the hook binary; its exit code and stdout parsed as JSON.
async fn hook(url: &str, input: &Value) -> (i32, Value) {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ironvise"))
        .arg("hook")
        .env("ECTOLEDGER_URL", url)
        .env("ECTOLEDGER_TOKEN", ADMIN_TOKEN)
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("ECTOLEDGER_HOOK_MODE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ectoledger hook");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.to_string().as_bytes()).await.unwrap();
    drop(stdin);
    let out = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let decision = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is one JSON decision ({e}): {stdout:?}"));
    (out.status.code().unwrap_or(-1), decision)
}

fn workspace() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

#[tokio::test]
async fn a_banned_command_is_denied_in_antigravitys_terms() {
    let base = spawn_server().await;
    let (_dir, ws) = workspace();
    let input = call(
        "ag-deny",
        &ws,
        "run_command",
        json!({ "CommandLine": "sudo id" }),
    );
    let (code, out) = hook(&base, &input).await;
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["decision"], "deny", "{out}");
    assert!(
        out["reason"].as_str().unwrap().contains("banned command"),
        "{out}"
    );
}

#[tokio::test]
async fn a_read_inside_the_workspace_is_allowed_and_the_session_is_labelled() {
    let base = spawn_server().await;
    let (_dir, ws) = workspace();
    let file = ws.join("notes.md");
    let input = call(
        "ag-allow",
        &ws,
        "view_file",
        json!({ "AbsolutePath": file }),
    );
    let (code, out) = hook(&base, &input).await;
    assert_eq!(code, 0, "{out}");
    assert_eq!(out, json!({ "decision": "allow" }));

    let sessions: Vec<Value> = reqwest::Client::new()
        .get(format!("{base}/api/sessions"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session = sessions
        .iter()
        .find(|s| s["llm_backend"] == "antigravity")
        .expect("an antigravity session");
    assert!(
        session["goal"]
            .as_str()
            .unwrap()
            .starts_with("Antigravity session in "),
        "{session}"
    );
}

#[tokio::test]
async fn a_write_outside_the_workspace_is_denied() {
    let base = spawn_server().await;
    let (_dir, ws) = workspace();
    let (_other, outside) = workspace();
    let target = outside.join("x.rs");
    let input = call(
        "ag-out",
        &ws,
        "write_to_file",
        json!({ "TargetFile": target, "CodeContent": "fn main() {}" }),
    );
    let (_, out) = hook(&base, &input).await;
    assert_eq!(out["decision"], "deny", "{out}");
}

#[tokio::test]
async fn its_own_hook_file_cannot_be_written() {
    let base = spawn_server().await;
    let (_dir, ws) = workspace();
    let target = ws.join(".agents/hooks.json");
    let input = call(
        "ag-self",
        &ws,
        "write_to_file",
        json!({ "TargetFile": target }),
    );
    let (_, out) = hook(&base, &input).await;
    assert_eq!(out["decision"], "deny", "{out}");
}

#[tokio::test]
async fn an_unreachable_observer_denies_on_stdout_and_exits_two() {
    let (_dir, ws) = workspace();
    let input = call(
        "ag-down",
        &ws,
        "run_command",
        json!({ "CommandLine": "ls" }),
    );
    let (code, out) = hook("http://127.0.0.1:9", &input).await;
    assert_eq!(code, 2);
    assert_eq!(out["decision"], "deny", "{out}");
    assert!(
        out["reason"].as_str().unwrap().contains("could not reach"),
        "{out}"
    );
}
