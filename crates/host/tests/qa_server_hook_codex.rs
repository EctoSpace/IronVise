//! Codex's tool calls through the hook route: `apply_patch` is checked file by
//! file against the project the session started in.

mod qa_server_common;

use qa_server_common::{ADMIN_TOKEN, bearer, spawn_server};

async fn codex_call(
    base: &str,
    session: &str,
    cwd: &std::path::Path,
    patch: &str,
) -> serde_json::Value {
    reqwest::Client::new()
        .post(format!("{base}/api/hook/tool-call"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({
            "session_id": session,
            "turn_id": "turn-1",
            "agent": "codex",
            "tool_name": "apply_patch",
            "tool_input": { "command": patch },
            "cwd": cwd,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn patch(files: &[&str]) -> String {
    let mut text = String::from("*** Begin Patch\n");
    for file in files {
        text.push_str(&format!("*** Update File: {file}\n@@\n-old\n+new\n"));
    }
    text + "*** End Patch\n"
}

#[tokio::test]
async fn a_patch_inside_the_project_is_allowed() {
    let base = spawn_server().await;
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().canonicalize().unwrap();
    let r = codex_call(
        &base,
        "codex-in",
        &dir,
        &patch(&["src/lib.rs", "README.md"]),
    )
    .await;
    assert_eq!(r["decision"], "allow", "{r}");
}

#[tokio::test]
async fn the_ledger_session_is_named_after_codex() {
    let base = spawn_server().await;
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().canonicalize().unwrap();
    let r = codex_call(&base, "codex-named", &dir, &patch(&["src/lib.rs"])).await;
    let id = r["ledger_session_id"]
        .as_str()
        .expect("a ledger session")
        .to_string();
    let sessions: Vec<serde_json::Value> = reqwest::Client::new()
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
        .find(|s| s["id"] == id.as_str())
        .expect("the session is listed");
    assert_eq!(session["llm_backend"], "codex", "{session}");
    assert!(
        session["goal"]
            .as_str()
            .unwrap()
            .starts_with("Codex session in "),
        "{session}"
    );
}

#[tokio::test]
async fn one_file_outside_the_project_denies_the_whole_patch_and_is_named() {
    let base = spawn_server().await;
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let escaped = outside.path().canonicalize().unwrap().join("x.rs");
    let r = codex_call(
        &base,
        "codex-out",
        &dir,
        &patch(&["src/lib.rs", escaped.to_str().unwrap()]),
    )
    .await;
    assert_eq!(r["decision"], "deny", "{r}");
    assert!(
        r["reason"]
            .as_str()
            .unwrap()
            .contains(escaped.to_str().unwrap()),
        "the refused file is named: {r}"
    );
}

#[tokio::test]
async fn a_move_target_is_checked_too() {
    let base = spawn_server().await;
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().canonicalize().unwrap().join("moved.rs");
    let text = format!(
        "*** Begin Patch\n*** Update File: a.rs\n*** Move to: {}\n@@\n-x\n+y\n*** End Patch\n",
        target.display()
    );
    let r = codex_call(&base, "codex-move", &dir, &text).await;
    assert_eq!(r["decision"], "deny", "{r}");
}

#[tokio::test]
async fn a_patch_that_names_no_file_is_escalated() {
    let base = spawn_server().await;
    let project = tempfile::tempdir().unwrap();
    let r = codex_call(&base, "codex-empty", project.path(), "not a patch").await;
    assert_eq!(r["decision"], "ask", "{r}");
    // The escalation is in the ledger as an approval gate, not a gap.
    assert_eq!(r["recorded"], true, "{r}");
}
