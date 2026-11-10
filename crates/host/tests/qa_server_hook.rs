mod qa_server_common;

use qa_server_common::{ADMIN_TOKEN, bearer, spawn_server};
use uuid::Uuid;

async fn tool_call(
    client: &reqwest::Client,
    base: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    client
        .post(format!("{base}/api/hook/tool-call"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn missing_tool_name_field_is_a_client_error() {
    let base = spawn_server().await;
    let resp = tool_call(
        &reqwest::Client::new(),
        &base,
        serde_json::json!({ "session_id": Uuid::new_v4().to_string(), "tool_input": {} }),
    )
    .await;
    assert!(resp.status().is_client_error(), "got {}", resp.status());
}

#[tokio::test]
async fn empty_tool_name_is_escalated_not_crashed() {
    let base = spawn_server().await;
    let resp = tool_call(
        &reqwest::Client::new(),
        &base,
        serde_json::json!({ "session_id": Uuid::new_v4().to_string(), "tool_name": "", "tool_input": {} }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "ask");
}

#[tokio::test]
async fn missing_tool_input_defaults_to_null_and_is_escalated() {
    let base = spawn_server().await;
    let resp = tool_call(
        &reqwest::Client::new(),
        &base,
        serde_json::json!({ "session_id": Uuid::new_v4().to_string(), "tool_name": "Bash" }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "ask");
}

#[tokio::test]
async fn non_object_tool_input_is_escalated_not_crashed() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    for bad_input in [
        serde_json::json!("just a string"),
        serde_json::json!(42),
        serde_json::json!(["array", "not", "object"]),
        serde_json::json!(null),
    ] {
        let resp = tool_call(
            &client,
            &base,
            serde_json::json!({
                "session_id": Uuid::new_v4().to_string(),
                "tool_name": "Bash",
                "tool_input": bad_input,
            }),
        )
        .await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "input {bad_input:?}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["decision"], "ask", "input {bad_input:?}");
    }
}

#[tokio::test]
async fn unicode_paths_and_commands_round_trip_without_crashing() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = tool_call(
        &client,
        &base,
        serde_json::json!({
            "session_id": Uuid::new_v4().to_string(),
            "tool_name": "Read",
            "tool_input": { "file_path": "/проект/文件/🔒.txt" },
        }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["ledger_session_id"].is_string());
}

#[tokio::test]
async fn auditor_role_cannot_submit_tool_calls() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let auditor = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "auditor").await;
    let resp = client
        .post(format!("{base}/api/hook/tool-call"))
        .header("Authorization", bearer(&auditor))
        .json(&serde_json::json!({
            "session_id": Uuid::new_v4().to_string(),
            "tool_name": "Bash",
            "tool_input": { "command": "ls" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_different_token_reusing_a_session_id_is_forbidden() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = Uuid::new_v4().to_string();
    let agent = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "agent").await;

    let first = tool_call(
        &client,
        &base,
        serde_json::json!({ "session_id": session_id, "tool_name": "Bash", "tool_input": { "command": "ls" } }),
    )
    .await;
    assert_eq!(first.status(), reqwest::StatusCode::OK);

    let second = client
        .post(format!("{base}/api/hook/tool-call"))
        .header("Authorization", bearer(&agent))
        .json(&serde_json::json!({ "session_id": session_id, "tool_name": "Bash", "tool_input": { "command": "pwd" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_first_calls_for_one_session_id_share_one_ledger_session() {
    let base = spawn_server().await;
    let session_id = Uuid::new_v4().to_string();
    let client = reqwest::Client::new();
    let mut handles = Vec::new();
    for i in 0..8 {
        let client = client.clone();
        let base = base.clone();
        let session_id = session_id.clone();
        handles.push(tokio::spawn(async move {
            tool_call(
                &client,
                &base,
                serde_json::json!({
                    "session_id": session_id,
                    "tool_name": "Bash",
                    "tool_input": { "command": "ls" },
                    "tool_use_id": format!("use-{i}"),
                }),
            )
            .await
        }));
    }
    let mut ledger_ids = std::collections::HashSet::new();
    for handle in handles {
        let resp = handle.await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        ledger_ids.insert(body["ledger_session_id"].as_str().unwrap().to_string());
    }
    assert_eq!(
        ledger_ids.len(),
        1,
        "expected one shared ledger session, got {ledger_ids:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn path_traversal_in_file_path_is_passed_through_for_downstream_policy_to_judge() {
    let base = spawn_server().await;
    let resp = tool_call(
        &reqwest::Client::new(),
        &base,
        serde_json::json!({
            "session_id": Uuid::new_v4().to_string(),
            "tool_name": "Read",
            "tool_input": { "file_path": "../../../etc/passwd" },
            "cwd": "/proj",
        }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(matches!(
        body["decision"].as_str(),
        Some("allow" | "deny" | "ask")
    ));
}

#[cfg(windows)]
#[tokio::test]
async fn windows_style_absolute_and_unc_cwd_do_not_crash_the_hook() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    for cwd in [r"C:\proj", r"\\server\share\proj"] {
        let resp = tool_call(
            &client,
            &base,
            serde_json::json!({
                "session_id": Uuid::new_v4().to_string(),
                "tool_name": "Grep",
                "tool_input": { "pattern": "fn main" },
                "cwd": cwd,
            }),
        )
        .await;
        assert_eq!(resp.status(), reqwest::StatusCode::OK, "cwd {cwd}");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["ledger_session_id"].is_string(), "cwd {cwd}");
    }
}
