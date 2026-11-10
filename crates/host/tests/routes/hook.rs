//! The hook route: what it allows, where a session is confined, replays,
//! the MCP proxy and data receipts.

use super::*;

/// Write, Edit and NotebookEdit are evaluated on where they land, instead of
/// being escalated unevaluated. The workspace is the server's working
/// directory, as for Read.
#[tokio::test]
async fn the_hook_judges_file_writes_by_where_they_land() {
    let base = spawn_server().await;
    let cwd = std::env::current_dir().unwrap();
    let inside = cwd.join("no-such-dir-yet/new.rs");

    let r = hook_call(
        &base,
        "Write",
        serde_json::json!({ "file_path": inside, "content": "x" }),
    )
    .await;
    assert_eq!(r["decision"], "allow", "{r}");
    assert_eq!(r["recorded"], serde_json::json!(true), "{r}");

    let r = hook_call(
        &base,
        "Edit",
        serde_json::json!({ "file_path": "/etc/passwd" }),
    )
    .await;
    assert_eq!(r["decision"], "deny", "{r}");

    // The agent's own hook settings, even inside the workspace.
    let settings = cwd.join(".claude/settings.local.json");
    let r = hook_call(&base, "Write", serde_json::json!({ "file_path": settings })).await;
    assert_eq!(r["decision"], "deny", "{r}");
    assert!(
        r["reason"].as_str().unwrap().contains("hook configuration"),
        "{r}"
    );

    let r = hook_call(
        &base,
        "NotebookEdit",
        serde_json::json!({ "notebook_path": cwd.join("a.ipynb") }),
    )
    .await;
    assert_eq!(r["decision"], "allow", "{r}");
    assert!(
        !inside.parent().unwrap().exists(),
        "the check must not create anything"
    );
}

/// Glob and Grep are checked as a read of the directory they can reach, which
/// defaults to Claude Code's working directory.
#[tokio::test]
async fn the_hook_judges_searches_by_the_directory_they_can_reach() {
    let base = spawn_server().await;
    let cwd = std::env::current_dir().unwrap();
    let call = |tool: &'static str, input: serde_json::Value| {
        let base = base.clone();
        let cwd = cwd.clone();
        async move {
            reqwest::Client::new()
                .post(format!("{base}/hook/tool-call"))
                .header(auth().0, auth().1)
                .json(&serde_json::json!({
                    "session_id": "search-test",
                    "tool_name": tool,
                    "tool_input": input,
                    "cwd": cwd,
                }))
                .send()
                .await
                .expect("POST /hook/tool-call")
                .json::<serde_json::Value>()
                .await
                .expect("json")
        }
    };

    let r = call("Grep", serde_json::json!({ "pattern": "fn main" })).await;
    assert_eq!(r["decision"], "allow", "{r}");
    let r = call("Glob", serde_json::json!({ "pattern": "src/**/*.rs" })).await;
    assert_eq!(r["decision"], "allow", "{r}");

    // An absolute pattern ignores the working directory, and is judged there.
    let r = call("Glob", serde_json::json!({ "pattern": "/etc/*" })).await;
    assert_eq!(r["decision"], "deny", "{r}");

    // A climbing pattern is escalated, not checked against the wrong place.
    let r = call("Glob", serde_json::json!({ "pattern": "{src,..}/*" })).await;
    assert_eq!(r["decision"], "ask", "{r}");
    assert!(
        r["reason"].as_str().unwrap().contains("stays inside"),
        "{r}"
    );
    let r = call("Task", serde_json::json!({ "prompt": "x" })).await;
    assert_eq!(r["decision"], "ask", "{r}");
    assert!(
        r["reason"].as_str().unwrap().contains("no equivalent"),
        "{r}"
    );
}

/// Without a tripwire.json the workspace is the project the Claude Code
/// session started in, not the server's working directory (for the desktop
/// app opened from Finder, `/`). It is pinned at the first call.
#[tokio::test]
async fn a_hook_session_is_confined_to_the_project_it_started_in() {
    let base = spawn_server().await;
    let project = tempfile::tempdir().unwrap();
    let project_dir = project.path().canonicalize().unwrap();
    let server_cwd = std::env::current_dir().unwrap();
    let call = |cwd: std::path::PathBuf, file: std::path::PathBuf| {
        let base = base.clone();
        async move {
            reqwest::Client::new()
                .post(format!("{base}/hook/tool-call"))
                .header(auth().0, auth().1)
                .json(&serde_json::json!({
                    "session_id": "pin-test",
                    "tool_name": "Write",
                    "tool_input": { "file_path": file },
                    "cwd": cwd,
                }))
                .send()
                .await
                .expect("POST /hook/tool-call")
                .json::<serde_json::Value>()
                .await
                .expect("json")
        }
    };

    let r = call(project_dir.clone(), project_dir.join("src/lib.rs")).await;
    assert_eq!(r["decision"], "allow", "{r}");
    // The server's own directory is outside this session's project.
    let r = call(project_dir.clone(), server_cwd.join("x.rs")).await;
    assert_eq!(r["decision"], "deny", "{r}");
    // A later cwd does not move the workspace.
    let r = call(server_cwd.clone(), server_cwd.join("x.rs")).await;
    assert_eq!(r["decision"], "deny", "{r}");
}

/// `$CLAUDE_PROJECT_DIR`, forwarded by the hook client, is the project root;
/// `cwd` may have followed a `cd` elsewhere, so the project wins.
#[tokio::test]
async fn the_project_dir_outranks_the_cwd() {
    let base = spawn_server().await;
    let project = tempfile::tempdir().unwrap();
    let project_dir = project.path().canonicalize().unwrap();
    let server_cwd = std::env::current_dir().unwrap();
    let call = |file: std::path::PathBuf| {
        let base = base.clone();
        let (project_dir, server_cwd) = (project_dir.clone(), server_cwd.clone());
        async move {
            reqwest::Client::new()
                .post(format!("{base}/hook/tool-call"))
                .header(auth().0, auth().1)
                .json(&serde_json::json!({
                    "session_id": "project-dir-test",
                    "tool_name": "Write",
                    "tool_input": { "file_path": file },
                    "cwd": server_cwd,
                    "project_dir": project_dir,
                }))
                .send()
                .await
                .expect("POST /hook/tool-call")
                .json::<serde_json::Value>()
                .await
                .expect("json")
        }
    };
    let r = call(project_dir.join("a.rs")).await;
    assert_eq!(r["decision"], "allow", "{r}");
    let r = call(server_cwd.join("a.rs")).await;
    assert_eq!(r["decision"], "deny", "{r}");
}

/// Claude Code runs tool calls in parallel. The hook fails closed on a 429, so
/// a burst of calls must not hit the session-creation limit (burst 5).
#[tokio::test]
async fn a_burst_of_hook_calls_is_not_rate_limited() {
    let base = spawn_server().await;
    let cwd = std::env::current_dir().unwrap();
    let calls = (0..12).map(|i| {
        let base = base.clone();
        let cwd = cwd.clone();
        async move {
            reqwest::Client::new()
                .post(format!("{base}/hook/tool-call"))
                .header(auth().0, auth().1)
                .json(&serde_json::json!({
                    "session_id": "burst-test",
                    "tool_name": "Read",
                    "tool_input": { "file_path": cwd.join(format!("f{i}.rs")) },
                    "cwd": cwd,
                }))
                .send()
                .await
                .expect("POST /hook/tool-call")
                .status()
        }
    });
    for status in futures_util::future::join_all(calls).await {
        assert!(status.is_success(), "{status}");
    }
}

/// A second request for the same tool use is refused, and the refusal is a
/// signed event: the session still verifies with it in.
#[tokio::test]
async fn a_replayed_hook_call_is_refused_and_the_refusal_is_signed() {
    let base = spawn_server().await;
    let (_, first) = hook_as(&base, TEST_TOKEN, "replay-test", "toolu_1").await;
    assert_eq!(first["decision"], "allow", "{first}");
    let (_, second) = hook_as(&base, TEST_TOKEN, "replay-test", "toolu_1").await;
    assert_eq!(second["decision"], "deny", "{second}");
    assert_eq!(second["stage"], "replay", "{second}");
    assert_eq!(second["recorded"], serde_json::json!(true), "{second}");
    let (_, other) = hook_as(&base, TEST_TOKEN, "replay-test", "toolu_2").await;
    assert_eq!(
        other["decision"], "allow",
        "a new tool use is not a replay: {other}"
    );

    let sid = first["ledger_session_id"].as_str().unwrap();
    let client = reqwest::Client::new();
    let events = client
        .get(format!("{base}/events?session_id={sid}"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        events.contains("replayed request: tool_use_id toolu_1"),
        "{events}"
    );
    let verify: serde_json::Value = client
        .get(format!("{base}/sessions/{sid}/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verify["signatures"]["verdict"], "verified", "{verify}");
    // allow, the signed refusal, allow
    assert_eq!(
        verify["signatures"]["signed"],
        serde_json::json!(3),
        "{verify}"
    );
}

/// Claude Code's session id is the client's choice. Another token reusing it
/// must not get the server to sign events into that session.
#[tokio::test]
async fn a_hook_session_takes_calls_only_from_the_token_that_opened_it() {
    let base = spawn_server().await;
    let (status, _) = hook_as(&base, TEST_TOKEN, "owned-session", "toolu_a").await;
    assert!(status.is_success());
    let intruder = agent_token(&base).await;
    let (status, _) = hook_as(&base, &intruder, "owned-session", "toolu_b").await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    let (status, own) = hook_as(&base, &intruder, "intruder-own-session", "toolu_c").await;
    assert!(status.is_success(), "its own session is fine: {own}");
}

/// The relay with the real decider: an allowed MCP call reaches the server, a
/// refused one (a `sudo` in its command argument) never does, and both
/// decisions are signed into one verifiable session.
#[tokio::test]
async fn the_mcp_proxy_asks_the_observer_and_records_both_decisions() {
    use ectoledger::commands::mcp_proxy::{ToolCall, ask_observer, record_result, relay};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};

    let api = spawn_server().await;
    let base = api.trim_end_matches("/api").to_string();
    let (mut client_w, proxy_in) = duplex(1 << 16);
    let (proxy_out, client_r) = duplex(1 << 16);
    let (to_server, server_stdin) = duplex(1 << 16);
    let (mut server_stdout, from_server) = duplex(1 << 16);

    let reached = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let server = {
        let reached = reached.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(server_stdin).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let msg: serde_json::Value = serde_json::from_str(&line).unwrap();
                reached
                    .lock()
                    .unwrap()
                    .push(msg["params"]["name"].to_string());
                let reply = serde_json::json!({ "jsonrpc": "2.0", "id": msg["id"],
                    "result": { "content": [{ "type": "text", "text": "listing" }] } });
                server_stdout
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
            }
        })
    };

    let session = format!("mcp-proxy:shell:{}", uuid::Uuid::new_v4());
    let http = reqwest::Client::new();
    let proxy = tokio::spawn({
        let base = base.clone();
        let session = session.clone();
        async move {
            let http = reqwest::Client::new();
            let received = {
                let (http, base, session) = (http.clone(), base.clone(), session.clone());
                move |call: ToolCall, response: serde_json::Value| {
                    let (http, base, session) = (http.clone(), base.clone(), session.clone());
                    async move {
                        record_result(
                            &http, &base, TEST_TOKEN, &session, "shell", &call, &response,
                        )
                        .await
                    }
                }
            };
            relay(
                proxy_in,
                proxy_out,
                to_server,
                from_server,
                |call: ToolCall| {
                    let (http, base, session) = (http.clone(), base.clone(), session.clone());
                    async move { ask_observer(&http, &base, TEST_TOKEN, &session, "shell", &call).await }
                },
                received,
            )
            .await
        }
    });
    for (id, cmd) in [(1, "ls && pwd"), (2, "ls && sudo id")] {
        let call = serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": "run", "arguments": { "command": cmd } } });
        client_w
            .write_all(format!("{call}\n").as_bytes())
            .await
            .unwrap();
    }
    drop(client_w);
    proxy.await.unwrap().unwrap();
    server.await.unwrap();

    let mut replies = Vec::new();
    let mut lines = BufReader::new(client_r).lines();
    while let Ok(Some(l)) = lines.next_line().await {
        replies.push(serde_json::from_str::<serde_json::Value>(&l).unwrap());
    }
    assert_eq!(
        reached.lock().unwrap().len(),
        1,
        "only the allowed call reached the server"
    );
    let refused = replies
        .iter()
        .find(|r| r["id"] == 2)
        .expect("reply to id 2");
    assert_eq!(refused["result"]["isError"], true, "{refused}");
    assert!(refused.to_string().contains("sudo id"), "{refused}");

    let sessions: serde_json::Value = http
        .get(format!("{api}/sessions"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sid = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["llm_backend"] == "mcp-proxy")
        .map(|s| s["id"].as_str().unwrap().to_string());
    let events = http
        .get(format!(
            "{api}/events?session_id={}",
            sid.clone().unwrap_or_default()
        ))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(events.contains("mcp:shell/run"), "{events}");
    assert!(events.contains("tripwire_rejection"), "{events}");
    // The allowed call's answer is in the chain by hash, and only by hash.
    assert!(events.contains("data_receipt"), "{events}");
    assert!(
        events.contains(&hex::encode(Sha256::digest(b"listing"))),
        "{events}"
    );
    assert!(!events.contains("\"listing\""), "{events}");
}

/// A data receipt, built where the tool ran, is recorded once per tool use,
/// only by tokens that may write, and only when it is hashes.
#[tokio::test]
async fn a_tool_result_is_recorded_as_a_receipt_once() {
    let base = spawn_server().await;
    let content = "db_password=example\n";
    let receipt = ectoledger::receipts::receipt(
        "Read",
        &serde_json::json!({ "file_path": "/p/config.ini" }),
        &serde_json::json!({ "type": "text", "file": { "filePath": "/p/config.ini", "content": content } }),
        None,
    );
    let body = serde_json::json!({
        "session_id": "receipts", "tool_use_id": "toolu_r1", "receipt": receipt,
    });
    assert!(!body.to_string().contains("db_password"), "{body}");
    let post = |token: String, body: serde_json::Value| {
        let url = format!("{base}/hook/tool-result");
        async move {
            reqwest::Client::new()
                .post(url)
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };
    let first = post(TEST_TOKEN.into(), body.clone()).await;
    assert!(first.status().is_success(), "{}", first.status());
    let first: serde_json::Value = first.json().await.unwrap();
    assert_eq!(first["receipt"]["type"], "data_receipt");
    assert_eq!(first["receipt"]["source"], "/p/config.ini");
    assert_eq!(first["receipt"]["call_id"], "toolu_r1");
    assert_eq!(
        first["receipt"]["text_sha256"][0],
        hex::encode(Sha256::digest(content.as_bytes()))
    );
    assert_eq!(
        post(TEST_TOKEN.into(), body.clone()).await.status(),
        reqwest::StatusCode::CONFLICT
    );
    let auditor = token_with_role(&base, "auditor").await;
    assert_eq!(
        post(auditor, body.clone()).await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    // The data where a hash belongs, or anything that is not a receipt.
    let mut leaky = body.clone();
    leaky["tool_use_id"] = "toolu_r2".into();
    leaky["receipt"]["text_sha256"] = serde_json::json!([content]);
    let refused = post(TEST_TOKEN.into(), leaky).await;
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("not a SHA-256 digest"),
        "the refusal says why"
    );
    let mut other = body.clone();
    other["tool_use_id"] = "toolu_r3".into();
    other["receipt"] = serde_json::json!({ "type": "thought", "content": "hi" });
    assert_eq!(
        post(TEST_TOKEN.into(), other).await.status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let sid = first["ledger_session_id"].as_str().unwrap();
    let events = reqwest::Client::new()
        .get(format!("{base}/events?session_id={sid}"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(events.contains("data_receipt"), "{events}");
    assert!(!events.contains("db_password"), "{events}");
    let verdict: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/sessions/{sid}/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verdict["ok"], true, "{verdict}");
    assert_eq!(verdict["signatures"]["verified"], true, "{verdict}");
}
