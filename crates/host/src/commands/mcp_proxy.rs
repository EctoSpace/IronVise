//! `ironvise mcp-proxy --name <server> -- <command…>`: sit between an MCP
//! client and a stdio MCP server, and have the Observer judge every
//! `tools/call` before the server sees it.
//!
//! Everything else (initialize, tools/list, notifications, responses) passes
//! through byte for byte. A refused call never reaches the server: the client
//! gets a tool result with `isError`, so the model reads why. The proxy fails
//! closed: an unreachable Observer, an unparseable line or a batched call is
//! refused, not forwarded. The server's answer to an allowed call is passed on
//! first and then recorded as a data receipt: its hashes, never its content.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// One `tools/call` request, as the client sent it.
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: Value,
    pub tool: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}

fn refusal(id: &Value, reason: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": format!("Refused by IronVise: {reason}") }],
            "isError": true,
        },
    })
    .to_string()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

fn as_tool_call(msg: &Value) -> Option<ToolCall> {
    if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let params = msg.get("params");
    Some(ToolCall {
        id: msg.get("id").cloned().unwrap_or(Value::Null),
        tool: params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        arguments: params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json!({})),
    })
}

/// Relay newline-delimited JSON-RPC between client and server, asking
/// `decide` about each `tools/call` and handing each answer to an allowed call
/// to `received` (after the client has it). Returns when the client closes its
/// input and the server has finished writing.
pub async fn relay<CI, CO, SI, SO, F, Fut, R, RFut>(
    client_in: CI,
    client_out: CO,
    mut server_in: SI,
    server_out: SO,
    decide: F,
    received: R,
) -> std::io::Result<()>
where
    CI: AsyncRead + Unpin,
    CO: AsyncWrite + Unpin + Send + 'static,
    SI: AsyncWrite + Unpin,
    SO: AsyncRead + Unpin + Send + 'static,
    F: Fn(ToolCall) -> Fut,
    Fut: Future<Output = Decision>,
    R: Fn(ToolCall, Value) -> RFut + Send + 'static,
    RFut: Future<Output = ()> + Send,
{
    // Allowed calls awaiting the server's answer, by JSON-RPC id.
    let pending: Arc<Mutex<HashMap<String, ToolCall>>> = Arc::default();
    // One writer, so the proxy's own replies never interleave with the server's.
    let (tx, mut rx) = mpsc::channel::<String>(64);
    let writer = tokio::spawn(async move {
        let mut out = client_out;
        while let Some(line) = rx.recv().await {
            out.write_all(line.as_bytes()).await?;
            out.write_all(b"\n").await?;
            out.flush().await?;
        }
        std::io::Result::Ok(())
    });
    let from_server = {
        let tx = tx.clone();
        let pending = pending.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(server_out).lines();
            while let Some(line) = lines.next_line().await? {
                let answered = serde_json::from_str::<Value>(&line).ok().and_then(|msg| {
                    let call = pending.lock().ok()?.remove(&msg.get("id")?.to_string())?;
                    let response = msg
                        .get("result")
                        .cloned()
                        .unwrap_or_else(|| json!({ "error": msg.get("error") }));
                    Some((call, response))
                });
                if tx.send(line).await.is_err() {
                    break;
                }
                if let Some((call, response)) = answered {
                    received(call, response).await;
                }
            }
            std::io::Result::Ok(())
        })
    };

    let mut lines = BufReader::new(client_in).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            let _ = tx
                .send(rpc_error(
                    &Value::Null,
                    -32700,
                    "parse error: not forwarded",
                ))
                .await;
            continue;
        };
        if let Value::Array(batch) = &msg {
            let calls: Vec<ToolCall> = batch.iter().filter_map(as_tool_call).collect();
            if !calls.is_empty() {
                for call in calls {
                    let _ = tx
                        .send(refusal(
                            &call.id,
                            "a batched tools/call is not checked; send calls one at a time",
                        ))
                        .await;
                }
                continue;
            }
        }
        if let Some(call) = as_tool_call(&msg) {
            if let Decision::Deny(reason) = decide(call.clone()).await {
                let _ = tx.send(refusal(&call.id, &reason)).await;
                continue;
            }
            if let Ok(mut waiting) = pending.lock() {
                waiting.insert(call.id.to_string(), call);
            }
        }
        server_in.write_all(line.as_bytes()).await?;
        server_in.write_all(b"\n").await?;
        server_in.flush().await?;
    }
    // Client gone: close the server's input so it can exit, then drain it.
    server_in.shutdown().await?;
    drop(server_in);
    from_server.await.map_err(std::io::Error::other)??;
    drop(tx);
    writer.await.map_err(std::io::Error::other)?
}

/// Ask the Observer's hook endpoint about one call, as a Claude Code
/// `mcp__<server>__<tool>` call would be asked. Anything but a clear allow is
/// a refusal: there is no human here to answer an `ask`.
pub async fn ask_observer(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    session_id: &str,
    server: &str,
    call: &ToolCall,
) -> Decision {
    let url = format!("{}/api/hook/tool-call", base_url.trim_end_matches('/'));
    let body = json!({
        "session_id": session_id,
        "tool_name": format!("mcp__{server}__{}", call.tool),
        "tool_input": call.arguments,
        "tool_use_id": format!("{session_id}:{}", call.id),
        "cwd": std::env::current_dir().ok(),
    });
    let reply = match client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return Decision::Deny(format!("IronVise unreachable at {url}: {e}")),
    };
    let status = reply.status();
    let verdict: Value = match reply.json().await {
        Ok(v) if status.is_success() => v,
        Ok(v) => return Decision::Deny(format!("IronVise returned {status}: {v}")),
        Err(e) => return Decision::Deny(format!("IronVise returned {status}: {e}")),
    };
    let reason = verdict["reason"]
        .as_str()
        .unwrap_or("no reason given")
        .to_string();
    match verdict["decision"].as_str() {
        Some("allow") => Decision::Allow,
        Some("ask") => Decision::Deny(format!("not evaluated, and no one here to ask: {reason}")),
        _ => Decision::Deny(reason),
    }
}

/// Record the data receipt for one answered call. The receipt is built here,
/// so only hashes leave the proxy. The answer has already reached the client,
/// so a failure can only be reported: on stderr, which MCP clients show as the
/// server's log.
pub async fn record_result(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    session_id: &str,
    server: &str,
    call: &ToolCall,
    response: &Value,
) {
    let url = format!("{}/api/hook/tool-result", base_url.trim_end_matches('/'));
    let tool_use_id = format!("{session_id}:{}", call.id);
    let receipt = crate::receipts::receipt(
        &format!("mcp__{server}__{}", call.tool),
        &call.arguments,
        response,
        Some(&tool_use_id),
    );
    let body = json!({
        "session_id": session_id,
        "receipt": receipt,
        "tool_use_id": tool_use_id,
    });
    let failed = match client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => return,
        Ok(r) => format!("{}", r.status()),
        Err(e) => e.to_string(),
    };
    eprintln!(
        "ironvise mcp-proxy: the data receipt for {} (id {}) was NOT recorded: {failed}",
        call.tool, call.id
    );
}

/// Run `command` as the MCP server behind the proxy, on this process's
/// stdin/stdout. Returns the server's exit code.
pub async fn run(
    name: &str,
    command: &[String],
) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    let valid = !name.is_empty()
        && !name.contains("__")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !valid {
        return Err(format!(
            "--name {name:?}: use letters, digits, '-', '_' or '.', without '__' \
             (policies name tools as mcp:<name>/<tool>)"
        )
        .into());
    }
    let token = std::env::var("ECTOLEDGER_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .ok_or("ECTOLEDGER_TOKEN is not set: every tool call would be refused")?;
    let base =
        std::env::var("ECTOLEDGER_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let (program, args) = command
        .split_first()
        .ok_or("no MCP server command after --")?;

    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("starting {program}: {e}"))?;
    let server_in = child.stdin.take().ok_or("no stdin for the MCP server")?;
    let server_out = child.stdout.take().ok_or("no stdout for the MCP server")?;

    // One ledger session per proxy run; the Observer binds it to this token.
    let session_id = format!("mcp-proxy:{name}:{}", uuid::Uuid::new_v4());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let decide = |call: ToolCall| {
        let (client, base, token, session_id) = (&client, &base, &token, &session_id);
        async move { ask_observer(client, base, token, session_id, name, &call).await }
    };
    let received = {
        let (client, base, token, session_id, name) = (
            client.clone(),
            base.clone(),
            token.clone(),
            session_id.clone(),
            name.to_string(),
        );
        move |call: ToolCall, response: Value| {
            let (client, base, token, session_id, name) = (
                client.clone(),
                base.clone(),
                token.clone(),
                session_id.clone(),
                name.clone(),
            );
            async move {
                record_result(&client, &base, &token, &session_id, &name, &call, &response).await
            }
        }
    };
    relay(
        tokio::io::stdin(),
        tokio::io::stdout(),
        server_in,
        server_out,
        decide,
        received,
    )
    .await?;
    Ok(child.wait().await?.code().unwrap_or(1))
}

#[cfg(test)]
mod tests;
