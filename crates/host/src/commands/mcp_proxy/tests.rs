use super::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, duplex};

/// A stand-in MCP server: answers every request with `{"echo": method}`
/// and remembers what reached it.
fn fake_server(
    stdin: tokio::io::DuplexStream,
    mut stdout: tokio::io::DuplexStream,
    seen: Arc<Mutex<Vec<Value>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdin).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let msg: Value = serde_json::from_str(&line).unwrap();
            seen.lock().unwrap().push(msg.clone());
            if let Some(id) = msg.get("id") {
                let reply =
                    json!({ "jsonrpc": "2.0", "id": id, "result": { "echo": msg["method"] } });
                stdout
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
            }
        }
    })
}

/// Run the relay over `input` lines with a decider that refuses the tool
/// named `rm`, and return what the client got and what the server saw.
async fn run(input: &[&str]) -> (Vec<Value>, Vec<Value>) {
    let (got, seen, _) = run_recording(input).await;
    (got, seen)
}

/// As [`run`], also returning the answers handed over for receipts.
async fn run_recording(input: &[&str]) -> (Vec<Value>, Vec<Value>, Vec<(String, Value)>) {
    let (mut client_w, proxy_client_in) = duplex(64 * 1024);
    let (proxy_client_out, client_r) = duplex(64 * 1024);
    let (proxy_server_in, server_stdin) = duplex(64 * 1024);
    let (server_stdout, proxy_server_out) = duplex(64 * 1024);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = fake_server(server_stdin, server_stdout, seen.clone());

    let decide = |call: ToolCall| async move {
        if call.tool == "rm" {
            Decision::Deny("rm is not allowed".into())
        } else {
            Decision::Allow
        }
    };
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let received = {
        let receipts = receipts.clone();
        move |call: ToolCall, response: Value| {
            receipts.lock().unwrap().push((call.tool, response));
            async {}
        }
    };
    let proxy = tokio::spawn(relay(
        proxy_client_in,
        proxy_client_out,
        proxy_server_in,
        proxy_server_out,
        decide,
        received,
    ));
    for line in input {
        client_w
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
    }
    drop(client_w);
    proxy.await.unwrap().unwrap();
    server.await.unwrap();

    let mut got = Vec::new();
    let mut lines = BufReader::new(client_r).lines();
    while let Ok(Some(l)) = lines.next_line().await {
        got.push(serde_json::from_str(&l).unwrap());
    }
    let seen = seen.lock().unwrap().clone();
    let receipts = receipts.lock().unwrap().clone();
    (got, seen, receipts)
}

/// Only an allowed call's answer is handed over, once, after the client
/// has it; refusals and other traffic produce no receipt.
#[tokio::test]
async fn an_answered_call_is_handed_over_for_its_receipt() {
    let (got, _, receipts) = run_recording(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read","arguments":{"path":"a"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rm","arguments":{}}}"#,
        ])
        .await;
    assert_eq!(by_id(&got, 2)["result"]["echo"], "tools/call");
    assert_eq!(
        receipts,
        vec![("read".to_string(), json!({ "echo": "tools/call" }))]
    );
}

fn by_id(msgs: &[Value], id: i64) -> Value {
    msgs.iter()
        .find(|m| m["id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn an_allowed_call_and_everything_else_pass_through() {
    let (got, seen) = run(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ls","arguments":{"path":"."}}}"#,
        ])
        .await;
    assert_eq!(seen.len(), 3, "all three reached the server: {seen:?}");
    assert_eq!(by_id(&got, 1)["result"]["echo"], "initialize");
    assert_eq!(by_id(&got, 2)["result"]["echo"], "tools/call");
}

#[tokio::test]
async fn a_refused_call_never_reaches_the_server_and_the_model_reads_why() {
    let (got, seen) = run(&[
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"rm","arguments":{"path":"/"}}}"#,
        ])
        .await;
    assert!(seen.is_empty(), "the server saw it: {seen:?}");
    let reply = by_id(&got, 7);
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert!(
        reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("rm is not allowed")
    );
}

#[tokio::test]
async fn what_cannot_be_checked_is_not_forwarded() {
    let (got, seen) = run(&[
        "{ not json",
        r#"[{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ls"}}]"#,
    ])
    .await;
    assert!(seen.is_empty(), "{seen:?}");
    assert_eq!(got[0]["error"]["code"], -32700);
    assert_eq!(by_id(&got, 3)["result"]["isError"], true);
}

#[tokio::test]
async fn an_unreachable_observer_refuses() {
    let call = ToolCall {
        id: json!(1),
        tool: "ls".into(),
        arguments: json!({}),
    };
    let d = ask_observer(
        &reqwest::Client::new(),
        "http://127.0.0.1:9",
        "t",
        "s",
        "fs",
        &call,
    )
    .await;
    assert!(matches!(d, Decision::Deny(r) if r.contains("unreachable")));
}
