use super::*;

/// A provider's encrypted reasoning passes through the proxy untouched
/// (the agent needs it back) but never reaches the ledger.
#[tokio::test]
async fn encrypted_reasoning_is_forwarded_but_not_recorded() {
    const BLOB: &str = "gAAAAABoPROXYciphertext";
    let upstream = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            axum::Json(serde_json::json!({ "choices": [{ "message": {
                "content": null,
                "reasoning_details": [{ "type": "reasoning.encrypted", "data": BLOB }],
            }}]}))
        }),
    );
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(up, upstream).await.unwrap() });

    let pool = crate::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let (session, key) = pool
        .create_session("proxy test", PROXY_BACKEND_LABEL, "n/a", None)
        .await
        .unwrap();
    let state = Arc::new(ProxyState {
        pool: pool.clone(),
        upstream: format!("http://{up_addr}"),
        client: reqwest::Client::new(),
        tripwire: Tripwire::new(vec![], vec![], vec![], 0, true),
        session_id: session.id,
        signing_key: Arc::new(key),
    });
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(proxy, router(state)).await.unwrap() });

    let reply = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/v1/chat/completions"))
        .json(
            &serde_json::json!({ "messages": [{ "role": "user", "content": "hi" }],
                "reasoning_details": [{ "type": "reasoning.encrypted", "data": BLOB }] }),
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        reply.contains(BLOB),
        "the agent must get its reasoning back: {reply}"
    );

    let events = pool.get_events_by_session(session.id).await.unwrap();
    let recorded: String = events
        .iter()
        .map(|e| serde_json::to_string(&e.payload).unwrap())
        .collect();
    assert!(
        events.len() >= 2,
        "prompt and completion recorded: {recorded}"
    );
    assert!(
        !recorded.contains(BLOB),
        "blob reached the ledger: {recorded}"
    );
    assert!(
        recorded.contains("provider-encrypted reasoning, sha256:"),
        "{recorded}"
    );
}

#[test]
fn only_loopback_is_accepted_without_allow_remote() {
    let addr = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
    assert!(check_bind(&[addr("127.0.0.1:3100")], false).is_ok());
    assert!(check_bind(&[addr("[::1]:3100")], false).is_ok());
    for remote in ["0.0.0.0:3100", "[::]:3100", "192.168.1.5:3100"] {
        let err = check_bind(&[addr(remote)], false).unwrap_err();
        assert!(err.contains("--allow-remote"), "{err}");
        assert!(check_bind(&[addr(remote)], true).is_ok());
    }
    // A name that resolves to loopback and something else is not loopback.
    assert!(check_bind(&[addr("127.0.0.1:1"), addr("10.0.0.1:1")], false).is_err());
    assert!(check_bind(&[], true).is_err());
}

#[tokio::test]
async fn run_refuses_a_wildcard_bind_before_recording_anything() {
    let pool = crate::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let err = run(pool.clone(), "0.0.0.0:0", "http://127.0.0.1:9", false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no authentication"), "{err}");
    assert!(pool.list_sessions().await.unwrap().is_empty());
}

#[test]
fn a_chat_request_is_flattened_to_readable_text() {
    let body = serde_json::json!({
        "messages": [
            {"role": "system", "content": "be careful"},
            {"role": "user", "content": "delete everything"}
        ]
    });
    let p = extract_prompt(&body);
    assert!(p.contains("[system] be careful"));
    assert!(p.contains("[user] delete everything"));
}

#[test]
fn an_unfamiliar_body_is_still_captured_verbatim() {
    // The proxy must not drop what it cannot parse: an incomplete record is
    // the failure mode this component exists to avoid.
    let body = serde_json::json!({ "prompt": "legacy completions shape" });
    assert!(extract_prompt(&body).contains("legacy completions shape"));
}

#[test]
fn the_assistant_message_is_extracted_from_a_response() {
    let body = serde_json::json!({
        "choices": [{ "message": { "role": "assistant", "content": "hello" } }]
    });
    assert_eq!(extract_completion(&body), "hello");
}

#[test]
fn an_unparseable_response_still_yields_something_to_record() {
    let body = serde_json::json!({ "error": "rate limited" });
    assert!(extract_completion(&body).contains("rate limited"));
}
