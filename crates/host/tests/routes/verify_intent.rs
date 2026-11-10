use super::*;

async fn ask(
    base: &str,
    session: &str,
    action: &str,
    params: serde_json::Value,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/sessions/{session}/verify-intent"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({
            "action": action,
            "params": params,
            "justification": "Checking an action before taking it, as the SDK does.",
            "reasoning": "",
        }))
        .send()
        .await
        .expect("POST verify-intent")
}

#[tokio::test]
async fn an_unknown_session_is_not_found_rather_than_echoed() {
    let base = spawn_server().await;
    let ghost = uuid::Uuid::new_v4();
    let resp = ask(
        &base,
        &ghost.to_string(),
        "read_file",
        serde_json::json!({"path": "/etc/hosts"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "a verdict must not name a session that does not exist"
    );
}

#[tokio::test]
async fn a_sealed_session_is_refused() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let sealed = reqwest::Client::new()
        .post(format!("{base}/sessions/{id}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(sealed.status().is_success());

    let resp = ask(
        &base,
        &id,
        "read_file",
        serde_json::json!({"path": "/etc/hosts"}),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn every_verdict_reports_the_layers_it_ran() {
    let base = spawn_server().await;
    let id = create_session(&base).await;

    // Denied by the tripwire - a banned command, which needs no policy.
    let resp = ask(
        &base,
        &id,
        "run_command",
        serde_json::json!({"command": "rm -rf /"}),
    )
    .await;
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(
        status.is_success(),
        "a denial is a 200 with a verdict; got {status}: {text}"
    );
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["stage"], "tripwire");
    assert_eq!(body["session_id"], id);
    // No ECTO_POLICY_PATH and no guard on this surface: both are reported
    // as skipped rather than silently counted as passed.
    assert_eq!(
        body["coverage"]["evaluated"],
        serde_json::json!(["tripwire"])
    );
    assert_eq!(
        body["coverage"]["skipped"],
        serde_json::json!(["policy", "guard"])
    );
    assert_eq!(
        body["recorded"], false,
        "this surface writes nothing, and the response has to say so"
    );
}
