use super::*;

async fn append(base: &str, session: &str, body: serde_json::Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/sessions/{session}/events"))
        .header(auth().0, auth().1)
        .json(&body)
        .send()
        .await
        .expect("POST events")
}

/// The finding: a client could post any tagged `EventPayload`, including
/// the two that carry `enforced: true`. That is evidence of the system
/// having stopped something, manufactured by the thing it would have
/// stopped.
#[tokio::test]
async fn a_client_cannot_manufacture_an_enforcement_record() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;

    for forged in [
        serde_json::json!({
            "type": "guard_denial",
            "action": "run_command",
            "reason": "the guard stopped this, honest",
            "enforced": true,
        }),
        serde_json::json!({
            "type": "tripwire_rejection",
            "action": "run_command",
            "reason": "refused",
            "stage": "tripwire",
            "enforced": true,
        }),
        serde_json::json!({ "type": "action", "name": "run_command", "params": {} }),
        serde_json::json!({ "type": "genesis", "message": "a second genesis" }),
    ] {
        let kind = forged["type"].as_str().unwrap().to_string();
        let resp = append(&base, &id, forged).await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "`{kind}` must not be appendable by a client"
        );
        let text = resp.text().await.unwrap();
        assert!(
            text.contains(&kind),
            "the refusal should name the kind it refused: {text}"
        );
    }
}

/// …while everything the SDKs actually send keeps working. Both documented
/// clients post untagged dictionaries, which become observations.
#[tokio::test]
async fn the_kinds_a_client_can_honestly_assert_still_append() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;

    for allowed in [
        serde_json::json!({ "observation": "tool_start: ls", "kind": "tool_start" }),
        serde_json::json!({ "step": "retrieved_docs" }),
        serde_json::json!({ "type": "observation", "content": "what I saw" }),
        serde_json::json!({ "type": "thought", "content": "what I think" }),
        serde_json::json!({ "type": "prompt_input", "content": "what I was asked" }),
        serde_json::json!({ "type": "chat_message", "role": "user", "content": "hello" }),
    ] {
        let described = allowed.to_string();
        let resp = append(&base, &id, allowed).await;
        assert!(
            resp.status().is_success(),
            "{described} must still append, got {}",
            resp.status()
        );
    }
}
