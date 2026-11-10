use super::*;

#[tokio::test]
async fn event_with_sensitive_linux_path() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/sessions/{id}/events"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({
            "event_type": "file_access",
            "payload": { "path": "/etc/shadow" }
        }))
        .send()
        .await
        .unwrap();
    // Accepted (guard logs, not blocks by default) or 400
    assert!(
        resp.status().is_success() || resp.status().as_u16() == 400,
        "linux sensitive path: {}",
        resp.status()
    );
}
