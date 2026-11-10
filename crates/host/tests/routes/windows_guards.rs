use super::*;

#[tokio::test]
async fn event_with_system32_path() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/sessions/{id}/events"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({
            "event_type": "file_access",
            "payload": { "path": "C:\\Windows\\System32\\config\\SAM" }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success() || resp.status().as_u16() == 400,
        "windows system32 path: {}",
        resp.status()
    );
}

#[tokio::test]
async fn event_with_unc_path() {
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/sessions/{id}/events"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({
            "event_type": "file_access",
            "payload": { "path": "\\\\server\\share\\secret.doc" }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success() || resp.status().as_u16() == 400,
        "windows UNC path: {}",
        resp.status()
    );
}
