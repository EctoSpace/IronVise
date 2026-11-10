mod qa_server_common;

use qa_server_common::{ADMIN_TOKEN, bearer, create_recorder_session, spawn_server};
use uuid::Uuid;

#[tokio::test]
async fn get_session_by_nonexistent_but_valid_uuid_is_404() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/sessions/{}", Uuid::new_v4()))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_session_by_malformed_uuid_is_a_client_error_not_a_crash() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/sessions/not-a-uuid-at-all"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error(), "got {}", resp.status());
}

#[tokio::test]
async fn certificate_for_nonexistent_session_is_404() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/certificates/{}", Uuid::new_v4()))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn certificate_for_malformed_uuid_is_a_client_error() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/certificates/not-a-uuid-at-all"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error(), "got {}", resp.status());
}

#[tokio::test]
async fn report_for_nonexistent_session_is_404() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/reports/{}", Uuid::new_v4()))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn events_json_without_session_id_query_param_is_400() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/events"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn events_json_with_malformed_session_id_query_param_is_a_client_error() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/events?session_id=not-a-uuid"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn events_are_visible_right_after_a_recorder_session_is_created() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let session_id = create_recorder_session(&client, &base, ADMIN_TOKEN).await;
    let resp = client
        .get(format!("{base}/api/events?session_id={session_id}"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let events: serde_json::Value = resp.json().await.unwrap();
    assert!(!events.as_array().unwrap().is_empty());
}
