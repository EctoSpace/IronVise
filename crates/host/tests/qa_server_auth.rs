mod qa_server_common;

use qa_server_common::{
    ADMIN_TOKEN, bearer, create_recorder_session, spawn_server, token_with_role,
};

#[tokio::test]
async fn missing_authorization_header_is_rejected() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/api/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_authorization_headers_are_rejected() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    for header_value in [
        "",
        "Bearer",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "token abc123",
        &bearer(""),
        "Bearer\tabc",
    ] {
        let resp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", header_value)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "header {header_value:?} should be rejected"
        );
    }
}

#[tokio::test]
async fn lowercase_bearer_scheme_is_rejected() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/api/sessions"))
        .header("Authorization", format!("bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorization_header_with_trailing_whitespace_is_still_accepted() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/api/sessions"))
        .header("Authorization", format!("Bearer {ADMIN_TOKEN} "))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn very_long_and_unicode_tokens_are_rejected_not_matched() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let long_token = "a".repeat(100_000);
    let unicode_token = "tökén-🔒-测试";
    for candidate in [long_token.as_str(), unicode_token] {
        let resp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", bearer(candidate))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn query_token_is_accepted_only_on_allowlisted_paths() {
    let base = spawn_server().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let allowed = client
        .get(format!("{base}/metrics?token={ADMIN_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_ne!(allowed.status(), reqwest::StatusCode::UNAUTHORIZED);

    let disallowed = client
        .get(format!("{base}/api/sessions?token={ADMIN_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(disallowed.status(), reqwest::StatusCode::UNAUTHORIZED);

    let webhooks = client
        .get(format!("{base}/api/webhooks?token={ADMIN_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(webhooks.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_header_wins_over_query_token_when_both_present() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{base}/api/sessions?token=garbage-not-a-real-token"
        ))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn unknown_role_string_in_db_is_rejected_not_trusted() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/sessions"))
        .header("Authorization", bearer("definitely-not-a-seeded-token"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_token_is_rejected_on_reuse() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let raw = token_with_role(&client, &base, ADMIN_TOKEN, "agent").await;
    let session_id = create_recorder_session(&client, &base, &raw).await;
    assert!(!session_id.is_empty());

    let hash = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(raw.as_bytes()))
    };
    let delete_resp = client
        .delete(format!("{base}/api/tokens/{hash}"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), reqwest::StatusCode::NO_CONTENT);

    let reuse_resp = client
        .get(format!("{base}/api/sessions"))
        .header("Authorization", bearer(&raw))
        .send()
        .await
        .unwrap();
    assert_eq!(reuse_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn non_admin_roles_cannot_mint_tokens() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    for role in ["auditor", "agent"] {
        let scoped = token_with_role(&client, &base, ADMIN_TOKEN, role).await;
        let resp = client
            .post(format!("{base}/api/tokens"))
            .header("Authorization", bearer(&scoped))
            .json(&serde_json::json!({ "role": "admin" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN, "role {role}");
    }
}

#[tokio::test]
async fn non_admin_roles_cannot_list_or_delete_tokens() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let agent = token_with_role(&client, &base, ADMIN_TOKEN, "agent").await;
    let list_resp = client
        .get(format!("{base}/api/tokens"))
        .header("Authorization", bearer(&agent))
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), reqwest::StatusCode::FORBIDDEN);

    let delete_resp = client
        .delete(format!(
            "{base}/api/tokens/0000000000000000000000000000000000000000000000000000000000000000"
        ))
        .header("Authorization", bearer(&agent))
        .send()
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_requested_role_is_rejected() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/tokens"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "role": "superadmin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn listed_tokens_never_include_the_raw_secret() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let raw = token_with_role(&client, &base, ADMIN_TOKEN, "agent").await;

    let resp = client
        .get(format!("{base}/api/tokens"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body_text = resp.text().await.unwrap();
    assert!(
        !body_text.contains(&raw),
        "raw token leaked in list_tokens response"
    );

    let rows: serde_json::Value = serde_json::from_str(&body_text).unwrap();
    for row in rows.as_array().unwrap() {
        assert!(
            row.get("token").is_none(),
            "row should not carry a raw token field"
        );
        assert!(row.get("token_hash").is_some());
    }
}
