mod qa_server_common;

use qa_server_common::{ADMIN_TOKEN, bearer, spawn_server};

async fn create(client: &reqwest::Client, base: &str, url: &str) -> reqwest::Response {
    client
        .post(format!("{base}/api/webhooks"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "label": "qa", "url": url }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn ssrf_targets_are_rejected_with_a_400() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let targets = [
        "http://127.0.0.1/hook",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "ftp://example.com/hook",
        "not a url",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[fd00::1]/",
        "http://10.0.0.5/",
        "http://192.168.1.5/",
    ];
    for target in targets {
        let resp = create(&client, &base, target).await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "target {target} should have been rejected"
        );
    }
}

#[tokio::test]
async fn empty_url_is_rejected() {
    let base = spawn_server().await;
    let resp = create(&reqwest::Client::new(), &base, "").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn public_https_url_is_accepted() {
    let base = spawn_server().await;
    let resp = create(&reqwest::Client::new(), &base, "https://example.com/hook").await;
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
}

#[tokio::test]
async fn duplicate_webhook_urls_are_both_accepted() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let first = create(&client, &base, "https://example.com/dup-hook").await;
    assert_eq!(first.status(), reqwest::StatusCode::CREATED);
    let second = create(&client, &base, "https://example.com/dup-hook").await;
    assert_eq!(
        second.status(),
        reqwest::StatusCode::CREATED,
        "no uniqueness constraint is enforced on webhook URLs"
    );

    let list = client
        .get(format!("{base}/api/webhooks"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    let rows: serde_json::Value = list.json().await.unwrap();
    let matching = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["url"] == "https://example.com/dup-hook")
        .count();
    assert_eq!(matching, 2);
}

#[tokio::test]
async fn non_admin_roles_cannot_manage_webhooks() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let agent = qa_server_common::token_with_role(&client, &base, ADMIN_TOKEN, "agent").await;
    for (method, path) in [
        ("GET", "/api/webhooks"),
        ("POST", "/api/webhooks"),
        ("PUT", "/api/webhooks/00000000-0000-0000-0000-000000000000"),
        (
            "DELETE",
            "/api/webhooks/00000000-0000-0000-0000-000000000000",
        ),
    ] {
        let req = client
            .request(method.parse().unwrap(), format!("{base}{path}"))
            .header("Authorization", bearer(&agent))
            .json(&serde_json::json!({ "label": "qa", "url": "https://example.com", "enabled": true }));
        let resp = req.send().await.unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::FORBIDDEN,
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn invalid_siem_format_is_rejected() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/webhooks"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({ "label": "qa", "url": "https://example.com", "siem_format": "xml" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn listed_webhooks_never_include_the_bearer_token() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let create_resp = client
        .post(format!("{base}/api/webhooks"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .json(&serde_json::json!({
            "label": "qa",
            "url": "https://example.com/secret-sink",
            "bearer_token": "super-secret-value",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_resp.status(), reqwest::StatusCode::CREATED);

    let list_resp = client
        .get(format!("{base}/api/webhooks"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    let body_text = list_resp.text().await.unwrap();
    assert!(!body_text.contains("super-secret-value"));
}
