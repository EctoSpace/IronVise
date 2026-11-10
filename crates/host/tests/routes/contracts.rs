//! The response shapes the SDK fixtures and the webhook editor rely on.

use super::*;

/// sdk/fixtures/server-responses/*.json are what the SDK tests parse. Their
/// field names must be exactly what this server sends, so a change here
/// breaks this test instead of the SDKs in users' hands.
#[tokio::test]
async fn the_sdk_response_fixtures_have_the_servers_field_names() {
    fn keys(v: &serde_json::Value) -> std::collections::BTreeSet<String> {
        v.as_object().unwrap().keys().cloned().collect()
    }
    let fixture = |name: &str| -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/fixtures/server-responses")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    };
    let base = spawn_server().await;
    let id = create_recorder_session(&base).await;
    let client = reqwest::Client::new();
    let get = |path: String| {
        let client = client.clone();
        async move {
            client
                .get(path)
                .header(auth().0, auth().1)
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };

    let events = get(format!("{base}/events?session_id={id}")).await;
    let fx_events = fixture("events.json");
    assert_eq!(keys(&events[0]), keys(&fx_events[0]), "events row");

    let bundle = get(format!("{base}/sessions/{id}/compliance")).await;
    let fx_bundle = fixture("compliance.json");
    assert_eq!(keys(&bundle), keys(&fx_bundle), "compliance bundle");
    assert_eq!(
        keys(&bundle["events"][0]),
        keys(&fx_bundle["events"][0]),
        "compliance event"
    );
}

/// A refused webhook says why. These answered with a bare 400, and the app
/// showed "Failed to create webhook:" with nothing after it.
#[tokio::test]
async fn a_refused_webhook_says_why() {
    let base = spawn_server().await;
    let c = reqwest::Client::new();
    for (url, expect) in [
        ("http://127.0.0.1:9000/hook", "public endpoints only"),
        ("ftp://example.org/hook", "https://"),
        ("not a url", "not a valid URL"),
    ] {
        let r = c
            .post(format!("{base}/webhooks"))
            .header(auth().0, auth().1)
            .json(&serde_json::json!({ "label": "t", "url": url }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "{url}");
        let body = r.text().await.unwrap();
        assert!(body.contains(expect), "{url}: {body}");
    }
}
