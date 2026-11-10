//! The JSON and security metrics.

use super::*;

#[tokio::test]
async fn metrics_json_returns_object() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/metrics"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "metrics/json: {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_object(), "metrics/json should be object: {body}");
}

/// Home reads `total_sessions`, `total_events`, `guard_denials` and
/// `tripwire_rejections` from this response. For a long time the response
/// did not carry them (the GUI test mock did), so every real install showed
/// 0 sessions. The counts are ledger rows, so a second session is visible.
#[tokio::test]
async fn security_metrics_count_the_ledgers_sessions_and_events() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let read = || async {
        let resp = client
            .get(format!("{base}/metrics/security"))
            .header(auth().0, auth().1)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "metrics/security: {}",
            resp.status()
        );
        resp.json::<serde_json::Value>().await.unwrap()
    };

    let before = read().await;
    for key in [
        "total_sessions",
        "total_events",
        "guard_denials",
        "tripwire_rejections",
    ] {
        assert!(
            before[key].is_u64(),
            "{key} missing or not a count: {before}"
        );
    }
    let sessions0 = before["total_sessions"].as_u64().unwrap();
    let events0 = before["total_events"].as_u64().unwrap();

    create_session(&base).await;
    let after = read().await;
    assert_eq!(after["total_sessions"].as_u64().unwrap(), sessions0 + 1);
    // A session opens with at least its genesis event.
    assert!(after["total_events"].as_u64().unwrap() > events0, "{after}");
}
