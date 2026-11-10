//! The tripwire settings and the dry-run check.

use super::*;

/// The screen needs to know whether the paths it shows are saved or the
/// server's fallback; the fields it already reads stay where they were.
#[tokio::test]
async fn tripwire_config_says_whether_it_is_saved() {
    let base = spawn_server().await;
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/tripwire"))
        .header(auth().0, auth().1)
        .send()
        .await
        .expect("GET /tripwire")
        .json()
        .await
        .expect("json");
    assert!(body["saved"].is_boolean(), "{body}");
    assert!(body["allowed_paths"].is_array(), "{body}");
    assert!(body["require_https"].is_boolean(), "{body}");
}

#[tokio::test]
async fn tripwire_check_allows_a_read_inside_the_workspace_and_records_nothing() {
    let base = spawn_server().await;
    let events0 = total_events(&base).await;

    // With no tripwire.json, the allowed path defaults to the server's
    // working directory (see `config::load_tripwire_config`) - an existing
    // file there, such as the crate's own manifest, is inside it.
    let readable = std::env::current_dir().unwrap().join("Cargo.toml");
    assert!(readable.exists(), "fixture path must exist: {readable:?}");

    let body = check_tripwire(&base, "read_file", serde_json::json!({ "path": readable })).await;
    assert_eq!(body["allowed"], serde_json::json!(true), "{body}");
    assert!(body["reason"].is_null(), "{body}");
    assert!(body["rule"].is_null(), "{body}");
    assert!(body["matched"].is_null(), "{body}");

    assert_eq!(
        total_events(&base).await,
        events0,
        "a tripwire check must not append to the ledger"
    );
}

#[tokio::test]
async fn tripwire_check_denies_a_banned_command_and_records_nothing() {
    let base = spawn_server().await;
    let events0 = total_events(&base).await;

    // Pull the actual banned pattern from the tripwire module at runtime
    // rather than typing one into the test, so the fixture tracks the real
    // default list.
    let pattern = ectoledger::tripwire::default_banned_command_patterns()
        .into_iter()
        .next()
        .expect("default banned patterns is non-empty");

    let body = check_tripwire(
        &base,
        "run_command",
        serde_json::json!({ "command": pattern }),
    )
    .await;
    assert_eq!(body["allowed"], serde_json::json!(false), "{body}");
    assert_eq!(
        body["rule"],
        serde_json::json!("banned_command_patterns"),
        "{body}"
    );
    assert!(
        body["matched"].as_str().is_some_and(|m| !m.is_empty()),
        "{body}"
    );
    assert!(
        body["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "{body}"
    );

    assert_eq!(
        total_events(&base).await,
        events0,
        "a tripwire check must not append to the ledger"
    );
}
