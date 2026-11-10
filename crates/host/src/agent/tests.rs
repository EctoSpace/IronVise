//! The isolation-tier fail-closed policy, and loop detection.
//!
//! The tier tests pin the decision made when a configured Firecracker/Docker
//! tier fails: abort by default, fall back to the host executor only under the
//! documented `ECTO_SANDBOX_PERMISSIVE` opt-in. The end-to-end executor
//! counterpart lives in `executor::sandbox_fail_closed_tests`. The loop as a
//! whole is pinned by `tests/agent_golden.rs`.

use super::*;
use std::sync::Mutex;

/// Serializes tests that mutate process-global environment variables.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn tier_failure_aborts_unless_permissive() {
    assert_eq!(tier_failure_action(false), TierFailureAction::Abort);
    assert_eq!(tier_failure_action(true), TierFailureAction::FallBackToHost);
}

/// The default (env var unset) must be fail-closed - a regression here
/// would silently reintroduce unsandboxed host execution.
#[test]
fn default_env_is_fail_closed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("ECTO_SANDBOX_PERMISSIVE") };
    assert_eq!(
        tier_failure_action(crate::config::sandbox_permissive()),
        TierFailureAction::Abort,
        "with ECTO_SANDBOX_PERMISSIVE unset, a failed isolation tier must abort"
    );

    unsafe { std::env::set_var("ECTO_SANDBOX_PERMISSIVE", "true") };
    assert_eq!(
        tier_failure_action(crate::config::sandbox_permissive()),
        TierFailureAction::FallBackToHost
    );
    unsafe { std::env::remove_var("ECTO_SANDBOX_PERMISSIVE") };
}

fn action(sequence: i64, name: &str, params: serde_json::Value) -> crate::schema::LedgerEventRow {
    crate::schema::LedgerEventRow {
        id: sequence,
        sequence,
        previous_hash: String::new(),
        content_hash: String::new(),
        payload: crate::schema::EventPayload::Action {
            name: name.to_string(),
            params,
        },
        created_at: chrono::Utc::now(),
    }
}

#[test]
fn canonical_json_ignores_key_order_at_every_depth() {
    let a = serde_json::json!({"b": 1, "a": {"y": [1, {"q": 2, "p": 3}], "x": null}});
    let b = serde_json::json!({"a": {"x": null, "y": [1, {"p": 3, "q": 2}]}, "b": 1});
    assert_eq!(
        loop_detection::canonical_json(&a),
        loop_detection::canonical_json(&b)
    );
    assert_eq!(
        loop_detection::canonical_json(&a),
        r#"{"a":{"x":null,"y":[1,{"p":3,"q":2}]},"b":1}"#
    );
}

#[test]
fn canonical_json_keeps_array_order() {
    assert_ne!(
        loop_detection::canonical_json(&serde_json::json!([1, 2])),
        loop_detection::canonical_json(&serde_json::json!([2, 1]))
    );
}

#[test]
fn three_identical_actions_in_the_last_six_are_a_loop() {
    let read = |seq, path: &str| action(seq, "read_file", serde_json::json!({"path": path}));
    let events = vec![
        read(1, "a"),
        read(2, "b"),
        read(3, "a"),
        read(4, "c"),
        read(5, "a"),
    ];
    assert!(loop_detection::detect_loop(&events));
    assert!(!loop_detection::detect_loop(&events[..4]));
}

#[test]
fn a_repeat_older_than_the_last_six_actions_is_not_a_loop() {
    let read = |seq, path: &str| action(seq, "read_file", serde_json::json!({"path": path}));
    let events: Vec<_> = ["a", "a", "b", "c", "d", "e", "f", "a"]
        .iter()
        .enumerate()
        .map(|(i, p)| read(i as i64 + 1, p))
        .collect();
    assert!(!loop_detection::detect_loop(&events));
}

#[test]
fn the_same_parameters_in_another_key_order_are_the_same_action() {
    let events = vec![
        action(1, "http_get", serde_json::json!({"url": "u", "h": "1"})),
        action(2, "http_get", serde_json::json!({"h": "1", "url": "u"})),
        action(3, "http_get", serde_json::json!({"url": "u", "h": "1"})),
    ];
    assert!(loop_detection::detect_loop(&events));
}
