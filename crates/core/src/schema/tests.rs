use super::*;

fn sample_event() -> ChainEvent {
    ChainEvent {
        sequence: 7,
        previous_hash: "a".repeat(64),
        payload_json: r#"{"type":"genesis"}"#.to_string(),
        session_id: Some("sess-1".to_string()),
        created_at: "2025-01-01T00:00:00.000000+00:00".to_string(),
    }
}

#[test]
fn chain_event_json_round_trips() {
    let event = sample_event();
    let json = serde_json::to_string(&event).unwrap();
    let back: ChainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sequence, event.sequence);
    assert_eq!(back.previous_hash, event.previous_hash);
    assert_eq!(back.payload_json, event.payload_json);
    assert_eq!(back.session_id, event.session_id);
    assert_eq!(back.created_at, event.created_at);
}

#[test]
fn chain_event_bincode_round_trips() {
    let event = sample_event();
    let bytes = bincode::serialize(&event).unwrap();
    let back: ChainEvent = bincode::deserialize(&bytes).unwrap();
    assert_eq!(back.sequence, event.sequence);
    assert_eq!(back.payload_json, event.payload_json);
}

#[test]
fn chain_event_without_session_round_trips_as_null() {
    let mut event = sample_event();
    event.session_id = None;
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"session_id\":null"));
    let back: ChainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.session_id, None);
}

#[test]
fn chain_event_missing_required_field_is_rejected() {
    let json = r#"{"sequence":1,"previous_hash":"ab","payload_json":"{}","session_id":null}"#;
    let err = serde_json::from_str::<ChainEvent>(json);
    assert!(err.is_err(), "missing created_at must fail to deserialize");
}

#[test]
fn chain_event_unknown_field_is_accepted() {
    // Unlike `ProposedIntent`, these guest/host protocol types carry no
    // `deny_unknown_fields`, so extra fields are silently ignored.
    let json = r#"{"sequence":1,"previous_hash":"ab","payload_json":"{}","session_id":null,"created_at":"t","extra_field":"surprise"}"#;
    let event: ChainEvent = serde_json::from_str(json).unwrap();
    assert_eq!(event.sequence, 1);
}

#[test]
fn guest_input_json_round_trips_with_multiple_events_and_patterns() {
    let input = GuestInput {
        anchor_previous_hash: "0".repeat(64),
        genesis_hash: "1".repeat(64),
        tip_hash: "2".repeat(64),
        merkle_root: "3".repeat(64),
        events: vec![sample_event(), sample_event()],
        policy_patterns: vec!["^rm\\s".to_string(), "secret".to_string()],
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: GuestInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.events.len(), 2);
    assert_eq!(back.policy_patterns, input.policy_patterns);
    assert_eq!(back.merkle_root, input.merkle_root);
}

#[test]
fn guest_input_with_empty_events_and_patterns_round_trips() {
    let input = GuestInput {
        anchor_previous_hash: String::new(),
        genesis_hash: String::new(),
        tip_hash: String::new(),
        merkle_root: String::new(),
        events: vec![],
        policy_patterns: vec![],
    };
    let bytes = bincode::serialize(&input).unwrap();
    let back: GuestInput = bincode::deserialize(&bytes).unwrap();
    assert!(back.events.is_empty());
    assert!(back.policy_patterns.is_empty());
}

#[test]
fn guest_output_round_trips_success_and_failure_shapes() {
    let success = GuestOutput {
        verified: true,
        event_count: 42,
        violations: vec![],
    };
    let json = serde_json::to_string(&success).unwrap();
    let back: GuestOutput = serde_json::from_str(&json).unwrap();
    assert!(back.verified);
    assert_eq!(back.event_count, 42);
    assert!(back.violations.is_empty());

    let failure = GuestOutput {
        verified: false,
        event_count: 3,
        violations: vec!["forbidden action: rm -rf /".to_string()],
    };
    let bytes = bincode::serialize(&failure).unwrap();
    let back: GuestOutput = bincode::deserialize(&bytes).unwrap();
    assert!(!back.verified);
    assert_eq!(back.violations.len(), 1);
}

#[test]
fn guest_output_missing_field_is_rejected() {
    let json = r#"{"verified":true,"event_count":1}"#;
    assert!(serde_json::from_str::<GuestOutput>(json).is_err());
}
