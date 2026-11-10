use super::*;
use crate::schema::LedgerEventRow;

fn row(sequence: i64, payload: EventPayload) -> LedgerEventRow {
    LedgerEventRow {
        id: sequence,
        sequence,
        previous_hash: String::new(),
        content_hash: String::new(),
        payload,
        created_at: chrono::Utc::now(),
    }
}

/// A finding cites observations by ledger sequence number, and the ledger is
/// shared by every session, so a session's first observation is rarely #3.
/// The prompt has to show the numbers the evidence check compares against.
#[test]
fn every_event_is_shown_with_the_sequence_a_finding_cites() {
    let state = RestoredState {
        snapshot_sequence: 0,
        snapshot_payload: serde_json::Value::Null,
        replayed_events: vec![
            row(
                9041,
                EventPayload::Action {
                    name: "read_file".into(),
                    params: serde_json::json!({ "path": "/srv/nginx.conf" }),
                },
            ),
            row(
                9042,
                EventPayload::Observation {
                    content: "ssl_protocols TLSv1 TLSv1.3;".into(),
                },
            ),
        ],
    };
    let prompt = state_to_prompt(&state, 50);
    assert!(prompt.contains("  #9041 [action] read_file"), "{prompt}");
    assert!(
        prompt.contains("  #9042 [observation] ssl_protocols TLSv1 TLSv1.3;"),
        "{prompt}"
    );
}
