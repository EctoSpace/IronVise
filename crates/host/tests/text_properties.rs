//! Arbitrary text through every public path that cuts, scans or embeds it.
//!
//! Observations, commands and chat messages are whatever a tool or a model
//! produced. A byte slice that lands inside a multi-byte character panics, and
//! two such slices have been found and fixed; these properties keep the rest
//! from hiding one.

use chrono::Utc;
use ectoledger::intent::ProposedIntent;
use ectoledger::output_scanner::{ScannerSensitivity, scan_observation_with_sensitivity};
use ectoledger::schema::{EventPayload, LedgerEventRow, RestoredState};
use ectoledger::tripwire::Tripwire;
use proptest::prelude::*;

/// Unicode text weighted towards multi-byte characters and the lengths at
/// which the code cuts (80, 120, 200, 4096 and so on).
fn text() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        Just("a".to_string()),
        Just("é".to_string()),
        Just("日本".to_string()),
        Just("🦀".to_string()),
        Just("\u{200b}".to_string()),
        Just("\n".to_string()),
        any::<char>().prop_map(String::from),
    ];
    proptest::collection::vec(piece, 0..1200).prop_map(|pieces| pieces.concat())
}

fn observation_row(sequence: i64, content: String) -> LedgerEventRow {
    LedgerEventRow {
        id: sequence,
        sequence,
        previous_hash: String::new(),
        content_hash: String::new(),
        payload: EventPayload::Observation { content },
        created_at: Utc::now(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn the_output_scanner_never_panics_at_any_sensitivity(content in text()) {
        for sensitivity in [ScannerSensitivity::Low, ScannerSensitivity::Medium, ScannerSensitivity::High] {
            let _ = scan_observation_with_sensitivity(&content, sensitivity);
        }
    }

    #[test]
    fn the_tripwire_never_panics_on_any_command_path_or_url(value in text(), justification in text()) {
        let tripwire = Tripwire::new(vec![std::path::PathBuf::from("/")], vec![], vec![], 0, false);
        for (action, key) in [("run_command", "command"), ("read_file", "path"), ("http_get", "url")] {
            let intent = ProposedIntent {
                action: action.to_string(),
                params: serde_json::json!({ key: value }),
                justification: justification.clone(),
                reasoning: String::new(),
            };
            let _ = tripwire.validate(&intent);
        }
    }

    #[test]
    fn a_webhook_preview_is_at_most_200_characters_of_the_text(content in text()) {
        let preview = ectoledger::webhook::preview(&content);
        prop_assert!(preview.chars().count() <= 200);
        prop_assert!(content.starts_with(&preview));
    }

    #[test]
    fn the_agent_prompt_embeds_any_observation_without_panicking(contents in proptest::collection::vec(text(), 0..6)) {
        let state = RestoredState {
            snapshot_sequence: 0,
            snapshot_payload: serde_json::Value::Null,
            replayed_events: contents
                .into_iter()
                .enumerate()
                .map(|(i, c)| observation_row(i as i64 + 1, c))
                .collect(),
        };
        let _ = ectoledger::llm::state_to_prompt(&state, 50);
    }

    #[test]
    fn sandbox_output_is_trimmed_on_a_character_boundary(content in text(), max in 0usize..5000) {
        let trimmed = ectoledger_sandbox::output::trim_to_max(&content, max);
        let kept = trimmed.strip_suffix("...").unwrap_or(&trimmed);
        prop_assert!(content.starts_with(kept));
    }
}
