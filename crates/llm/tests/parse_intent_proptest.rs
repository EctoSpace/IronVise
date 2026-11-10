//! Property tests for the shared model-output parser.
//!
//! These pin that `parse_intent_repairing_justification` and
//! `strip_markdown_fences` never panic on adversarial or truncated input, and
//! that a successful repair never silently edits a justification the model
//! already supplied.

use ectoledger_llm::{parse_intent_repairing_justification, strip_markdown_fences};
use proptest::prelude::*;
use serde_json::json;

const ALLOWED_ACTIONS: [&str; 4] = ["run_command", "read_file", "http_get", "complete"];

/// A complete, valid intent object as the agent schema expects it.
fn valid_intent_json(action: &str, justification: &str, reasoning: &str) -> String {
    json!({
        "action": action,
        "params": {},
        "justification": justification,
        "reasoning": reasoning,
    })
    .to_string()
}

fn assert_ok_contract(action: &str, justification: &str) {
    assert!(
        ALLOWED_ACTIONS.contains(&action),
        "unexpected action {action:?}"
    );
    assert!(
        !justification.trim().is_empty(),
        "justification must be non-empty after repair"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn parse_intent_never_panics_on_arbitrary_strings(s in ".*") {
        let _ = parse_intent_repairing_justification(&s);
    }

    #[test]
    fn strip_markdown_fences_never_panics_on_arbitrary_strings(s in ".*") {
        let _ = strip_markdown_fences(&s);
    }

    #[test]
    fn parse_intent_never_panics_on_arbitrary_json_values(v in arb_json_value(4, 24)) {
        let raw = v.to_string();
        let _ = parse_intent_repairing_justification(&raw);
    }

    #[test]
    fn parse_intent_never_panics_on_fenced_prose_or_think_wrappers(
        action in prop::sample::select(&ALLOWED_ACTIONS),
        justification in "[A-Za-z0-9 .,;:!?'-]{5,40}",
        wrapper in 0u8..5,
    ) {
        let body = valid_intent_json(action, &justification, "step serves the goal");
        let wrapped = match wrapper {
            0 => format!("```json\n{body}\n```"),
            1 => format!("```\n{body}\n```"),
            2 => format!("Here is the answer:\n```json\n{body}\n```"),
            3 => format!("<think>planning</think>\n{body}"),
            _ => format!("Sure.\n\n{body}\n\nThanks."),
        };
        let parsed = parse_intent_repairing_justification(&wrapped);
        // A fenced intent with nothing around it is what models send most;
        // it must parse to exactly what was written.
        if wrapper < 2 {
            let intent = parsed.expect("a fenced intent parses");
            prop_assert_eq!(intent.action, action);
            prop_assert_eq!(intent.justification, justification);
        }
    }

    #[test]
    fn parse_intent_never_panics_on_truncated_prefixes_of_valid_intents(
        action in prop::sample::select(&ALLOWED_ACTIONS),
        cut in 0usize..120,
    ) {
        let full = valid_intent_json(action, "Need enough chars here.", "because");
        let prefix: String = full.chars().take(cut.min(full.chars().count())).collect();
        let _ = parse_intent_repairing_justification(&prefix);
    }

    #[test]
    fn parse_intent_never_panics_on_huge_but_bounded_input(
        pad in prop::collection::vec(any::<u8>(), 0..8_192),
    ) {
        // Bounded noise around a tiny object: large enough to stress the
        // fence trimmer, small enough for the suite to stay fast.
        let noise = String::from_utf8_lossy(&pad);
        let raw = format!("{noise}{{\"action\":\"complete\",\"params\":{{}}}}{noise}");
        let _ = parse_intent_repairing_justification(&raw);
    }

    #[test]
    fn a_successful_parse_of_a_documented_intent_keeps_action_and_nonempty_justification(
        action in prop::sample::select(&ALLOWED_ACTIONS),
        justification in "[A-Za-z0-9 .,;:!?'-]{5,60}",
        fence in prop::bool::ANY,
    ) {
        let body = valid_intent_json(action, &justification, "how this step serves the goal");
        let raw = if fence {
            format!("```json\n{body}\n```")
        } else {
            body
        };
        let intent = parse_intent_repairing_justification(&raw).expect("valid intent");
        assert_ok_contract(&intent.action, &intent.justification);
        prop_assert_eq!(intent.action, action);
        prop_assert_eq!(intent.justification, justification);
    }

    #[test]
    fn a_model_supplied_justification_is_never_overwritten(
        action in prop::sample::select(&ALLOWED_ACTIONS),
        justification in "[A-Za-z0-9 .,;:!?'-]{1,80}",
        reasoning in ".{0,80}",
    ) {
        // Any non-whitespace justification must survive even when reasoning
        // is longer or more specific - the repair fills gaps, it does not edit.
        prop_assume!(!justification.trim().is_empty());
        let body = valid_intent_json(action, &justification, &reasoning);
        let intent = parse_intent_repairing_justification(&body).expect("parses");
        prop_assert_eq!(&intent.justification, &justification);
    }

    #[test]
    fn empty_justification_is_repaired_to_something_nonempty(
        action in prop::sample::select(&ALLOWED_ACTIONS),
        reasoning in prop::option::of("[A-Za-z0-9 .,;:!?'-]{0,40}"),
        blank in prop::sample::select(vec!["", "   ", "\t\n"]),
    ) {
        let mut obj = json!({
            "action": action,
            "params": {},
            "justification": blank,
        });
        if let Some(r) = reasoning {
            obj["reasoning"] = json!(r);
        }
        let intent = parse_intent_repairing_justification(&obj.to_string()).expect("parses");
        prop_assert!(!intent.justification.trim().is_empty());
        prop_assert_eq!(intent.action, action);
    }
}

/// Recursively build JSON values with a hard depth/width budget so the
/// generator cannot explode memory or trip an unbounded serde recursion.
fn arb_json_value(max_depth: u32, max_width: usize) -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i32>().prop_map(|n| json!(n)),
        "[ -~]{0,32}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(max_depth, 256, max_width as u32, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..max_width).prop_map(serde_json::Value::Array),
            prop::collection::hash_map("[A-Za-z_]{1,12}", inner, 0..max_width).prop_map(|map| {
                let mut obj = serde_json::Map::new();
                for (k, v) in map {
                    obj.insert(k, v);
                }
                serde_json::Value::Object(obj)
            }),
        ]
    })
}

#[test]
fn deeply_nested_json_does_not_panic_the_parser() {
    // Nest past typical comfort but within a size bound; serde may reject
    // deep recursion with an error - that is fine, panicking is not.
    let mut v = json!({"action": "complete", "params": {}});
    for _ in 0..64 {
        v = json!({ "outer": v });
    }
    let _ = parse_intent_repairing_justification(&v.to_string());
}

#[test]
fn leading_think_tags_around_valid_json_do_not_panic() {
    let body = valid_intent_json(
        "complete",
        "All planned checks done.",
        "Sufficient evidence gathered.",
    );
    let raw = format!("<think>internal monologue</think>\n{body}");
    // Current stripper only recognises a leading markdown fence, so this may
    // be InvalidJson - the contract under test is "no panic".
    let _ = parse_intent_repairing_justification(&raw);
}
