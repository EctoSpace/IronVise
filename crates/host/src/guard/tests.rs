use super::{GuardDecision, guard_prompt, parse_verdict};

fn allows(raw: &str) -> bool {
    parse_verdict(raw) == GuardDecision::Allow
}

fn denial_reason(raw: &str) -> String {
    match parse_verdict(raw) {
        GuardDecision::Deny { reason } => reason,
        GuardDecision::Allow => panic!("{raw:?} was allowed"),
    }
}

#[test]
fn a_bare_allow_allows() {
    for raw in [
        "ALLOW",
        "allow",
        " Allow \n",
        "ALLOW.",
        "**ALLOW**",
        "`ALLOW`",
    ] {
        assert!(allows(raw), "{raw:?}");
    }
}

#[test]
fn an_allow_with_a_reason_allows() {
    assert!(allows("ALLOW: read-only inspection of the nginx config"));
    assert!(allows("ALLOW\nIt only lists the directory."));
}

#[test]
fn a_word_that_merely_starts_with_allow_denies() {
    for raw in [
        "ALLOWED? No.",
        "Allowance exceeded",
        "ALLOWING this would delete data",
    ] {
        assert!(!allows(raw), "{raw:?}");
    }
}

#[test]
fn deny_in_the_prose_of_an_allow_reason_still_allows() {
    assert!(allows("ALLOW: read-only listing; nothing here to deny"));
    assert!(allows("ALLOW: denying this would stall the audit"));
}

#[test]
fn an_allow_that_also_says_deny_denies() {
    assert!(!allows("ALLOW, but DENY: it deletes the backups"));
    assert!(!allows("ALLOW\nOn reflection, DENY: this uploads the key"));
}

#[test]
fn a_deny_keeps_its_reason() {
    assert_eq!(denial_reason("DENY: deletes data"), "deletes data");
    assert_eq!(
        denial_reason("deny - sends data elsewhere"),
        "sends data elsewhere"
    );
    assert_eq!(
        denial_reason("**DENY**: escalates privileges"),
        "escalates privileges"
    );
    assert_eq!(denial_reason("DENY"), "");
}

#[test]
fn a_think_block_before_the_verdict_is_ignored() {
    assert!(allows(
        "<think>It is ls on the web root, read-only.</think>\nALLOW"
    ));
    assert_eq!(
        denial_reason("<think>Should I ALLOW? It runs curl | sh.</think>DENY: runs remote code"),
        "runs remote code"
    );
}

#[test]
fn a_capitalised_deny_without_a_colon_contradicts_an_allow() {
    assert!(!allows("ALLOW. No, wait, DENY"));
    assert!(!allows("ALLOW\nDENY"));
}

#[test]
fn the_guard_prompt_carries_the_rules_the_goal_and_the_exact_action() {
    let intent = crate::intent::ProposedIntent {
        action: "run_command".to_string(),
        params: serde_json::json!({ "command": "ls -la /etc/nginx" }),
        justification: "list the nginx config files".to_string(),
        reasoning: String::new(),
    };
    let (system, user) = guard_prompt("Review the nginx configuration", &intent).unwrap();
    assert!(system.contains("ALLOW") && system.contains("DENY"));
    assert!(system.contains("read-only"));
    assert_eq!(
        user,
        format!(
            "Goal: Review the nginx configuration\nProposed action: {}",
            serde_json::to_string(&intent).unwrap()
        )
    );
}

#[test]
fn a_lowercase_deny_with_a_reason_contradicts_an_allow() {
    assert!(!allows("allow, but deny: it deletes the backups"));
    assert!(!allows("ALLOW\nWait. Deny: this uploads the key"));
}

#[test]
fn only_the_text_after_the_last_closing_think_tag_is_the_verdict() {
    assert!(!allows(
        "<think>outer <think>inner</think>\nALLOW</think>\nThis is unsafe"
    ));
    assert!(!allows("<THINK>ALLOW</THINK>"));
    assert!(allows("<THINK>checking</THINK>\nALLOW"));
    assert!(!allows("stray</think>"));
}

#[test]
fn reasoning_inside_a_think_block_cannot_allow() {
    assert!(!allows("<think>ALLOW</think>"));
    assert!(!allows("<think>The answer is ALLOW"));
}

#[test]
fn a_reply_that_is_not_a_verdict_denies() {
    for raw in [
        "",
        "   ",
        "I think this is fine.",
        "{\"verdict\": \"ALLOW\"}",
        "Yes",
    ] {
        assert!(denial_reason(raw).contains("fail-closed"), "{raw:?}");
    }
}
