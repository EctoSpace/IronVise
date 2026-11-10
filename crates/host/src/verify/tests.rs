use super::*;
use std::path::PathBuf;

fn intent(action: &str, params: serde_json::Value, justification: &str) -> ProposedIntent {
    ProposedIntent {
        action: action.to_string(),
        params,
        justification: justification.to_string(),
        reasoning: "test".to_string(),
    }
}

/// The allowed root, canonicalised.
///
/// `validate_path_strict` resolves symlinks before comparing prefixes -
/// which is the point of it, since otherwise a symlink would walk straight
/// out of the allowed root. On macOS `/tmp` is a symlink to `/private/tmp`,
/// so a test that hardcodes `/tmp` as the prefix fails against its own
/// canonicalised path.
fn allowed_root() -> PathBuf {
    std::env::temp_dir()
        .canonicalize()
        .expect("temp dir canonicalises")
}

fn in_root(name: &str) -> String {
    allowed_root().join(name).to_string_lossy().into_owned()
}

/// Permissive tripwire: allows reads under the temp root and example.com,
/// bans `rm -rf`.
fn tripwire() -> Tripwire {
    Tripwire::new(
        vec![allowed_root()],
        vec!["example.com".to_string()],
        vec!["rm -rf".to_string()],
        10,
        true,
    )
}

fn ctx<'a>(tw: &'a Tripwire) -> EvaluationContext<'a> {
    EvaluationContext {
        policy: None,
        tripwire: tw,
        goal: "audit the host",
        step: 0,
        guard_required: false,
    }
}

/// The contract the hook and SDK surfaces depend on: no guard plus
/// `guard_required` is a denial, not a quiet allow.
#[tokio::test]
async fn a_required_guard_that_is_absent_denies() {
    let tw = tripwire();
    let mut c = ctx(&tw);
    c.guard_required = true;
    let v = evaluate_intent(
        &c,
        None,
        &intent(
            "read_file",
            serde_json::json!({ "path": in_root("a.txt") }),
            "Reading a permitted file for the audit.",
        ),
    )
    .await;
    match v {
        Verdict::Deny { stage, reason } => {
            assert_eq!(stage, DenyStage::GuardUnavailable);
            assert!(
                reason.contains("GUARD_REQUIRED"),
                "the reason must name the setting that caused it: {reason}"
            );
        }
        Verdict::Allow => panic!("an absent required guard must not allow"),
    }
}

/// …and the deterministic layers still refuse first, so the recorded reason
/// names the rule that actually applied rather than the missing guard.
#[tokio::test]
async fn a_tripwire_refusal_outranks_the_missing_guard() {
    let tw = tripwire();
    let mut c = ctx(&tw);
    c.guard_required = true;
    let v = evaluate_intent(
        &c,
        None,
        &intent(
            "run_command",
            serde_json::json!({ "command": "rm -rf /" }),
            "Cleaning up the working directory before the audit.",
        ),
    )
    .await;
    assert!(matches!(
        v,
        Verdict::Deny {
            stage: DenyStage::Tripwire,
            ..
        }
    ));
}

#[test]
fn coverage_names_the_layers_that_ran() {
    let full = Coverage::new(Some("abc".into()), true);
    assert_eq!(full.evaluated, ["policy", "tripwire", "guard"]);
    assert!(full.skipped.is_empty());

    let preflight = Coverage::new(None, false);
    assert_eq!(preflight.evaluated, ["tripwire"]);
    assert_eq!(preflight.skipped, ["policy", "guard"]);
    assert!(preflight.policy_hash.is_none());
}

#[tokio::test]
async fn a_permitted_action_is_allowed() {
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "read_file",
            serde_json::json!({ "path": in_root("a.txt") }),
            "Reading a permitted file for the audit.",
        ),
    )
    .await;
    assert_eq!(v, Verdict::Allow);
}

#[tokio::test]
async fn a_banned_command_is_denied_at_the_tripwire_stage() {
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "run_command",
            serde_json::json!({ "command": "rm -rf /" }),
            "Cleaning up temporary files after the audit.",
        ),
    )
    .await;
    match v {
        Verdict::Deny { stage, .. } => assert_eq!(stage, DenyStage::Tripwire),
        Verdict::Allow => panic!("a banned command was allowed"),
    }
}

#[tokio::test]
async fn a_path_outside_the_allowed_roots_is_denied() {
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "read_file",
            serde_json::json!({ "path": "/etc/shadow" }),
            "Reading a file to inspect its contents for the audit.",
        ),
    )
    .await;
    assert!(
        !v.is_allowed(),
        "a path outside the allowed roots was allowed"
    );
}

#[tokio::test]
async fn the_reason_is_carried_through_verbatim() {
    // An auditor reading the ledger needs the rule that fired, not a
    // generic "denied".
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "run_command",
            serde_json::json!({ "command": "rm -rf /var" }),
            "Removing files that the audit identified as stale.",
        ),
    )
    .await;
    match v {
        Verdict::Deny { reason, .. } => assert!(
            !reason.trim().is_empty(),
            "denial carried no reason, so the ledger entry would be useless"
        ),
        Verdict::Allow => panic!("expected a denial"),
    }
}

#[tokio::test]
async fn with_no_guard_configured_deterministic_checks_still_apply() {
    // Absence of a guard must not become absence of enforcement.
    let tw = tripwire();
    let allowed = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "read_file",
            serde_json::json!({ "path": in_root("ok") }),
            "Reading a permitted file for the audit.",
        ),
    )
    .await;
    let denied = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "read_file",
            serde_json::json!({ "path": "/etc/passwd" }),
            "Reading a file for the audit record.",
        ),
    )
    .await;
    assert!(allowed.is_allowed());
    assert!(!denied.is_allowed());
}

#[test]
fn guard_stages_are_distinguishable_from_deterministic_ones() {
    // Callers use this to decide between a guard_denial and a
    // tripwire_rejection ledger event; getting it wrong mislabels the
    // audit trail.
    assert!(DenyStage::Guard.is_guard());
    assert!(DenyStage::GuardUnavailable.is_guard());
    assert!(!DenyStage::Policy.is_guard());
    assert!(!DenyStage::Tripwire.is_guard());
}

#[test]
fn stage_identifiers_are_stable() {
    // These reach the ledger and the API; renaming one silently changes a
    // recorded audit trail's meaning.
    assert_eq!(DenyStage::Policy.as_str(), "policy");
    assert_eq!(DenyStage::Tripwire.as_str(), "tripwire");
    assert_eq!(DenyStage::Guard.as_str(), "guard");
    assert_eq!(DenyStage::GuardUnavailable.as_str(), "guard_unavailable");
}

#[tokio::test]
async fn complete_is_allowed() {
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent("complete", serde_json::json!({ "findings": [] }), ""),
    )
    .await;
    assert_eq!(v, Verdict::Allow);
}

#[tokio::test]
async fn unknown_action_is_denied_at_tripwire() {
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "write_file",
            serde_json::json!({}),
            "Writing a file for the audit.",
        ),
    )
    .await;
    match v {
        Verdict::Deny { stage, .. } => assert_eq!(stage, DenyStage::Tripwire),
        Verdict::Allow => panic!("unknown action was allowed"),
    }
}

#[tokio::test]
async fn http_without_tls_is_denied_when_https_is_required() {
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "http_get",
            serde_json::json!({ "url": "http://example.com/x" }),
            "Fetching a page for the audit record.",
        ),
    )
    .await;
    assert!(!v.is_allowed());
}

#[tokio::test]
async fn a_disallowed_https_host_is_denied() {
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "http_get",
            serde_json::json!({ "url": "https://evil.example.net/x" }),
            "Fetching a page for the audit record.",
        ),
    )
    .await;
    match v {
        Verdict::Deny { stage, .. } => assert_eq!(stage, DenyStage::Tripwire),
        Verdict::Allow => panic!("disallowed host was allowed"),
    }
}

#[tokio::test]
async fn a_permitted_https_host_is_allowed() {
    let tw = tripwire();
    let v = evaluate_intent(
        &ctx(&tw),
        None,
        &intent(
            "http_get",
            serde_json::json!({ "url": "https://api.example.com/v1" }),
            "Fetching a page for the audit record.",
        ),
    )
    .await;
    assert_eq!(v, Verdict::Allow);
}

struct DenyGuard;
struct BrokenGuard;
struct AllowGuard;

#[async_trait::async_trait]
impl crate::guard::GuardExecutor for DenyGuard {
    async fn evaluate(
        &mut self,
        _goal: &str,
        _proposed: &ProposedIntent,
    ) -> Result<crate::guard::GuardDecision, Box<dyn std::error::Error + Send + Sync>> {
        Ok(crate::guard::GuardDecision::Deny {
            reason: "off-goal".into(),
        })
    }
}

#[async_trait::async_trait]
impl crate::guard::GuardExecutor for BrokenGuard {
    async fn evaluate(
        &mut self,
        _goal: &str,
        _proposed: &ProposedIntent,
    ) -> Result<crate::guard::GuardDecision, Box<dyn std::error::Error + Send + Sync>> {
        Err("unreachable".into())
    }
}

#[async_trait::async_trait]
impl crate::guard::GuardExecutor for AllowGuard {
    async fn evaluate(
        &mut self,
        _goal: &str,
        _proposed: &ProposedIntent,
    ) -> Result<crate::guard::GuardDecision, Box<dyn std::error::Error + Send + Sync>> {
        Ok(crate::guard::GuardDecision::Allow)
    }
}

#[tokio::test]
async fn a_guard_deny_is_the_guard_stage() {
    let tw = tripwire();
    let mut guard = DenyGuard;
    let v = evaluate_intent(
        &ctx(&tw),
        Some(&mut guard),
        &intent(
            "read_file",
            serde_json::json!({ "path": in_root("ok") }),
            "Reading a permitted file for the audit.",
        ),
    )
    .await;
    match v {
        Verdict::Deny { stage, reason } => {
            assert_eq!(stage, DenyStage::Guard);
            assert_eq!(reason, "off-goal");
        }
        Verdict::Allow => panic!("guard deny was allowed"),
    }
}

#[tokio::test]
async fn a_broken_guard_is_fail_closed() {
    let tw = tripwire();
    let mut guard = BrokenGuard;
    let v = evaluate_intent(
        &ctx(&tw),
        Some(&mut guard),
        &intent(
            "read_file",
            serde_json::json!({ "path": in_root("ok") }),
            "Reading a permitted file for the audit.",
        ),
    )
    .await;
    match v {
        Verdict::Deny { stage, .. } => assert_eq!(stage, DenyStage::GuardUnavailable),
        Verdict::Allow => panic!("unreachable guard must not allow"),
    }
}

#[tokio::test]
async fn an_allowing_guard_cannot_override_the_tripwire() {
    let tw = tripwire();
    let mut guard = AllowGuard;
    let v = evaluate_intent(
        &ctx(&tw),
        Some(&mut guard),
        &intent(
            "run_command",
            serde_json::json!({ "command": "rm -rf /" }),
            "Cleaning up temporary files after the audit.",
        ),
    )
    .await;
    match v {
        Verdict::Deny { stage, .. } => assert_eq!(stage, DenyStage::Tripwire),
        Verdict::Allow => panic!("guard allow must not bypass a banned command"),
    }
}
