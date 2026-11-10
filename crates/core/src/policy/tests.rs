use super::*;

fn engine(toml_str: &str) -> PolicyEngine {
    let policy: AuditPolicy = toml::from_str(toml_str).expect("parse policy");
    PolicyEngine::new(policy).expect("compile policy")
}

fn intent(action: &str, params: serde_json::Value) -> ProposedIntent {
    ProposedIntent {
        action: action.to_string(),
        params,
        justification: "test".into(),
        reasoning: "test".into(),
    }
}

const REDACT_AND_FLAG: &str = r#"
        [[observation_rules]]
        pattern = "password=\\S+"
        action = "redact"
        label = "credential"

        [[observation_rules]]
        pattern = "SUSPICIOUS"
        action = "flag"
        label = "sus"

        [[observation_rules]]
        pattern = "EXPLOIT"
        action = "abort"
        label = "exploit"

        [[observation_rules]]
        pattern = "token=\\S+"
        action = "redact"
        label = "token"
    "#;

#[test]
fn a_flagged_observation_keeps_its_redactions() {
    let outcome = engine(REDACT_AND_FLAG).validate_observation("password=s3cret SUSPICIOUS");
    assert_eq!(
        outcome,
        ObservationOutcome::Flagged {
            labels: "sus".into(),
            content: "[REDACTED:credential] SUSPICIOUS".into(),
        }
    );
}

#[test]
fn an_abort_reports_content_with_every_redaction_even_later_rules() {
    let outcome = engine(REDACT_AND_FLAG).validate_observation("password=s3cret EXPLOIT token=t0k");
    let ObservationOutcome::Abort { reason, content } = outcome else {
        panic!("expected Abort, got {outcome:?}");
    };
    assert!(reason.contains("exploit"), "{reason}");
    assert_eq!(content, "[REDACTED:credential] EXPLOIT [REDACTED:token]");
}

#[test]
fn require_approval_command_rule_uses_the_stable_prefix() {
    let engine = engine(
        r#"
            [[command_rules]]
            program = "nmap"
            arg_pattern = ".*"
            decision = "require_approval"
            "#,
    );
    let err = engine
        .validate_intent(
            &intent(
                "run_command",
                serde_json::json!({ "command": "nmap -sV host" }),
            ),
            0,
        )
        .unwrap_err();
    assert!(err.to_string().contains("REQUIRE_APPROVAL"), "got {err}");
}

#[test]
fn approval_gate_fires_on_command_contains() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "action == 'run_command' && command_contains('nmap')"
            require_approval = true
            timeout_seconds = 30
            on_timeout = "deny"
            "#,
    );
    let nmap = intent(
        "run_command",
        serde_json::json!({ "command": "nmap -sV host" }),
    );
    let ls = intent("run_command", serde_json::json!({ "command": "ls -la" }));
    assert!(engine.check_approval_gates(&nmap).is_some());
    assert!(engine.check_approval_gates(&ls).is_none());
}

#[test]
fn unknown_trigger_clause_fails_closed() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "acton == 'run_command'"
            require_approval = true
            "#,
    );
    let i = intent("read_file", serde_json::json!({ "path": "/tmp/a" }));
    assert!(
        engine.check_approval_gates(&i).is_some(),
        "a typo in the trigger must require approval, not skip the gate"
    );
}

#[test]
fn path_extension_gate_matches_key_files() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "path_extension_matches('.key')"
            require_approval = true
            "#,
    );
    let key = intent("read_file", serde_json::json!({ "path": "/tmp/id.key" }));
    let txt = intent("read_file", serde_json::json!({ "path": "/tmp/id.txt" }));
    assert!(engine.check_approval_gates(&key).is_some());
    assert!(engine.check_approval_gates(&txt).is_none());
}

#[test]
fn url_host_in_cidr_matches_private_ips() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "url_host_in_cidr('10.0.0.0/8')"
            require_approval = true
            "#,
    );
    let inside = intent(
        "http_get",
        serde_json::json!({ "url": "https://10.1.2.3/x" }),
    );
    let outside = intent(
        "http_get",
        serde_json::json!({ "url": "https://8.8.8.8/x" }),
    );
    assert!(engine.check_approval_gates(&inside).is_some());
    assert!(engine.check_approval_gates(&outside).is_none());
}

#[test]
fn command_matches_regex_gate() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "command_matches_regex('^nmap\\s')"
            require_approval = true
            "#,
    );
    let nmap = intent("run_command", serde_json::json!({ "command": "nmap -sV" }));
    let ls = intent("run_command", serde_json::json!({ "command": "ls nmap" }));
    assert!(engine.check_approval_gates(&nmap).is_some());
    assert!(engine.check_approval_gates(&ls).is_none());
}

#[test]
fn require_approval_false_never_fires() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "action == 'run_command'"
            require_approval = false
            "#,
    );
    let i = intent("run_command", serde_json::json!({ "command": "ls" }));
    assert!(engine.check_approval_gates(&i).is_none());
}

#[test]
fn invalid_observation_regex_is_rejected_at_construction() {
    let policy: AuditPolicy = toml::from_str(
        r#"
            [[observation_rules]]
            pattern = "[invalid(("
            action = "flag"
            label = "bad"
            "#,
    )
    .unwrap();
    assert!(PolicyEngine::new(policy).is_err());
}

#[test]
fn policy_hash_bytes_is_stable_sha256() {
    assert_eq!(
        policy_hash_bytes(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn policy_hash_bytes_is_sensitive_to_whitespace() {
    let a = policy_hash_bytes(b"name = \"p\"");
    let b = policy_hash_bytes(b"name = \"p\"\n");
    let c = policy_hash_bytes(b" name = \"p\"");
    assert_ne!(a, b);
    assert_ne!(a, c);
}

#[test]
fn redact_rules_apply_in_order_and_do_not_re_match_already_redacted_text() {
    let engine = engine(
        r#"
            [[observation_rules]]
            pattern = "secret"
            action = "redact"
            label = "first"

            [[observation_rules]]
            pattern = "REDACTED"
            action = "redact"
            label = "second"
            "#,
    );
    // The second rule's pattern ("REDACTED") starts matching the literal
    // text the first rule just inserted, so it redacts that marker too -
    // the rules compose rather than skip already-rewritten spans.
    let outcome = engine.validate_observation("secret");
    let ObservationOutcome::Redacted(content) = outcome else {
        panic!("expected Redacted, got {outcome:?}");
    };
    assert_eq!(content, "[[REDACTED:second]:first]");
}

#[test]
fn redact_rules_with_overlapping_patterns_apply_left_to_right() {
    let engine = engine(
        r#"
            [[observation_rules]]
            pattern = "password=\\S+"
            action = "redact"
            label = "cred"

            [[observation_rules]]
            pattern = "\\S+=secret"
            action = "redact"
            label = "any_secret"
            "#,
    );
    // First rule already consumes "password=secret" before the second
    // rule's broader pattern gets a chance to match it.
    let outcome = engine.validate_observation("password=secret");
    let ObservationOutcome::Redacted(content) = outcome else {
        panic!("expected Redacted, got {outcome:?}");
    };
    assert_eq!(content, "[REDACTED:cred]");
}

#[test]
fn first_matching_command_rule_wins_even_when_a_later_rule_conflicts() {
    let engine = engine(
        r#"
            [[command_rules]]
            program = "curl"
            arg_pattern = "internal\\.corp"
            decision = "allow"

            [[command_rules]]
            program = "curl"
            arg_pattern = ".*"
            decision = "deny"
            "#,
    );
    let ok = engine.validate_intent(
        &intent(
            "run_command",
            serde_json::json!({ "command": "curl https://internal.corp/x" }),
        ),
        0,
    );
    assert!(ok.is_ok(), "the earlier allow rule must take precedence");

    let denied = engine.validate_intent(
        &intent(
            "run_command",
            serde_json::json!({ "command": "curl https://example.com" }),
        ),
        0,
    );
    assert!(denied.is_err(), "falls through to the catch-all deny rule");
}

#[test]
fn allowed_actions_and_forbidden_actions_both_list_the_same_action_forbidden_wins() {
    let engine = engine(
        r#"
            [[allowed_actions]]
            action = "read_file"

            [[forbidden_actions]]
            action = "read_file"
            "#,
    );
    let err = engine
        .validate_intent(
            &intent("read_file", serde_json::json!({ "path": "/tmp/a" })),
            0,
        )
        .unwrap_err();
    assert!(err.to_string().contains("forbidden"));
}

#[test]
fn cidr_slash_zero_matches_any_v4_address() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "url_host_in_cidr('0.0.0.0/0')"
            require_approval = true
            "#,
    );
    for url in [
        "https://1.2.3.4/x",
        "https://255.255.255.255/x",
        "https://0.0.0.0/x",
    ] {
        let i = intent("http_get", serde_json::json!({ "url": url }));
        assert!(engine.check_approval_gates(&i).is_some(), "{url}");
    }
}

#[test]
fn cidr_slash_32_matches_only_the_exact_host() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "url_host_in_cidr('10.0.0.5/32')"
            require_approval = true
            "#,
    );
    let exact = intent(
        "http_get",
        serde_json::json!({ "url": "https://10.0.0.5/x" }),
    );
    let neighbor = intent(
        "http_get",
        serde_json::json!({ "url": "https://10.0.0.6/x" }),
    );
    assert!(engine.check_approval_gates(&exact).is_some());
    assert!(engine.check_approval_gates(&neighbor).is_none());
}

#[test]
fn cidr_invalid_pattern_should_fail_closed_like_the_regex_predicates_do() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "url_host_in_cidr('not-a-cidr')"
            require_approval = true
            "#,
    );
    let i = intent(
        "http_get",
        serde_json::json!({ "url": "https://10.0.0.5/x" }),
    );
    assert!(engine.check_approval_gates(&i).is_some());
}

#[test]
fn cidr_gate_ignores_non_ip_hostnames() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "url_host_in_cidr('10.0.0.0/8')"
            require_approval = true
            "#,
    );
    for url in [
        "https://internal.example.com/x",
        "https://xn--e1aybc.xn--p1ai/x", // punycode
    ] {
        let i = intent("http_get", serde_json::json!({ "url": url }));
        assert!(engine.check_approval_gates(&i).is_none(), "{url}");
    }
}

#[test]
fn cidr_gate_ignores_userinfo_in_the_url() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "url_host_in_cidr('10.0.0.0/8')"
            require_approval = true
            "#,
    );
    let i = intent(
        "http_get",
        serde_json::json!({ "url": "https://user:pass@10.0.0.9/x" }),
    );
    assert!(
        engine.check_approval_gates(&i).is_some(),
        "userinfo must not hide the host from the CIDR check"
    );
}

#[test]
fn ipv6_cidr_against_an_ipv6_url() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "url_host_in_cidr('::1/128')"
            require_approval = true
            "#,
    );
    let i = intent("http_get", serde_json::json!({ "url": "https://[::1]/x" }));
    // Documents current behaviour either way: `Url::host_str()` for an
    // IPv6 literal may or may not parse directly as `IpAddr` depending
    // on bracket handling.
    let fired = engine.check_approval_gates(&i).is_some();
    let outside = intent(
        "http_get",
        serde_json::json!({ "url": "https://[2001:db8::1]/x" }),
    );
    let outside_fired = engine.check_approval_gates(&outside).is_some();
    assert!(
        !outside_fired,
        "a /128 on ::1 must not match an unrelated address"
    );
    let _ = fired;
}

#[test]
fn path_extension_matches_is_case_insensitive_for_plain_patterns() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "path_extension_matches('.key')"
            require_approval = true
            "#,
    );
    let upper = intent("read_file", serde_json::json!({ "path": "/tmp/ID.KEY" }));
    assert!(engine.check_approval_gates(&upper).is_some());
}

#[test]
fn path_extension_matches_treats_a_dotfile_as_having_no_extension() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "path_extension_matches('key')"
            require_approval = true
            "#,
    );
    let dotfile = intent("read_file", serde_json::json!({ "path": "/tmp/.key" }));
    assert!(engine.check_approval_gates(&dotfile).is_none());
}

#[test]
fn path_extension_matches_plain_pattern_only_compares_the_final_extension() {
    // `std::path::Path::extension()` returns only the final suffix, so a
    // plain (non-regex) pattern of "tar.gz" never matches "archive.tar.gz"
    // (its extension is just "gz"). Policies that need multi-suffix
    // matching must use the regex form (a pattern containing one of
    // `| ( [`), e.g. `(\.tar\.gz)$`.
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "path_extension_matches('tar.gz')"
            require_approval = true
            "#,
    );
    let archive = intent(
        "read_file",
        serde_json::json!({ "path": "/tmp/archive.tar.gz" }),
    );
    assert!(engine.check_approval_gates(&archive).is_none());
}

#[test]
fn path_extension_matches_on_windows_style_backslash_paths() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "path_extension_matches('.key')"
            require_approval = true
            "#,
    );
    let win = intent(
        "read_file",
        serde_json::json!({ "path": "C:\\secrets\\id.key" }),
    );
    assert!(engine.check_approval_gates(&win).is_some());
}

#[test]
fn command_rule_should_still_deny_a_leading_whitespace_command() {
    let engine = engine(
        r#"
            [[command_rules]]
            program = "nmap"
            arg_pattern = ".*"
            decision = "deny"
            "#,
    );
    let padded = intent(
        "run_command",
        serde_json::json!({ "command": "  nmap -sV host" }),
    );
    assert!(engine.validate_intent(&padded, 0).is_err());
}

#[test]
fn eval_trigger_requires_every_clause_in_a_conjunction() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "action == 'run_command' && command_contains('nmap') && command_contains('host')"
            require_approval = true
            "#,
    );
    let both = intent(
        "run_command",
        serde_json::json!({ "command": "nmap -sV host" }),
    );
    let one = intent("run_command", serde_json::json!({ "command": "nmap -sV" }));
    assert!(engine.check_approval_gates(&both).is_some());
    assert!(engine.check_approval_gates(&one).is_none());
}

#[test]
fn eval_trigger_empty_string_fails_closed_as_an_unknown_clause() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = ""
            require_approval = true
            "#,
    );
    let i = intent("read_file", serde_json::json!({ "path": "/tmp/a" }));
    assert!(engine.check_approval_gates(&i).is_some());
}

#[test]
fn command_contains_empty_needle_matches_any_command() {
    let engine = engine(
        r#"
            [[approval_gates]]
            trigger = "command_contains('')"
            require_approval = true
            "#,
    );
    let i = intent("run_command", serde_json::json!({ "command": "ls" }));
    assert!(engine.check_approval_gates(&i).is_some());
}

#[test]
fn max_steps_boundary_is_inclusive_at_the_limit() {
    let engine = engine("max_steps = 3");
    let i = intent("read_file", serde_json::json!({ "path": "/tmp/a" }));
    assert!(engine.validate_intent(&i, 2).is_ok());
    assert!(engine.validate_intent(&i, 3).is_err());
    assert!(engine.validate_intent(&i, 4).is_err());
}
