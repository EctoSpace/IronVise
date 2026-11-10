use ectoledger_core::{
    hash::*,
    intent::ProposedIntent,
    merkle,
    policy::{AuditPolicy, PolicyEngine},
    schema::ChainEvent,
};
use proptest::prelude::*;
use serde_json::{Value, json};

const TS: &str = "2026-01-01T00:00:00.123456+00:00";

fn text() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..48).prop_map(|v| v.into_iter().collect())
}

fn json_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<i32>().prop_map(|n| Value::from(f64::from(n) / 2.0)),
        text().prop_map(Value::String)
    ]
    .prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            proptest::collection::btree_map(text(), inner, 0..8)
                .prop_map(|m| Value::Object(m.into_iter().collect()))
        ]
    })
}

fn intent() -> impl Strategy<Value = ProposedIntent> {
    let action = prop_oneof![
        text(),
        Just("run_command".to_string()),
        Just("read_file".to_string()),
        Just("http_get".to_string()),
    ];
    let shaped_params = (text(), text(), text(), json_value()).prop_map(|(command, path, url, extra)| {
        json!({ "command": command, "path": path, "url": url, "extra": extra })
    });
    let params = prop_oneof![json_value(), shaped_params];
    (action, params, text(), text()).prop_map(|(action, params, justification, reasoning)| {
        ProposedIntent {
            action,
            params,
            justification,
            reasoning,
        }
    })
}

fn digest(e: &ChainEvent) -> String {
    compute_content_hash_v2(
        &e.previous_hash,
        e.sequence,
        &e.payload_json,
        e.session_id.as_deref(),
        &e.created_at,
    )
}

fn first_failure(events: &[(ChainEvent, String)]) -> Option<usize> {
    let mut previous = GENESIS_PREVIOUS_HASH;
    for (i, (e, stored)) in events.iter().enumerate() {
        if e.previous_hash != previous
            || verify_content_hash_any_scheme(
                &e.previous_hash,
                e.sequence,
                &e.payload_json,
                e.session_id.as_deref(),
                Some(&e.created_at),
                stored,
            ) != Some(HashScheme::V2)
        {
            return Some(i);
        }
        previous = stored;
    }
    None
}

fn policy(source: &str) -> PolicyEngine {
    PolicyEngine::new(toml::from_str::<AuditPolicy>(source).unwrap()).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn equal_inputs_hash_identically_and_each_bound_field_changes_the_hash(
        payload in json_value(), sequence in any::<i64>(), previous in "[0-9a-f]{64}",
        sid in proptest::option::of("[0-9a-f]{8}-1234-1234-1234-123456789abc"), micros in 0..1_000_000u32
    ) {
        let e = ChainEvent { sequence, previous_hash: previous, payload_json: payload.to_string(), session_id: sid, created_at: format!("2026-01-01T00:00:00.{micros:06}+00:00") };
        let hash = digest(&e);
        prop_assert_eq!(&hash, &digest(&e.clone()));
        let expected = format!("ELv2\0{}\0{}\0{}\0{}\0{}", e.previous_hash, e.sequence, e.payload_json, e.session_id.as_deref().unwrap_or(""), e.created_at);
        prop_assert_eq!(content_hash_input_v2(&e.previous_hash,e.sequence,&e.payload_json,e.session_id.as_deref(),&e.created_at), expected.into_bytes());
        for field in 0..5 {
            let mut changed = e.clone();
            match field {
                0 => changed.previous_hash.replace_range(..1, if e.previous_hash.starts_with('0') { "1" } else { "0" }),
                1 => changed.sequence = sequence.wrapping_add(1),
                2 => changed.payload_json = json!([payload, null]).to_string(),
                3 => changed.session_id = if e.session_id.is_some() { None } else { Some("12345678-1234-1234-1234-123456789abc".into()) },
                _ => changed.created_at.replace_range(..4, "2027"),
            }
            prop_assert_ne!(&hash, &digest(&changed));
            prop_assert_eq!(verify_content_hash_any_scheme(&changed.previous_hash,changed.sequence,&changed.payload_json,changed.session_id.as_deref(),Some(&changed.created_at),&hash), None);
        }
    }

    #[test]
    fn payload_bytes_are_preserved_without_json_canonicalization(payload in json_value()) {
        let compact = payload.to_string();
        let spaced = format!(" \n{compact}\t");
        prop_assert_eq!(serde_json::from_str::<Value>(&spaced).unwrap(), payload.clone());
        let hash = |s: &str| compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 0, s, None, TS);
        prop_assert_ne!(hash(&compact), hash(&spaced));
        let forward = format!("{{\"a\":{compact},\"b\":null}}");
        let reverse = format!("{{\"b\":null,\"a\":{compact}}}");
        prop_assert_eq!(serde_json::from_str::<Value>(&forward).unwrap(), serde_json::from_str::<Value>(&reverse).unwrap());
        prop_assert_ne!(hash(&forward), hash(&reverse));
        prop_assert!(!compact.contains('\0'));
        prop_assert_eq!(hash(&compact), compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 0, &compact, Some(""), TS));
    }

    #[test]
    fn an_intent_round_trips_and_rejects_extra_top_level_fields(i in intent(), extra in json_value(), suffix in text()) {
        let encoded = serde_json::to_string(&i).unwrap();
        prop_assert_eq!(serde_json::from_str::<ProposedIntent>(&encoded).unwrap(), i.clone());
        let mut value = serde_json::to_value(&i).unwrap();
        value.as_object_mut().unwrap().insert(format!("extra_{suffix}"), extra);
        prop_assert!(serde_json::from_value::<ProposedIntent>(value).is_err());
        let minimal: ProposedIntent = serde_json::from_value(json!({"action": i.action})).unwrap();
        prop_assert_eq!(minimal.params, Value::Null);
        prop_assert!(minimal.justification.is_empty() && minimal.reasoning.is_empty());
    }

    #[test]
    fn table_and_bare_name_policy_lists_parse_and_forbidden_actions_win(
        names in proptest::collection::vec("[a-zA-Z_][a-zA-Z0-9_]{0,24}", 1..12), max in any::<u32>(), i in intent()
    ) {
        let bare = format!("name = 'generated'\nmax_steps = {max}\nallowed_actions = {names:?}\nforbidden_actions = {names:?}\nrequired_checks = {names:?}\n");
        let mut tables = format!("name = 'generated'\nmax_steps = {max}\n");
        for name in &names {
            tables.push_str(&format!("[[allowed_actions]]\naction = '{name}'\n[[forbidden_actions]]\naction = '{name}'\n[[required_checks]]\nname = '{name}'\naction = ''\n"));
        }
        for source in [bare, tables] {
            let engine = policy(&source);
            prop_assert_eq!(engine.max_steps(), Some(max));
            prop_assert_eq!(engine.policy().required_checks.as_ref().unwrap().len(), names.len());
            for (rule, name) in engine.policy().allowed_actions.as_ref().unwrap().iter().zip(&names) {
                prop_assert_eq!(&rule.action, name);
            }
            for name in &names {
                let mut forbidden = i.clone();
                forbidden.action.clone_from(name);
                prop_assert!(engine.validate_intent(&forbidden, 0).is_err());
            }
        }
    }

    #[test]
    fn generated_extended_policies_parse_and_never_allow_a_forbidden_unicode_action(
        name in text(), action in text(), decision in prop::sample::select(vec!["allow", "deny", "require_approval"]),
        observation in prop::sample::select(vec!["redact", "flag", "abort"]), approval in any::<bool>(), timeout in any::<u32>(), i in intent()
    ) {
        let quote = |s: &str| toml::Value::String(s.into()).to_string();
        let source = format!(r#"
            name = {name}
            allowed_actions = [{action}]
            forbidden_actions = [{action}]
            [[command_rules]]
            program = "curl"
            arg_pattern = "^safe.*"
            decision = "{decision}"
            reason = {name}
            [[observation_rules]]
            pattern = "secret"
            action = "{observation}"
            label = {name}
            [[approval_gates]]
            trigger = "action == 'run_command' && command_contains('curl')"
            require_approval = {approval}
            timeout_seconds = {timeout}
            on_timeout = "deny"
            [[plugins]]
            name = {name}
            binary = "scanner"
            arg_patterns = ["^safe.*"]
            env_passthrough = ["LANG"]
            [findings]
            require_evidence_for_severity = ["high"]
            evidence_must_reference_observation = true
        "#, name = quote(&name), action = quote(&action));
        let engine = policy(&source);
        prop_assert_eq!(engine.policy().name.as_deref(), Some(name.as_str()));
        let mut forbidden = i;
        forbidden.action = action;
        prop_assert!(engine.validate_intent(&forbidden, 0).is_err());
        let _ = engine.check_approval_gates(&forbidden);
        let _ = engine.validate_observation(&forbidden.reasoning);
    }

    #[test]
    fn policy_evaluation_handles_arbitrary_unicode_and_nested_params(i in intent(), step in any::<u32>()) {
        let engine = policy(r#"
            [[command_rules]]
            program = "curl"
            arg_pattern = ".*"
            decision = "deny"
            [[allowed_actions]]
            action = "run_command"
            [[allowed_actions]]
            action = "read_file"
            path_pattern = "/safe/**"
            [[allowed_actions]]
            action = "http_get"
            [[plugins]]
            name = "scanner"
            binary = "scan"
            arg_patterns = ["^safe"]
            [[approval_gates]]
            trigger = "command_matches_regex('secret')"
            require_approval = true
            [[approval_gates]]
            trigger = "path_extension_matches('.key')"
            require_approval = true
            [[approval_gates]]
            trigger = "url_host_in_cidr('10.0.0.0/8')"
            require_approval = true
        "#);
        let _ = engine.validate_intent(&i, step);
        let _ = engine.check_approval_gates(&i);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn altering_an_event_breaks_the_chain_at_that_event(payloads in proptest::collection::vec(json_value(), 1..40), selected in any::<usize>()) {
        let mut previous = GENESIS_PREVIOUS_HASH.to_owned();
        let mut events = Vec::new();
        for (sequence, payload) in payloads.iter().enumerate() {
            let e = ChainEvent { sequence: sequence as i64, previous_hash: previous, payload_json: payload.to_string(), session_id: None, created_at: TS.into() };
            previous = digest(&e);
            events.push((e, previous.clone()));
        }
        prop_assert_eq!(first_failure(&events), None);
        let index = selected % events.len();
        events[index].0.payload_json.push(' ');
        prop_assert_eq!(first_failure(&events), Some(index));
        // Even rewriting the tampered digest leaves the successor bound to the original.
        events[index].1 = digest(&events[index].0);
        if index + 1 < events.len() {
            prop_assert_eq!(first_failure(&events), Some(index + 1));
        } else {
            prop_assert_ne!(&events[index].1, &previous);
        }
    }

    #[test]
    fn every_leaf_verifies_and_changed_or_distinct_leaves_fail(seeds in proptest::collection::vec(any::<[u8;32]>(), 1..512), selected in any::<usize>()) {
        // Include the index so duplicate random seeds still describe distinct leaves.
        let leaves: Vec<String> = seeds.iter().enumerate().map(|(i,s)| sha256_hex(format!("{i}:{s:?}").as_bytes())).collect();
        let refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let tree = merkle::build_merkle_tree(&refs).unwrap();
        let root = merkle::root(&tree).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = merkle::proof(&tree, i).unwrap();
            prop_assert!(merkle::verify_proof(&root, leaf, &proof).unwrap());
            let mutated = format!("{leaf}0");
            prop_assert!(!merkle::verify_proof(&root, &mutated, &proof).unwrap());
            if leaves.len() > 1 {
                prop_assert!(!merkle::verify_proof(&root, &leaves[(i + 1) % leaves.len()], &proof).unwrap());
            }
        }
        let mut changed = leaves.clone();
        let index = selected % changed.len();
        changed[index].push('0');
        let changed_refs: Vec<&str> = changed.iter().map(String::as_str).collect();
        prop_assert_ne!(&root, &merkle::root(&merkle::build_merkle_tree(&changed_refs).unwrap()).unwrap());
    }

    /// Pins the duplicate-last-node construction (docs/reference/elc-spec.md §3), which
    /// certificates already issued depend on. It has the known Bitcoin-style
    /// ambiguity: an odd leaf list and the same list with its last leaf repeated
    /// share a root. A certificate cannot exploit it because the signature
    /// covers the event list and `event_count`.
    #[test]
    fn an_odd_leaf_list_shares_its_root_with_its_last_leaf_repeated(seeds in proptest::collection::vec(any::<[u8;32]>(), 1..256)) {
        // A single leaf is its own root, so the ambiguity starts at three.
        prop_assume!(seeds.len() > 1 && seeds.len() % 2 == 1);
        let leaves: Vec<String> = seeds.iter().enumerate().map(|(i, s)| sha256_hex(format!("{i}:{s:?}").as_bytes())).collect();
        let refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let mut repeated = refs.clone();
        repeated.push(refs[refs.len() - 1]);
        let root = |r: &[&str]| merkle::root(&merkle::build_merkle_tree(r).unwrap()).unwrap();
        prop_assert_eq!(root(&refs), root(&repeated));
    }
}
