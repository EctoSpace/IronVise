use super::*;
use crate::CertEventEntry;

fn cert() -> EctoLedgerCertificate {
    EctoLedgerCertificate {
        version: 1,
        session_id: uuid::Uuid::nil(),
        goal: "g".into(),
        goal_hash: String::new(),
        policy_hash: None,
        session_public_key: Some("aa".repeat(32)),
        ledger_tip_hash: "h3".into(),
        merkle_root: String::new(),
        event_count: 3,
        started_at: String::new(),
        completed_at: None,
        events: (1..=3)
            .map(|i| CertEventEntry {
                sequence: i,
                content_hash: format!("h{i}"),
            })
            .collect(),
        findings: vec![],
        ots_proof_hex: None,
        zk_proof: None,
        enclave_attestation: None,
        signature: None,
        issuer: None,
    }
}

fn ledger(events: &[(i64, &str)]) -> Vec<(i64, String)> {
    events.iter().map(|(s, h)| (*s, h.to_string())).collect()
}

const SID: &str = "00000000-0000-0000-0000-000000000000";

#[test]
fn an_unchanged_ledger_agrees() {
    let ev = ledger(&[(1, "h1"), (2, "h2"), (3, "h3"), (4, "anchor")]);
    let key = "aa".repeat(32);
    let c = compare(
        &cert(),
        &LedgerView {
            session_id: SID,
            session_public_key: Some(&key),
            events: &ev,
        },
    );
    assert!(c.agrees(), "{c:?}");
    assert_eq!(c.events_after_certificate, 1);
}

#[test]
fn truncation_behind_a_rewritten_seal_is_caught() {
    let ev = ledger(&[(1, "h1"), (2, "h2")]);
    let key = "aa".repeat(32);
    let c = compare(
        &cert(),
        &LedgerView {
            session_id: SID,
            session_public_key: Some(&key),
            events: &ev,
        },
    );
    assert!(!c.agrees());
}

#[test]
fn a_re_keyed_and_rewritten_session_is_caught() {
    let ev = ledger(&[(1, "h1"), (2, "x2"), (3, "x3")]);
    let key = "bb".repeat(32);
    let c = compare(
        &cert(),
        &LedgerView {
            session_id: SID,
            session_public_key: Some(&key),
            events: &ev,
        },
    );
    assert_eq!(c.problems.len(), 2, "{c:?}");
}

fn view<'a>(key: Option<&'a str>, events: &'a [(i64, String)]) -> LedgerView<'a> {
    LedgerView {
        session_id: SID,
        session_public_key: key,
        events,
    }
}

#[test]
fn every_event_after_the_tip_is_counted_and_none_before_it() {
    let key = "aa".repeat(32);
    let ev = ledger(&[(1, "h1"), (2, "h2"), (3, "h3"), (4, "a"), (5, "b")]);
    let c = compare(&cert(), &view(Some(&key), &ev));
    assert!(c.agrees(), "{c:?}");
    assert_eq!(c.events_after_certificate, 2);
}

#[test]
fn truncation_says_how_many_events_are_gone_and_from_where() {
    let key = "aa".repeat(32);
    let ev = ledger(&[(1, "h1")]);
    let c = compare(&cert(), &view(Some(&key), &ev));
    assert_eq!(
        c.problems,
        [
            "2 event(s) the certificate covers are gone from the ledger, from sequence 2: \
              removed after the certificate was cut"
        ]
    );
}

#[test]
fn a_re_keyed_session_names_both_keys_and_the_first_rewritten_event() {
    let ev = ledger(&[(1, "h1"), (2, "x2"), (3, "x3")]);
    let key = "bb".repeat(32);
    let c = compare(&cert(), &view(Some(&key), &ev));
    assert!(
        c.problems[0].starts_with(&format!(
            "the session's key is now {}…, but the certificate was signed under {}…",
            "b".repeat(16),
            "a".repeat(16)
        )),
        "{c:?}"
    );
    assert!(
        c.problems[1].starts_with("event 2 no longer has the hash"),
        "{c:?}"
    );
}

/// Deleting the key column is how a re-key would hide from the check above.
#[test]
fn a_session_key_removed_from_the_ledger_is_a_contradiction() {
    let ev = ledger(&[(1, "h1"), (2, "h2"), (3, "h3")]);
    let c = compare(&cert(), &view(None, &ev));
    assert_eq!(
        c.problems,
        [format!(
            "the session no longer records a key; the certificate names {}…",
            "a".repeat(16)
        )]
    );
}

/// Hex case and stray whitespace are not a different key or hash.
#[test]
fn case_and_whitespace_are_not_a_change() {
    let key = format!(" {} ", "AA".repeat(32));
    let ev = ledger(&[(1, "H1"), (2, "h2"), (3, "h3")]);
    let c = compare(&cert(), &view(Some(&key), &ev));
    assert!(c.agrees(), "{c:?}");
}

#[test]
fn a_certificate_for_another_session_is_refused() {
    let ev = ledger(&[(1, "h1")]);
    let c = compare(
        &cert(),
        &LedgerView {
            session_id: "11111111-1111-1111-1111-111111111111",
            session_public_key: None,
            events: &ev,
        },
    );
    assert!(!c.agrees());
}
