use super::*;

fn approval(gate: &str) -> PendingApproval {
    PendingApproval {
        gate_id: gate.to_string(),
        action_name: "run_command".to_string(),
        action_params_summary: r#"{"command":"nmap -sS 10.0.0.0/24"}"#.to_string(),
        created_at: chrono::Utc::now(),
    }
}

/// The read path the dashboard uses, end to end.
///
/// `set_pending` had no callers, so this map was never written and
/// `GET /api/approvals/:id/pending` always answered with null. The
/// decision buttons worked; the operator pressing them could not see what
/// they were approving. A test over `get_pending` alone would have passed
/// throughout - the gap was that nothing published.
#[test]
fn a_published_approval_is_readable_and_carries_the_action() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    assert!(state.get_pending(session).is_none(), "nothing pending yet");

    state.set_pending(session, approval("gate-1"));
    let got = state.get_pending(session).expect("published approval");
    assert_eq!(got.gate_id, "gate-1");
    assert_eq!(got.action_name, "run_command");
    assert!(
        got.action_params_summary.contains("nmap"),
        "the operator must be able to see what they are approving, got {:?}",
        got.action_params_summary
    );
}

/// Deciding clears the pending entry, so the dashboard stops offering a
/// question that has already been answered.
#[test]
fn recording_a_decision_clears_what_was_pending() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate-2"));

    state.record_decision(session, "gate-2".to_string(), true, None);
    assert!(state.get_pending(session).is_none());
    assert_eq!(
        state.take_decision(session, "gate-2"),
        Some((true, None)),
        "the decision itself must survive being collected once"
    );
}

/// Two sessions awaiting approval do not see each other's.
#[test]
fn pending_approvals_are_per_session() {
    let state = ApprovalState::new();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    state.set_pending(a, approval("gate-a"));
    state.set_pending(b, approval("gate-b"));
    assert_eq!(state.get_pending(a).unwrap().gate_id, "gate-a");
    assert_eq!(state.get_pending(b).unwrap().gate_id, "gate-b");
    state.record_decision(a, "gate-a".to_string(), false, None);
    assert!(state.get_pending(a).is_none());
    assert!(state.get_pending(b).is_some(), "b must be untouched");
}

#[test]
fn try_record_decision_recorded_when_the_gate_matches_pending() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate-1"));
    let outcome = state.try_record_decision(session, "gate-1".to_string(), true, Some("ok".into()));
    assert_eq!(outcome, DecisionOutcome::Recorded);
    assert!(state.get_pending(session).is_none());
    assert_eq!(
        state.take_decision(session, "gate-1"),
        Some((true, Some("ok".to_string())))
    );
}

#[test]
fn try_record_decision_rejects_an_unknown_session() {
    let state = ApprovalState::new();
    let outcome = state.try_record_decision(Uuid::new_v4(), "gate-1".to_string(), true, None);
    assert_eq!(outcome, DecisionOutcome::NotPending);
}

#[test]
fn try_record_decision_rejects_a_gate_id_mismatch() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate-1"));
    let outcome = state.try_record_decision(session, "gate-2".to_string(), true, None);
    assert_eq!(outcome, DecisionOutcome::GateMismatch);
    // The mismatched attempt must not disturb the real pending entry.
    assert_eq!(state.get_pending(session).unwrap().gate_id, "gate-1");
}

/// The race the REST handler must close: exactly one of two concurrent
/// decisions for the same gate is recorded, the other sees it already
/// gone, regardless of which thread the OS schedules first.
#[test]
fn try_record_decision_settles_a_concurrent_approve_and_deny_to_one_winner() {
    use std::sync::Arc;

    let state = Arc::new(ApprovalState::new());
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate-1"));

    let approve_state = Arc::clone(&state);
    let deny_state = Arc::clone(&state);
    let approve = std::thread::spawn(move || {
        approve_state.try_record_decision(session, "gate-1".to_string(), true, None)
    });
    let deny = std::thread::spawn(move || {
        deny_state.try_record_decision(session, "gate-1".to_string(), false, None)
    });
    let outcomes = [approve.join().unwrap(), deny.join().unwrap()];
    let recorded = outcomes
        .iter()
        .filter(|o| **o == DecisionOutcome::Recorded)
        .count();
    assert_eq!(recorded, 1, "expected exactly one winner, got {outcomes:?}");
}

#[test]
fn a_decision_after_the_gate_expired_is_refused() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate-1"));

    assert_eq!(state.expire(session, "gate-1"), None);
    assert!(
        state.get_pending(session).is_none(),
        "the dashboard stops showing it"
    );
    let late = state.try_record_decision(session, "gate-1".to_string(), true, None);
    assert_eq!(late, DecisionOutcome::NotPending);
    assert_eq!(state.take_decision(session, "gate-1"), None);
}

#[test]
fn a_decision_that_beat_the_timeout_stands() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate-1"));
    let outcome = state.try_record_decision(session, "gate-1".to_string(), true, Some("ok".into()));
    assert_eq!(outcome, DecisionOutcome::Recorded);

    assert_eq!(
        state.expire(session, "gate-1"),
        Some((true, Some("ok".into())))
    );
}

#[test]
fn expiring_one_gate_leaves_a_newer_gate_pending() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate-2"));

    assert_eq!(state.expire(session, "gate-1"), None);
    assert_eq!(state.get_pending(session).unwrap().gate_id, "gate-2");
}
