use ectoledger::approvals::{ApprovalState, PendingApproval};
use std::sync::Arc;
use uuid::Uuid;

fn approval(gate: &str) -> PendingApproval {
    PendingApproval {
        gate_id: gate.to_string(),
        action_name: "run_command".to_string(),
        action_params_summary: "{}".to_string(),
        created_at: chrono::Utc::now(),
    }
}

#[test]
fn take_decision_for_an_unknown_gate_id_is_none_not_a_panic() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    assert_eq!(state.take_decision(session, "never-existed"), None);
}

#[test]
fn take_decision_for_an_unknown_session_id_is_none_not_a_panic() {
    let state = ApprovalState::new();
    assert_eq!(state.take_decision(Uuid::new_v4(), "gate"), None);
}

#[test]
fn a_decision_can_only_be_taken_once() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.record_decision(session, "gate".to_string(), true, None);
    assert_eq!(state.take_decision(session, "gate"), Some((true, None)));
    assert_eq!(state.take_decision(session, "gate"), None);
}

#[test]
fn recording_a_decision_with_no_matching_pending_entry_still_records_it() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    assert!(state.get_pending(session).is_none());
    state.record_decision(session, "orphan-gate".to_string(), false, Some("no".into()));
    assert_eq!(
        state.take_decision(session, "orphan-gate"),
        Some((false, Some("no".to_string())))
    );
}

#[test]
fn deciding_the_same_gate_twice_lets_the_second_decision_win() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate"));
    state.record_decision(session, "gate".to_string(), true, Some("approved".into()));
    state.record_decision(
        session,
        "gate".to_string(),
        false,
        Some("actually denied".into()),
    );
    assert_eq!(
        state.take_decision(session, "gate"),
        Some((false, Some("actually denied".to_string())))
    );
}

#[test]
fn cleanup_session_also_discards_an_undecided_decision() {
    let state = ApprovalState::new();
    let session = Uuid::new_v4();
    state.record_decision(session, "gate".to_string(), true, None);
    state.cleanup_session(session);
    assert_eq!(state.take_decision(session, "gate"), None);
}

#[test]
fn cleanup_session_leaves_other_sessions_decisions_intact() {
    let state = ApprovalState::new();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    state.record_decision(a, "gate".to_string(), true, None);
    state.record_decision(b, "gate".to_string(), false, None);
    state.cleanup_session(a);
    assert_eq!(state.take_decision(a, "gate"), None);
    assert_eq!(state.take_decision(b, "gate"), Some((false, None)));
}

#[test]
fn concurrent_approve_and_deny_on_the_same_gate_resolves_to_exactly_one_outcome_without_panicking()
{
    let state = Arc::new(ApprovalState::new());
    let session = Uuid::new_v4();
    state.set_pending(session, approval("gate"));

    let approve_state = Arc::clone(&state);
    let deny_state = Arc::clone(&state);
    let approve = std::thread::spawn(move || {
        approve_state.record_decision(session, "gate".to_string(), true, Some("approve".into()));
    });
    let deny = std::thread::spawn(move || {
        deny_state.record_decision(session, "gate".to_string(), false, Some("deny".into()));
    });
    approve.join().unwrap();
    deny.join().unwrap();

    let outcome = state.take_decision(session, "gate");
    assert!(
        outcome == Some((true, Some("approve".to_string())))
            || outcome == Some((false, Some("deny".to_string()))),
        "expected exactly one of the two racing decisions to win, got {outcome:?}"
    );
    assert!(state.get_pending(session).is_none());
}
