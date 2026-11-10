use ectoledger::webhook::{EgressEvent, EgressKind, preview, try_enqueue_event};
use tokio::sync::mpsc;
use uuid::Uuid;

mod preview_truncation {
    use super::*;

    #[test]
    fn a_string_under_the_limit_is_unchanged() {
        assert_eq!(preview("short text"), "short text");
    }

    #[test]
    fn a_string_of_exactly_two_hundred_chars_is_unchanged() {
        let s = "a".repeat(200);
        assert_eq!(preview(&s), s);
    }

    #[test]
    fn a_string_over_two_hundred_chars_is_truncated_to_exactly_two_hundred() {
        let s = "a".repeat(500);
        let got = preview(&s);
        assert_eq!(got.chars().count(), 200);
    }

    #[test]
    fn truncation_counts_chars_not_bytes_so_multibyte_characters_are_not_split() {
        let s = "\u{1f600}".repeat(250);
        let got = preview(&s);
        assert_eq!(got.chars().count(), 200);
        assert_eq!(got, "\u{1f600}".repeat(200));
    }
}

fn event(kind: EgressKind) -> EgressEvent {
    EgressEvent {
        session_id: Uuid::new_v4(),
        severity: "flag".to_string(),
        rule_label: "qa".to_string(),
        observation_preview: "qa observation".to_string(),
        kind,
    }
}

mod try_enqueue_backpressure {
    use super::*;

    #[test]
    fn a_full_channel_drops_the_event_instead_of_blocking_or_panicking() {
        let (tx, mut rx) = mpsc::channel::<EgressEvent>(1);
        try_enqueue_event(&tx, event(EgressKind::Observation));
        try_enqueue_event(&tx, event(EgressKind::GuardDenial));

        let first = rx.try_recv().expect("the first event was accepted");
        assert_eq!(first.kind, EgressKind::Observation);
        assert!(
            rx.try_recv().is_err(),
            "the second event must have been dropped, not queued"
        );
    }

    #[test]
    fn a_closed_channel_is_silently_ignored_not_a_panic() {
        let (tx, rx) = mpsc::channel::<EgressEvent>(4);
        drop(rx);
        try_enqueue_event(&tx, event(EgressKind::TripwireRejection));
    }
}
