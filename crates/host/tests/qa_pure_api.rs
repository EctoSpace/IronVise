use ectoledger::certificate::{CertEventEntry, EctoLedgerCertificate};
use ectoledger::certificate::{CertificateError, read_certificate_file, write_certificate_file};
use ectoledger::schema::{EventPayload, LedgerEventRow};
use ectoledger::snapshot::{build_snapshot_payload, compute_state_hash};
use uuid::Uuid;

fn minimal_certificate() -> EctoLedgerCertificate {
    EctoLedgerCertificate {
        version: 1,
        session_id: Uuid::new_v4(),
        goal: "qa goal".to_string(),
        goal_hash: "ab".repeat(32),
        policy_hash: None,
        session_public_key: None,
        ledger_tip_hash: "cd".repeat(32),
        merkle_root: "ef".repeat(32),
        event_count: 1,
        started_at: "2026-01-01T00:00:00+00:00".to_string(),
        completed_at: None,
        events: vec![CertEventEntry {
            sequence: 1,
            content_hash: "cd".repeat(32),
        }],
        findings: vec![],
        ots_proof_hex: None,
        zk_proof: None,
        enclave_attestation: None,
        signature: None,
        issuer: None,
    }
}

fn event_row(sequence: i64, payload: EventPayload) -> LedgerEventRow {
    LedgerEventRow {
        id: sequence,
        sequence,
        previous_hash: String::new(),
        content_hash: format!("{sequence:064x}"),
        payload,
        created_at: chrono::Utc::now(),
    }
}

mod certificate_file_round_trip {
    use super::*;

    #[test]
    fn reading_a_missing_file_is_io_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.elc");
        assert!(matches!(
            read_certificate_file(&path),
            Err(CertificateError::Io(_))
        ));
    }

    #[test]
    fn reading_a_directory_as_a_file_is_io_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_certificate_file(dir.path()),
            Err(CertificateError::Io(_))
        ));
    }

    #[test]
    fn reading_an_empty_file_is_serialize_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.elc");
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(
            read_certificate_file(&path),
            Err(CertificateError::Serialize(_))
        ));
    }

    #[test]
    fn a_utf8_bom_before_the_json_is_serialize_error_not_a_panic() {
        let cert = minimal_certificate();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bom.elc");
        write_certificate_file(&cert, &path).unwrap();
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend(std::fs::read(&path).unwrap());
        std::fs::write(&path, with_bom).unwrap();
        assert!(matches!(
            read_certificate_file(&path),
            Err(CertificateError::Serialize(_))
        ));
    }

    #[test]
    fn writing_over_an_existing_file_replaces_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert.elc");
        std::fs::write(&path, b"stale placeholder content").unwrap();

        let cert = minimal_certificate();
        write_certificate_file(&cert, &path).unwrap();
        let loaded = read_certificate_file(&path).unwrap();
        assert_eq!(loaded.session_id, cert.session_id);
        assert_eq!(loaded.merkle_root, cert.merkle_root);
    }

    #[test]
    fn write_then_read_round_trips_every_field_the_signature_covers() {
        let cert = minimal_certificate();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("round-trip.elc");
        write_certificate_file(&cert, &path).unwrap();
        let loaded = read_certificate_file(&path).unwrap();
        assert_eq!(loaded.session_id, cert.session_id);
        assert_eq!(loaded.goal, cert.goal);
        assert_eq!(loaded.goal_hash, cert.goal_hash);
        assert_eq!(loaded.ledger_tip_hash, cert.ledger_tip_hash);
        assert_eq!(loaded.event_count, cert.event_count);
        assert_eq!(loaded.events.len(), cert.events.len());
    }

    #[test]
    fn writing_to_a_nonexistent_parent_directory_is_io_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-parent").join("cert.elc");
        let cert = minimal_certificate();
        assert!(matches!(
            write_certificate_file(&cert, &path),
            Err(CertificateError::Io(_))
        ));
    }
}

mod snapshot_payload_edge_cases {
    use super::*;

    #[test]
    fn an_empty_event_slice_produces_an_empty_summary_and_a_stable_hash() {
        let payload = build_snapshot_payload(&[], 0);
        assert_eq!(payload.event_count, 0);
        assert_eq!(payload.last_sequence, 0);
        assert!(payload.latest_events_summary.is_empty());
        let hash = compute_state_hash(&payload).unwrap();
        assert_eq!(
            hash,
            compute_state_hash(&build_snapshot_payload(&[], 0)).unwrap()
        );
    }

    #[test]
    fn a_single_event_is_summarised_with_its_type_label() {
        let events = vec![event_row(
            1,
            EventPayload::Thought {
                content: "hi".into(),
            },
        )];
        let payload = build_snapshot_payload(&events, 1);
        assert_eq!(payload.event_count, 1);
        assert_eq!(payload.latest_events_summary.len(), 1);
        assert_eq!(payload.latest_events_summary[0].sequence, 1);
        assert_eq!(payload.latest_events_summary[0].type_label, "thought");
    }

    #[test]
    fn more_than_a_hundred_events_keeps_only_the_most_recent_hundred_in_order() {
        let events: Vec<LedgerEventRow> = (1..=150)
            .map(|i| {
                event_row(
                    i,
                    EventPayload::Thought {
                        content: format!("thought-{i}"),
                    },
                )
            })
            .collect();
        let payload = build_snapshot_payload(&events, 150);
        assert_eq!(payload.event_count, 150);
        assert_eq!(payload.latest_events_summary.len(), 100);
        assert_eq!(payload.latest_events_summary.first().unwrap().sequence, 51);
        assert_eq!(payload.latest_events_summary.last().unwrap().sequence, 150);
    }

    #[test]
    fn out_of_order_sequences_in_the_input_are_summarised_in_the_given_order_not_resorted() {
        let events = vec![
            event_row(
                5,
                EventPayload::Thought {
                    content: "later".into(),
                },
            ),
            event_row(
                2,
                EventPayload::Thought {
                    content: "earlier".into(),
                },
            ),
        ];
        let payload = build_snapshot_payload(&events, 5);
        let sequences: Vec<i64> = payload
            .latest_events_summary
            .iter()
            .map(|e| e.sequence)
            .collect();
        assert_eq!(sequences, vec![5, 2]);
    }

    #[test]
    fn different_last_sequence_values_change_the_state_hash_even_with_identical_events() {
        let events = vec![event_row(
            1,
            EventPayload::Thought {
                content: "hi".into(),
            },
        )];
        let a = compute_state_hash(&build_snapshot_payload(&events, 1)).unwrap();
        let b = compute_state_hash(&build_snapshot_payload(&events, 2)).unwrap();
        assert_ne!(a, b);
    }
}

mod secrets_persistent_variant {
    use ectoledger::secrets::load_env_secret_persistent;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn load_env_secret_persistent_does_not_remove_the_variable() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: serialised by ENV_LOCK; this test owns this variable name.
        unsafe { std::env::set_var("_QA_PERSISTENT_SECRET", "still-here") };
        let secret = load_env_secret_persistent("_QA_PERSISTENT_SECRET");
        assert_eq!(secret.unwrap().expose_secret(), "still-here");
        assert_eq!(
            std::env::var("_QA_PERSISTENT_SECRET").unwrap(),
            "still-here"
        );
        // SAFETY: serialised by ENV_LOCK; cleans up after itself.
        unsafe { std::env::remove_var("_QA_PERSISTENT_SECRET") };
    }

    #[test]
    fn load_env_secret_persistent_missing_returns_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(load_env_secret_persistent("_QA_PERSISTENT_SECRET_MISSING_XYZ").is_none());
    }
}
