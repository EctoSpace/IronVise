use super::*;
use crate::schema::EventPayload;
use crate::signing;
use sqlx::sqlite::SqlitePoolOptions;

/// A finding that cites a sequence the session does not have. The builder
/// used to drop that proof and shift the rest, so the certificate either
/// failed or verified with the phantom evidence unproven, depending on
/// where it sat. Now the phantom is left out and the rest stay paired.
///
/// The ledger already refuses such a `complete` at append time
/// (`UnverifiedEvidence`), so this is the builder's own guarantee, tested
/// on the function directly.
#[test]
fn a_phantom_evidence_sequence_is_left_out_and_the_rest_stay_paired() {
    use crate::schema::LedgerEventRow;
    let row = |seq: i64, hash: &str, payload: EventPayload| LedgerEventRow {
        id: seq,
        sequence: seq,
        previous_hash: String::new(),
        content_hash: hash.to_string(),
        payload,
        created_at: chrono::Utc::now(),
    };
    for order in [vec![9_999, 1], vec![1, 9_999]] {
        let events = vec![
            row(
                1,
                &"a".repeat(64),
                EventPayload::Observation {
                    content: "PermitRootLogin yes".into(),
                },
            ),
            row(
                2,
                &"b".repeat(64),
                EventPayload::Action {
                    name: "complete".into(),
                    params: serde_json::json!({ "findings": [{
                        "severity": "low",
                        "title": "root login",
                        "evidence": "PermitRootLogin yes",
                        "recommendation": "disable it",
                        "evidence_sequence": order,
                        "evidence_quotes": ["q-a", "q-b"],
                    }]}),
                },
            ),
        ];
        let hashes: Vec<&str> = events.iter().map(|e| e.content_hash.as_str()).collect();
        let tree = merkle::build_merkle_tree(&hashes).unwrap();
        let hash_to_leaf: std::collections::HashMap<&str, usize> =
            hashes.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let f = &extract_findings_with_proofs(&events, &tree, &hash_to_leaf)[0];
        assert_eq!(f.evidence_sequence, vec![1], "{order:?}");
        assert_eq!(f.merkle_proofs.len(), 1);
        let kept = if order[0] == 1 { "q-a" } else { "q-b" };
        assert_eq!(f.evidence_quotes, vec![kept.to_string()]);
        let root = merkle::root(&tree).unwrap();
        assert!(merkle::verify_proof(&root, &"a".repeat(64), &f.merkle_proofs[0]).unwrap());
    }
}

#[tokio::test]
async fn build_certificate_sqlite_round_trip() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .unwrap();

    let (session, sk) = crate::ledger::sqlite::create_session_sqlite(
        &pool,
        "cert test goal",
        "test",
        "test-model",
        None,
        None,
    )
    .await
    .unwrap();

    crate::ledger::sqlite::append_event_sqlite(
        &pool,
        &EventPayload::Thought {
            content: "hello".into(),
        },
        Some(session.id),
        Some("cert test goal"),
        Some(&sk),
    )
    .await
    .unwrap();

    let cert = build_certificate_sqlite(&pool, session.id, Some(&sk), false, None)
        .await
        .unwrap();
    assert_eq!(cert.session_id, session.id);
    assert_eq!(cert.event_count, 1);
    assert!(cert.signature.is_some());
    assert!(!cert.merkle_root.is_empty());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.elc");
    write_certificate_file(&cert, &path).unwrap();
    let loaded = read_certificate_file(&path).unwrap();
    assert_eq!(loaded.merkle_root, cert.merkle_root);
    let _ = signing::public_key_hex(&sk.verifying_key());

    // A key that is not the session's would sign a certificate that names
    // one key and is signed by another: refused rather than written.
    let (stranger, _) = signing::generate_keypair();
    assert!(matches!(
        build_certificate_sqlite(&pool, session.id, Some(&stranger), false, None).await,
        Err(CertificateError::KeyMismatch)
    ));
}
