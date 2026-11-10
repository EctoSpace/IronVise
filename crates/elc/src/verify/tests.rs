use super::*;
use crate::{CertEventEntry, CertFinding};

/// A certificate whose four event hashes are committed to by `merkle_root`,
/// with no findings - the shape that used to bypass the root check.
fn cert_without_findings() -> EctoLedgerCertificate {
    let hashes: Vec<String> = (1..=4u8)
        .map(|i| hex::encode(Sha256::digest([i])))
        .collect();
    let refs: Vec<&str> = hashes.iter().map(String::as_str).collect();
    let tree = merkle::build_merkle_tree(&refs).expect("tree");
    let root = merkle::root(&tree).expect("root");

    EctoLedgerCertificate {
        version: 1,
        session_id: uuid::Uuid::nil(),
        goal: "example".to_string(),
        goal_hash: hex::encode(Sha256::digest(b"example")),
        session_public_key: None,
        ledger_tip_hash: hashes[3].clone(),
        merkle_root: root,
        event_count: 4,
        started_at: "2026-01-01T00:00:00Z".to_string(),
        completed_at: None,
        events: hashes
            .iter()
            .enumerate()
            .map(|(i, h)| CertEventEntry {
                sequence: i as i64 + 1,
                content_hash: h.clone(),
            })
            .collect(),
        findings: Vec::new(),
        ots_proof_hex: None,
        policy_hash: None,
        zk_proof: None,
        enclave_attestation: None,
        signature: None,
        issuer: None,
    }
}

fn fails(c: &Check) -> bool {
    c.status == Status::Fail
}

#[test]
fn an_untampered_certificate_passes() {
    let cert = cert_without_findings();
    assert!(!fails(&check_merkle_proofs(&cert)));
    let r = verify(&cert, &Requirements::default());
    assert_eq!(r.verdict, Verdict::ConsistentUnsigned);
}

#[test]
fn editing_an_interior_event_hash_is_detected_even_with_no_findings() {
    // `check_merkle_proofs` used to return early with a green tick when
    // `findings` was empty, so `merkle_root` was never compared against the
    // events it commits to. Interior, deliberately: the last event is
    // separately pinned by the tip check.
    let mut cert = cert_without_findings();
    cert.events[1].content_hash = hex::encode(Sha256::digest(b"fabricated"));
    assert!(fails(&check_merkle_proofs(&cert)));
}

#[test]
fn editing_the_first_event_hash_is_detected() {
    let mut cert = cert_without_findings();
    cert.events[0].content_hash = hex::encode(Sha256::digest(b"fabricated"));
    assert!(fails(&check_merkle_proofs(&cert)));
}

#[test]
fn a_tampered_last_event_fails_both_the_chain_and_the_root_check() {
    let mut cert = cert_without_findings();
    cert.events[3].content_hash = hex::encode(Sha256::digest(b"fabricated"));
    assert!(fails(&check_hash_chain(&cert)), "tip mismatch should fail");
    assert!(
        fails(&check_merkle_proofs(&cert)),
        "root mismatch should also fail"
    );
}

#[test]
fn reordering_events_is_detected() {
    let mut cert = cert_without_findings();
    cert.events.swap(0, 1);
    assert!(fails(&check_merkle_proofs(&cert)));
}

// The three cases below are where `ironvise verify-certificate` used to
// disagree with `verify-cert`. One implementation now; these pin it.

#[test]
fn a_sequence_gap_is_invalid() {
    let mut cert = cert_without_findings();
    cert.events[2].sequence = 7;
    cert.events[3].sequence = 8;
    let r = verify(&cert, &Requirements::default());
    assert_eq!(r.verdict, Verdict::Invalid);
}

#[test]
fn a_finding_citing_an_absent_event_is_invalid() {
    let mut cert = cert_without_findings();
    let refs: Vec<&str> = cert
        .events
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();
    let tree = merkle::build_merkle_tree(&refs).unwrap();
    cert.findings.push(CertFinding {
        title: "fabricated evidence".into(),
        severity: "high".into(),
        evidence_sequence: vec![99],
        evidence_quotes: vec![String::new()],
        merkle_proofs: vec![merkle::proof(&tree, 0).unwrap()],
    });
    assert_eq!(
        verify(&cert, &Requirements::default()).verdict,
        Verdict::Invalid
    );
}

#[test]
fn a_finding_with_fewer_proofs_than_evidence_is_invalid() {
    let mut cert = cert_without_findings();
    let refs: Vec<&str> = cert
        .events
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();
    let tree = merkle::build_merkle_tree(&refs).unwrap();
    cert.findings.push(CertFinding {
        title: "half proven".into(),
        severity: "low".into(),
        evidence_sequence: vec![1, 2],
        evidence_quotes: vec![String::new(), String::new()],
        merkle_proofs: vec![merkle::proof(&tree, 0).unwrap()],
    });
    assert_eq!(
        verify(&cert, &Requirements::default()).verdict,
        Verdict::Invalid
    );
}

#[test]
fn a_fully_proven_finding_is_valid() {
    let mut cert = cert_without_findings();
    let refs: Vec<&str> = cert
        .events
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();
    let tree = merkle::build_merkle_tree(&refs).unwrap();
    cert.findings.push(CertFinding {
        title: "proven".into(),
        severity: "low".into(),
        evidence_sequence: vec![1, 3],
        evidence_quotes: vec![String::new(), String::new()],
        merkle_proofs: vec![
            merkle::proof(&tree, 0).unwrap(),
            merkle::proof(&tree, 2).unwrap(),
        ],
    });
    assert_eq!(
        verify(&cert, &Requirements::default()).verdict,
        Verdict::ConsistentUnsigned
    );
    assert_eq!(
        check_merkle_proofs(&cert).detail,
        " (1 findings, 2 evidence sequences verified)"
    );
}

#[test]
fn bitcoin_marker_bytes_without_an_ots_header_are_not_an_anchor() {
    let mut cert = cert_without_findings();
    cert.ots_proof_hex = Some("0588960d73d71901".repeat(4));
    let req = Requirements {
        anchor: true,
        ..Default::default()
    };
    let r = verify(&cert, &req);
    assert!(!r.anchored);
    assert_eq!(r.verdict, Verdict::Invalid);
}

#[test]
fn the_shipped_example_stamp_reads_as_a_pending_calendar_promise() {
    let cert: EctoLedgerCertificate = serde_json::from_str(include_str!(
        "../../../../examples/verified-session/session.elc"
    ))
    .unwrap();
    let r = verify(&cert, &Requirements::default());
    let ots = r.checks.iter().find(|c| c.id == "ots").unwrap();
    assert_eq!(ots.status, Status::Warn);
    assert!(ots.detail.contains("pending"), "{}", ots.detail);
    assert!(
        ots.notes
            .iter()
            .any(|n| n.starts_with("calendar: https://")),
        "{:?}",
        ots.notes
    );
    assert!(!r.anchored);
}

#[test]
fn an_ots_file_for_another_digest_fails() {
    let cert: EctoLedgerCertificate = serde_json::from_str(include_str!(
        "../../../../examples/verified-session/session.elc"
    ))
    .unwrap();
    let raw = hex::decode(cert.ots_proof_hex.as_ref().unwrap()).unwrap();
    let other: [u8; 32] = Sha256::digest(b"another tip").into();
    let req = Requirements {
        ots_file: Some(crate::ots::detached_file(&other, &raw)),
        ..Default::default()
    };
    assert_eq!(verify(&cert, &req).verdict, Verdict::Invalid);

    let tip: [u8; 32] = hex::decode(&cert.ledger_tip_hash)
        .unwrap()
        .try_into()
        .unwrap();
    let req = Requirements {
        ots_file: Some(crate::ots::detached_file(&tip, &raw)),
        ..Default::default()
    };
    assert!(verify(&cert, &req).is_valid());
}

#[test]
fn an_unsigned_certificate_fails_when_a_signature_is_required() {
    let cert = cert_without_findings();
    let req = Requirements {
        signature: true,
        ..Default::default()
    };
    assert_eq!(verify(&cert, &req).verdict, Verdict::Invalid);
}

#[test]
fn a_signature_without_a_public_key_is_invalid_not_unsigned() {
    let mut cert = cert_without_findings();
    cert.signature = Some("00".repeat(64));
    assert_eq!(
        verify(&cert, &Requirements::default()).verdict,
        Verdict::Invalid
    );
}

/// Every text field of a certificate is untrusted. None may make the
/// verifier or its rendering panic, whatever it holds.
#[test]
fn no_field_content_makes_the_verifier_panic() {
    let long = "é".repeat(200);
    let hostile = [
        "",
        "é",
        "aéééééééééééééééééé",
        "🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀",
        "\u{0}\u{202e}ab",
        long.as_str(),
    ];
    let edits: Vec<fn(&mut EctoLedgerCertificate, &str)> = vec![
        |c, t| c.goal = t.into(),
        |c, t| c.goal_hash = t.into(),
        |c, t| c.session_public_key = Some(t.into()),
        |c, t| c.ledger_tip_hash = t.into(),
        |c, t| c.merkle_root = t.into(),
        |c, t| c.started_at = t.into(),
        |c, t| c.completed_at = Some(t.into()),
        |c, t| c.events[0].content_hash = t.into(),
        |c, t| c.events[3].content_hash = t.into(),
        |c, t| c.ots_proof_hex = Some(t.into()),
        |c, t| c.policy_hash = Some(t.into()),
        |c, t| c.signature = Some(t.into()),
        |c, t| c.zk_proof = Some(serde_json::json!(t)),
        |c, t| {
            c.issuer = Some(crate::IssuerSignature {
                public_key: t.into(),
                signature: t.into(),
            })
        },
        |c, t| {
            c.enclave_attestation = Some(crate::EnclaveAttestationPillar {
                level: crate::EnclaveLevel::SoftwareHardened,
                measurement_hash: t.into(),
                raw_attestation_hex: Some(t.into()),
            })
        },
        |c, t| {
            c.findings.push(CertFinding {
                title: t.into(),
                severity: t.into(),
                evidence_sequence: vec![1, -1, i64::MAX],
                evidence_quotes: vec![t.into()],
                merkle_proofs: vec![],
            })
        },
    ];
    for text in hostile {
        let requirements = [
            Requirements::default(),
            Requirements {
                expected_key: Some("b".repeat(64)),
                ..Default::default()
            },
            Requirements {
                expected_key: Some(text.into()),
                issuer: Some(text.into()),
                anchor: true,
                ots_file: Some(text.as_bytes().to_vec()),
                ..Default::default()
            },
        ];
        for (edit, signed) in edits.iter().flat_map(|e| [(e, false), (e, true)]) {
            let mut cert = cert_without_findings();
            if signed {
                cert.session_public_key = Some("ab".repeat(32));
                cert.signature = Some("00".repeat(64));
            }
            edit(&mut cert, text);
            for req in &requirements {
                let r = verify(&cert, req);
                let _ = (r.render(true, true), r.render(false, true));
            }
        }
    }
}

#[test]
fn a_non_ascii_key_against_an_expected_key_is_a_failure_not_a_panic() {
    let mut cert = cert_without_findings();
    cert.session_public_key = Some(format!("a{}", "é".repeat(20)));
    cert.signature = Some("00".repeat(64));
    let req = Requirements {
        expected_key: Some("b".repeat(64)),
        ..Default::default()
    };
    assert_eq!(verify(&cert, &req).verdict, Verdict::Invalid);
}

#[test]
fn unverified_pillars_are_reported_as_unverified() {
    let mut cert = cert_without_findings();
    cert.zk_proof = Some(serde_json::json!({ "proof": "anything" }));
    cert.enclave_attestation = Some(crate::EnclaveAttestationPillar {
        level: crate::EnclaveLevel::SoftwareHardened,
        measurement_hash: "00".repeat(32),
        raw_attestation_hex: None,
    });
    let r = verify(&cert, &Requirements::default());
    for id in ["enclave", "zk_proof"] {
        let c = r.checks.iter().find(|c| c.id == id).expect(id);
        assert_eq!(c.status, Status::Warn, "{id}");
        assert!(c.detail.contains("not verified"), "{id}: {}", c.detail);
    }
    assert_eq!(r.verdict, Verdict::ConsistentUnsigned);
}

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn hex_key(k: &ed25519_dalek::SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

fn session_signed(session: &ed25519_dalek::SigningKey) -> EctoLedgerCertificate {
    use ed25519_dalek::Signer;
    let mut cert = cert_without_findings();
    cert.session_public_key = Some(hex_key(session));
    let bytes = crate::canonical_json_for_signing(&cert).unwrap();
    cert.signature = Some(hex::encode(session.sign(bytes.as_bytes()).to_bytes()));
    cert
}

fn required(issuer: &str) -> Requirements {
    Requirements {
        issuer: Some(issuer.to_uppercase()),
        ..Default::default()
    }
}

/// Signed over the field-order bytes a `preserve_order` build produced:
/// valid, with a note saying so, and still bound to every field.
#[test]
fn a_certificate_signed_in_the_legacy_form_verifies_and_says_so() {
    use ed25519_dalek::Signer;
    let session = key(3);
    let mut cert = cert_without_findings();
    cert.session_public_key = Some(hex_key(&session));
    let legacy = crate::legacy_json_for_signing(&cert).unwrap();
    assert_ne!(legacy, crate::canonical_json_for_signing(&cert).unwrap());
    cert.signature = Some(hex::encode(session.sign(legacy.as_bytes()).to_bytes()));

    let r = verify(&cert, &Requirements::default());
    assert!(
        matches!(r.verdict, Verdict::Valid { .. }),
        "{:?}",
        r.verdict
    );
    let sig = r.checks.iter().find(|c| c.id == "signature").unwrap();
    assert_eq!(sig.status, Status::Pass);
    assert!(sig.notes[0].contains("pre-0.8 field-order form"), "{sig:?}");

    cert.goal = "another goal".into();
    let r = verify(&cert, &Requirements::default());
    let sig = r.checks.iter().find(|c| c.id == "signature").unwrap();
    assert_eq!(sig.status, Status::Fail, "{sig:?}");
}

/// The verdict names who signed; it hints at `--issuer` only when no key
/// in it was one the caller expected.
#[test]
fn the_verdict_line_names_signer_and_issuer_and_hints_only_when_unpinned() {
    let (session, issuer) = (key(1), key(2));
    let mut cert = session_signed(&session);
    crate::countersign(&mut cert, &issuer).unwrap();
    let (s16, i16) = (&hex_key(&session)[..16], &hex_key(&issuer)[..16]);

    let line = verify(&cert, &Requirements::default()).verdict_line();
    assert!(
        line.contains(&format!(
            "signed by key {s16}…, countersigned by issuer {i16}…"
        )),
        "{line}"
    );
    assert!(line.contains("pass --issuer to check"), "{line}");

    let line = verify(&cert, &required(&hex_key(&issuer))).verdict_line();
    assert!(
        line.contains(&format!("countersigned by the expected issuer {i16}…")),
        "{line}"
    );
    assert!(!line.contains("pass --issuer"), "{line}");

    let pinned_session = Requirements {
        expected_key: Some(hex_key(&session)),
        ..Default::default()
    };
    let line = verify(&cert, &pinned_session).verdict_line();
    assert!(line.contains(&format!("the expected key {s16}…")), "{line}");
    assert!(!line.contains("pass --issuer"), "{line}");
}

/// A stamp embedded as a whole `.ots` file must be for this certificate's
/// tip; one for another digest proves nothing about it.
#[test]
fn an_embedded_ots_file_for_another_digest_fails() {
    let cert = cert_without_findings();
    let tip: [u8; 32] = hex::decode(&cert.ledger_tip_hash)
        .unwrap()
        .try_into()
        .unwrap();
    let other: [u8; 32] = Sha256::digest(b"another tip").into();
    let mut raw = vec![0x00];
    raw.extend([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e, 2, 1, b'c']);
    let ots = |digest: &[u8; 32]| {
        let mut c = cert.clone();
        c.ots_proof_hex = Some(hex::encode(crate::ots::detached_file(digest, &raw)));
        let r = verify(&c, &Requirements::default());
        r.checks.into_iter().find(|c| c.id == "ots").unwrap()
    };
    assert_eq!(ots(&other).status, Status::Fail);
    assert!(ots(&other).detail.contains("different digest"));
    assert_eq!(
        ots(&tip).status,
        Status::Warn,
        "a pending stamp for the tip"
    );
}

/// `--expected-key`: the signer must be that key (any hex case), and a
/// valid signature by another key is a failure, not a pass.
#[test]
fn the_expected_key_must_be_the_signer() {
    let (signer, other) = (key(6), key(7));
    let cert = session_signed(&signer);
    let expecting = |k: String| {
        verify(
            &cert,
            &Requirements {
                expected_key: Some(k),
                ..Default::default()
            },
        )
    };
    let r = expecting(hex_key(&signer).to_uppercase());
    assert_eq!(
        r.verdict,
        Verdict::Valid {
            signer: hex_key(&signer),
            expected: true,
            issuer: None
        }
    );
    let r = expecting(hex_key(&other));
    assert_eq!(r.verdict, Verdict::Invalid);
    let sig = r.checks.iter().find(|c| c.id == "signature").unwrap();
    assert!(
        sig.detail.contains(&format!(
            "not by the expected key {}…",
            &hex_key(&other)[..16]
        )),
        "{sig:?}"
    );
    // Without an expectation the same certificate is valid, and says the
    // key is not known to be anyone's.
    let r = verify(&cert, &Requirements::default());
    assert!(matches!(
        r.verdict,
        Verdict::Valid {
            expected: false,
            ..
        }
    ));
    assert!(r.verdict_line().contains("pass --expected-key to check"));
}

/// Any one requirement makes the run strict; none leaves it an inspection.
#[test]
fn any_requirement_makes_the_mode_strict() {
    let cert = cert_without_findings();
    let mode = |req: Requirements| verify(&cert, &req).mode;
    assert_eq!(mode(Requirements::default()), "inspection");
    for req in [
        Requirements {
            signature: true,
            ..Default::default()
        },
        Requirements {
            anchor: true,
            ..Default::default()
        },
        Requirements {
            issuer: Some("ab".repeat(32)),
            ..Default::default()
        },
    ] {
        assert_eq!(mode(req), "strict");
    }
}

/// What `verify-cert` and the browser page print, without colour: the
/// header, one line per check with its symbol, and the verdict last.
#[test]
fn the_plain_report_reads_as_documented() {
    let r = verify(&session_signed(&key(5)), &Requirements::default());
    let text = r.render(false, true);
    assert!(
        text.starts_with("\nVerifying IronVise Audit Certificate\n  Session : "),
        "{text}"
    );
    assert!(text.contains("  Events  : 4\n"), "{text}");
    assert!(
        text.contains("  Mode    : inspection - reports contents and internal consistency\n"),
        "{text}"
    );
    assert!(text.contains("✓  Signature valid (ed25519)\n"), "{text}");
    assert!(
        text.ends_with(&format!("\n{}\n", r.verdict_line())),
        "{text}"
    );
    assert!(!text.contains('\x1b'), "{text}");
    assert_eq!(r.render(false, false), r.render_checks(false));

    let strict = verify(
        &session_signed(&key(5)),
        &Requirements {
            signature: true,
            ..Default::default()
        },
    );
    assert!(
        strict
            .render(false, false)
            .contains("  Mode    : strict - the requirements below must be met\n")
    );
}

/// Colour goes around the symbol and title of a check, and around only
/// the "CERTIFICATE …" phrase of the verdict: green, yellow, red.
#[test]
fn colour_marks_each_status_and_verdict() {
    let valid = verify(&session_signed(&key(5)), &Requirements::default());
    assert!(
        valid
            .render(true, false)
            .contains("\x1b[32m✓  Signature valid\x1b[0m (ed25519)\n")
    );
    assert!(
        valid
            .render_verdict(true)
            .starts_with("\x1b[32mCERTIFICATE VALID \x1b[0m - session ")
    );

    let unsigned = verify(&cert_without_findings(), &Requirements::default());
    assert!(unsigned.render(true, false).contains("\x1b[33m⚠  "));
    assert!(
        unsigned
            .render_verdict(true)
            .starts_with("\x1b[33mCERTIFICATE INTERNALLY CONSISTENT\x1b[0m - session ")
    );

    let mut tampered = session_signed(&key(5));
    tampered.goal = "changed".into();
    let invalid = verify(&tampered, &Requirements::default());
    assert!(invalid.render(true, false).contains("\x1b[31m✗  "));
    assert_eq!(
        invalid.render_verdict(true),
        "\x1b[31mCERTIFICATE INVALID\x1b[0m - one or more checks failed."
    );
    assert!(invalid.render(true, true).ends_with("checks failed.\n"));
}

/// The canonical form carries no note: only the fallback does.
#[test]
fn a_canonically_signed_certificate_has_no_legacy_note() {
    let r = verify(&session_signed(&key(4)), &Requirements::default());
    let sig = r.checks.iter().find(|c| c.id == "signature").unwrap();
    assert_eq!(sig.status, Status::Pass);
    assert!(sig.notes.is_empty(), "{sig:?}");
}

#[test]
fn a_countersignature_leaves_the_session_signature_valid() {
    let (session, issuer) = (key(1), key(2));
    let mut cert = session_signed(&session);
    crate::countersign(&mut cert, &issuer).unwrap();
    let r = verify(&cert, &required(&hex_key(&issuer)));
    assert_eq!(
        r.verdict,
        Verdict::Valid {
            signer: hex_key(&session),
            expected: false,
            issuer: Some(IssuerVerdict {
                key: hex_key(&issuer),
                expected: true
            }),
        }
    );
    assert!(
        r.verdict_line()
            .contains("countersigned by the expected issuer")
    );
}

#[test]
fn an_issuer_alone_satisfies_strict_but_not_an_expected_session_key() {
    let issuer = key(2);
    let mut cert = cert_without_findings();
    crate::countersign(&mut cert, &issuer).unwrap();
    let strict = Requirements {
        signature: true,
        ..Default::default()
    };
    assert!(matches!(
        verify(&cert, &strict).verdict,
        Verdict::Valid { .. }
    ));
    let by_session = Requirements {
        expected_key: Some(hex_key(&issuer)),
        ..Default::default()
    };
    assert_eq!(verify(&cert, &by_session).verdict, Verdict::Invalid);
}

#[test]
fn a_wrong_missing_or_stale_countersignature_fails() {
    let (session, issuer, other) = (key(1), key(2), key(3));
    let plain = session_signed(&session);
    assert_eq!(
        verify(&plain, &required(&hex_key(&issuer))).verdict,
        Verdict::Invalid,
        "required but missing"
    );
    let mut cert = plain.clone();
    crate::countersign(&mut cert, &other).unwrap();
    assert_eq!(
        verify(&cert, &required(&hex_key(&issuer))).verdict,
        Verdict::Invalid,
        "another issuer"
    );
    let mut stale = cert_without_findings();
    crate::countersign(&mut stale, &issuer).unwrap();
    stale.goal = "edited after signing".into();
    stale.goal_hash = hex::encode(Sha256::digest(stale.goal.as_bytes()));
    assert_eq!(
        verify(&stale, &Requirements::default()).verdict,
        Verdict::Invalid,
        "content changed after the issuer signed"
    );
    // A session signature is not an issuer signature over the same bytes.
    let mut replayed = session_signed(&session);
    replayed.issuer = Some(crate::IssuerSignature {
        public_key: hex_key(&session),
        signature: replayed.signature.clone().unwrap(),
    });
    assert_eq!(
        verify(&replayed, &Requirements::default()).verdict,
        Verdict::Invalid
    );
}

#[test]
fn an_old_certificate_gains_no_issuer_line() {
    let r = verify(&session_signed(&key(1)), &Requirements::default());
    assert!(r.checks.iter().all(|c| c.id != "issuer"));
}

#[test]
fn a_goal_that_does_not_match_its_declared_hash_is_invalid() {
    let mut cert = cert_without_findings();
    cert.goal = "a different goal".to_string();
    assert!(fails(&check_goal_hash(&cert)));
    assert_eq!(
        verify(&cert, &Requirements::default()).verdict,
        Verdict::Invalid
    );
}

#[test]
fn an_event_count_that_disagrees_with_the_event_list_is_invalid() {
    // No gap, and the tip is still correct: only `event_count` lies.
    let mut cert = cert_without_findings();
    cert.event_count = cert.events.len() as u64 + 1;
    assert!(fails(&check_hash_chain(&cert)));
    assert_eq!(
        verify(&cert, &Requirements::default()).verdict,
        Verdict::Invalid
    );
}

#[test]
fn a_certificate_with_no_events_warns_the_chain_check_instead_of_failing_it() {
    let mut cert = cert_without_findings();
    cert.events.clear();
    let chain = check_hash_chain(&cert);
    assert_eq!(chain.status, Status::Warn);
}

#[test]
fn an_absent_enclave_pillar_warns_that_the_session_ran_without_one() {
    let cert = cert_without_findings();
    let check = check_enclave_attestation(&cert);
    assert_eq!(check.status, Status::Warn);
    assert!(check.detail.contains("without an enclave"));
}

#[test]
fn a_present_enclave_pillar_is_reported_but_not_verified() {
    let mut cert = cert_without_findings();
    cert.enclave_attestation = Some(crate::EnclaveAttestationPillar {
        level: crate::EnclaveLevel::AppleHypervisor,
        measurement_hash: "deadbeef".to_string(),
        raw_attestation_hex: Some("aabb".to_string()),
    });
    let check = check_enclave_attestation(&cert);
    assert_eq!(check.status, Status::Warn);
    assert!(check.notes.iter().any(|n| n.contains("apple_hypervisor")));
    assert!(check.notes.iter().any(|n| n.contains("2 bytes")));
}

#[test]
fn a_zk_proof_is_reported_as_present_but_unverified_only_when_attached() {
    let mut cert = cert_without_findings();
    assert!(check_zk_proof(&cert).is_none());
    cert.zk_proof = Some(serde_json::json!({"proof": "abc"}));
    let check = check_zk_proof(&cert).unwrap();
    assert_eq!(check.status, Status::Warn);
}
