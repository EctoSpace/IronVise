use super::SessionVerdict as V;

/// `kind` is an API: the SDKs, the desktop app and the answer key of
/// `examples/challenge` compare against these strings. Changing one is a
/// breaking change, so it must fail here first.
#[test]
fn every_verdict_has_its_stable_name() {
    let names = [
        (
            V::Verified {
                signatures: 1,
                unsigned: 0,
            },
            "verified",
        ),
        (V::Unsigned { events: 1 }, "unsigned"),
        (
            V::MissingSignature {
                sequence: 1,
                kind: "action".into(),
            },
            "missing-signature",
        ),
        (V::NoSignatures { events: 1 }, "no-signatures"),
        (
            V::PayloadHashMismatch { sequence: 1 },
            "payload-hash-mismatch",
        ),
        (
            V::AlteredAfterSigning { sequence: 1 },
            "altered-after-signing",
        ),
        (V::BadSignature { sequence: 1 }, "bad-signature"),
        (V::UnauthorisedKey { sequence: 1 }, "unauthorised-key"),
        (
            V::TruncatedSinceSealing {
                sealed_events: 2,
                found_events: 1,
            },
            "truncated-since-sealing",
        ),
    ];
    for (verdict, name) in &names {
        assert_eq!(verdict.kind(), *name);
        assert_eq!(verdict.is_verified(), *name == "verified");
    }
    let challenge = include_str!("../../../../examples/challenge/README.md");
    for name in [
        "verified",
        "payload-hash-mismatch",
        "altered-after-signing",
        "truncated-since-sealing",
        "bad-signature",
        "unauthorised-key",
    ] {
        assert!(challenge.contains(&format!("`{name}`")), "{name}");
        assert!(names.iter().any(|(_, n)| *n == name), "{name}");
    }
}

/// What `verify-session` prints: each verdict names the numbers a reader
/// needs to find the problem.
#[test]
fn every_verdict_says_where_the_problem_is() {
    let says = |v: V, parts: &[&str]| {
        let text = v.to_string();
        for part in parts {
            assert!(text.contains(part), "{text:?} lacks {part:?}");
        }
    };
    says(
        V::Verified {
            signatures: 3,
            unsigned: 0,
        },
        &["all 3 event signatures verified"],
    );
    says(
        V::Verified {
            signatures: 3,
            unsigned: 2,
        },
        &["all 3 event signatures", "2 further event(s)"],
    );
    says(
        V::Unsigned { events: 4 },
        &["the 4 event(s)", "no public key"],
    );
    says(V::NoSignatures { events: 4 }, &["none of its 4 event(s)"]);
    says(
        V::MissingSignature {
            sequence: 7,
            kind: "action".into(),
        },
        &["event 7", "`action`"],
    );
    says(
        V::PayloadHashMismatch { sequence: 8 },
        &["event 8", "edited"],
    );
    says(
        V::AlteredAfterSigning { sequence: 9 },
        &["event 9", "altered after signing"],
    );
    says(
        V::BadSignature { sequence: 10 },
        &["event 10", "does not verify"],
    );
    says(
        V::UnauthorisedKey { sequence: 11 },
        &["event 11", "not authorised"],
    );
    says(
        V::TruncatedSinceSealing {
            sealed_events: 5,
            found_events: 3,
        },
        &["sealed with 5 events but has 3"],
    );
}

/// A session with no events has nothing to fail: it verifies, with or
/// without a key. "No signatures" needs events that should have had them.
#[test]
fn an_empty_session_verifies_and_a_wholly_unsigned_one_does_not() {
    use super::SignatureCoverage;
    for has_key in [true, false] {
        assert_eq!(
            SignatureCoverage::default().finish(has_key),
            V::Verified {
                signatures: 0,
                unsigned: 0
            }
        );
    }
    let mut c = SignatureCoverage::default();
    c.unsigned(1, r#"{"type":"observation","content":"x"}"#)
        .unwrap();
    assert_eq!(c.finish(true), V::NoSignatures { events: 1 });
    let mut c = SignatureCoverage::default();
    c.unsigned(1, r#"{"type":"observation","content":"x"}"#)
        .unwrap();
    assert_eq!(c.finish(false), V::Unsigned { events: 1 });
    let mut c = SignatureCoverage::default();
    c.signed(r#"{"type":"thought","content":"x"}"#);
    c.unsigned(2, r#"{"type":"observation","content":"x"}"#)
        .unwrap();
    assert_eq!(
        c.finish(true),
        V::Verified {
            signatures: 1,
            unsigned: 1
        }
    );
}
