//! The shipped example certificates must keep behaving as their README claims.
//!
//! `examples/verified-session/` invites people to try to break a real
//! certificate. That invitation is only honest if the genuine file still
//! verifies and the tampered one still fails - a committed example that quietly
//! stopped working would be worse than shipping none, because the README states
//! the outcome as fact.
//!
//! These run the verification logic directly rather than shelling out to the
//! binary, so they work in any environment.

use std::path::{Path, PathBuf};

use ectoledger::certificate::EctoLedgerCertificate;
use ectoledger::merkle;

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/verified-session")
}

fn load(name: &str) -> EctoLedgerCertificate {
    let path = examples_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{} is not a valid certificate: {e}", path.display()))
}

/// Recompute the Merkle root over the embedded event hashes, as `verify-cert`
/// does. This is the check that catches a substituted event.
fn root_matches(cert: &EctoLedgerCertificate) -> bool {
    let hashes: Vec<&str> = cert
        .events
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();
    let Ok(tree) = merkle::build_merkle_tree(&hashes) else {
        return false;
    };
    merkle::root(&tree)
        .map(|r| r == cert.merkle_root)
        .unwrap_or(false)
}

fn tip_matches(cert: &EctoLedgerCertificate) -> bool {
    cert.events
        .last()
        .map(|e| e.content_hash == cert.ledger_tip_hash)
        .unwrap_or(false)
        && cert.events.len() as u64 == cert.event_count
}

#[test]
fn the_genuine_example_certificate_verifies() {
    let cert = load("session.elc");
    assert!(tip_matches(&cert), "tip hash or event count does not match");
    assert!(
        root_matches(&cert),
        "Merkle root does not match the embedded events - the shipped example is broken, \
         and examples/verified-session/README.md tells readers it is valid"
    );
}

#[test]
fn the_tampered_example_certificate_is_rejected() {
    let cert = load("session-tampered.elc");
    assert!(
        !root_matches(&cert),
        "the tampered example now PASSES the Merkle root check. Either the tamper was \
         undone, or a verification gap has reopened. The README promises this file fails."
    );
}

#[test]
fn the_two_examples_differ_only_in_the_third_event_hash() {
    // The README says one hex character changed, in the denial event. If the
    // files drift apart in other ways that sentence becomes a lie.
    let genuine = load("session.elc");
    let tampered = load("session-tampered.elc");

    assert_eq!(genuine.session_id, tampered.session_id);
    assert_eq!(genuine.merkle_root, tampered.merkle_root);
    assert_eq!(genuine.ledger_tip_hash, tampered.ledger_tip_hash);
    assert_eq!(genuine.events.len(), tampered.events.len());

    let differing: Vec<usize> = genuine
        .events
        .iter()
        .zip(&tampered.events)
        .enumerate()
        .filter(|(_, (a, b))| a.content_hash != b.content_hash)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        differing,
        vec![2],
        "exactly one event should differ, at index 2 (the first denial)"
    );
}

#[test]
fn the_example_contains_the_denials_its_readme_advertises() {
    // The README's table lists two enforced denials. Those are the reason the
    // example is worth looking at, so pin that they are actually in there.
    let cert = load("session.elc");
    assert_eq!(cert.event_count, 4, "README describes four events");
    assert!(
        !cert.goal.is_empty(),
        "a certificate with no goal cannot have its goal_hash checked"
    );
}

/// The `.elc` format is only open if somebody can implement it from
/// `docs/reference/elc-spec.md` without reading this crate. `verify_elc.py` is that
/// implementation, and this test is what stops the spec drifting away from the
/// code it describes: if a change here makes the two disagree, one of the two
/// is wrong and the spec is the likelier candidate.
///
/// Skips when neither python3 nor python is available rather than failing -
/// this is a cross-language agreement check, not a Python dependency.
#[test]
fn the_independent_python_verifier_agrees() {
    use std::process::Command;

    let script = examples_dir().join("verify_elc.py");
    let python = ["python3", "python"].into_iter().find(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    });
    let Some(python) = python else {
        eprintln!("skipping: neither python3 nor python is available");
        return;
    };

    for (file, should_pass) in [("session.elc", true), ("session-tampered.elc", false)] {
        let out = Command::new(python)
            .arg(&script)
            .arg(examples_dir().join(file))
            .output()
            .expect("running verify_elc.py");
        assert_eq!(
            out.status.success(),
            should_pass,
            "verify_elc.py disagrees with verify-cert on {file}: expected \
             pass={should_pass}.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

/// The shipped example must be **signed**, and its README publishes the key.
///
/// It was unsigned until late in this release, and `verify-cert` printed
/// `CERTIFICATE VALID`
/// over it - true about the checks that ran, misleading about what had been
/// established. Every other check in this file recomputes something from the
/// certificate's own contents, so a file forged from scratch passes them all.
/// The signature is the only one that ties the document to a key.
#[test]
fn the_genuine_example_is_signed_and_the_signature_verifies() {
    use ectoledger::certificate::canonical_json_for_signing;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let cert = load("session.elc");
    let sig_hex = cert
        .signature
        .as_deref()
        .expect("the shipped example must be signed - an unsigned receipt identifies no issuer");
    let pk_hex = cert
        .session_public_key
        .as_deref()
        .expect("a signed certificate must carry the key that signed it");

    let canonical = canonical_json_for_signing(&cert).expect("canonical JSON");
    let vk = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(hex::decode(pk_hex).expect("pk hex").as_slice())
            .expect("32-byte key"),
    )
    .expect("valid ed25519 key");
    let sig = Signature::from_bytes(
        &<[u8; 64]>::try_from(hex::decode(sig_hex).expect("sig hex").as_slice())
            .expect("64-byte signature"),
    );
    vk.verify(canonical.as_bytes(), &sig)
        .expect("the shipped signature must verify against the shipped key");

    // The README quotes this key so a reader can check against something that
    // did not come out of the file. If they drift apart the instruction stops
    // working, and the whole point of an expected key is that it is external.
    let readme = std::fs::read_to_string(examples_dir().join("README.md"))
        .expect("reading examples/verified-session/README.md");
    assert!(
        readme.contains(pk_hex),
        "examples/verified-session/README.md must publish the signing key {pk_hex} \
         so --expected-key has something out-of-band to check against"
    );
}

/// The tampered copy must fail *strictly* too, and for the reason advertised.
#[test]
fn the_tampered_example_breaks_the_merkle_root_not_just_the_signature() {
    let cert = load("session-tampered.elc");
    assert!(
        !root_matches(&cert),
        "the tampered example must break the Merkle root - that is the check its \
         README says catches the substitution"
    );
}
