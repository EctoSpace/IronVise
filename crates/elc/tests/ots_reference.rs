//! The OpenTimestamps parser against bytes from the reference implementation.
//!
//! `fixtures/reference-bitcoin.ots` was serialized by python-opentimestamps
//! (`fixtures/make_reference_ots.py`) over the shipped example certificate's
//! tip, with a pending branch and a Bitcoin branch at height 800000. The
//! reference client's `ots info` prints Merkle root
//! 98d0db0e510a2d70f2da2d077457cee50d28a5b6ccacb783b75c343e2c37b76c for that
//! branch; the Rust parser must agree.

use ectoledger_elc::verify::{Requirements, verify};
use ectoledger_elc::{EctoLedgerCertificate, ots};

const FIXTURE: &[u8] = include_bytes!("fixtures/reference-bitcoin.ots");

fn example() -> EctoLedgerCertificate {
    serde_json::from_str(include_str!(
        "../../../examples/verified-session/session.elc"
    ))
    .unwrap()
}

#[test]
fn reads_the_reference_file_like_the_reference_client() {
    let cert = example();
    let tip = hex::decode(&cert.ledger_tip_hash).unwrap();
    let stamp = ots::parse(FIXTURE, &tip).unwrap();
    assert_eq!(stamp.file_digest.as_deref(), Some(&tip[..]));
    assert_eq!(
        stamp.bitcoin(),
        Some((
            800_000,
            Some("98d0db0e510a2d70f2da2d077457cee50d28a5b6ccacb783b75c343e2c37b76c")
        ))
    );
    assert_eq!(stamp.calendars(), vec!["https://calendar.example"]);
}

#[test]
fn a_kept_ots_file_satisfies_require_anchor() {
    let req = Requirements {
        anchor: true,
        ots_file: Some(FIXTURE.to_vec()),
        ..Default::default()
    };
    let r = verify(&example(), &req);
    assert!(r.anchored);
    assert!(r.is_valid(), "{}", r.render(false, true));
}

#[test]
fn without_it_the_embedded_calendar_promise_does_not() {
    let req = Requirements {
        anchor: true,
        ..Default::default()
    };
    assert!(!verify(&example(), &req).is_valid());
}
