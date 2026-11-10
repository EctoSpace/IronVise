use super::*;

fn tip() -> [u8; 32] {
    Sha256::digest(b"tip").into()
}

/// append, sha256, then a pending attestation for `url`.
fn pending_stamp(url: &str) -> Vec<u8> {
    let mut b = vec![0xf0, 4, 1, 2, 3, 4, 0x08, 0x00];
    b.extend_from_slice(&TAG_PENDING);
    let mut payload = vec![url.len() as u8];
    payload.extend_from_slice(url.as_bytes());
    b.push(payload.len() as u8);
    b.extend_from_slice(&payload);
    b
}

#[test]
fn a_raw_pending_stamp_names_its_calendar() {
    let s = parse(&pending_stamp("https://a.pool.example"), &tip()).unwrap();
    assert_eq!(s.calendars(), vec!["https://a.pool.example"]);
    assert!(s.bitcoin().is_none());
    assert!(s.file_digest.is_none());
}

#[test]
fn a_bitcoin_attestation_reports_height_and_the_root_to_check() {
    // fork: one branch pending, one sha256 then Bitcoin at height 800000.
    let mut b = vec![0xff];
    b.extend(pending_stamp("https://c"));
    b.extend([0x08, 0x00]);
    b.extend_from_slice(&TAG_BITCOIN);
    b.extend([3, 0x80, 0xea, 0x30]); // varuint 800000
    let s = parse(&b, &tip()).unwrap();
    let (h, root) = s.bitcoin().unwrap();
    assert_eq!(h, 800_000);
    let mut expect = Sha256::digest(tip()).to_vec();
    expect.reverse();
    assert_eq!(root, Some(hex::encode(expect).as_str()));
    assert_eq!(s.calendars(), vec!["https://c"]);
}

#[test]
fn a_detached_file_round_trips_and_names_its_digest() {
    let raw = pending_stamp("https://a");
    let file = detached_file(&tip(), &raw);
    let s = parse(&file, b"ignored for files").unwrap();
    assert_eq!(s.file_digest.as_deref(), Some(&tip()[..]));
    assert_eq!(raw_timestamp(&file), Some(&raw[..]));
}

/// `ops`, then a Bitcoin attestation at height 1.
fn bitcoin_after(ops: &[u8]) -> Vec<u8> {
    let mut b = ops.to_vec();
    b.push(0x00);
    b.extend_from_slice(&TAG_BITCOIN);
    b.extend([1, 1]);
    b
}

fn root_of(stamp: &[u8]) -> String {
    let s = parse(stamp, &tip()).unwrap();
    s.bitcoin().unwrap().1.unwrap().to_string()
}

/// The root a block must carry, from `digest`: displayed byte order.
fn displayed(digest: &[u8]) -> String {
    let mut be = digest.to_vec();
    be.reverse();
    hex::encode(be)
}

/// Append puts its argument after the message, prepend before: the root
/// differs, and each is exactly the reference client's.
#[test]
fn append_and_prepend_lead_to_different_known_roots() {
    let arg = [1u8, 2, 3, 4];
    let appended = Sha256::digest([&tip()[..], &arg].concat());
    let prepended = Sha256::digest([&arg[..], &tip()].concat());
    assert_eq!(
        root_of(&bitcoin_after(&[0xf0, 4, 1, 2, 3, 4, 0x08])),
        displayed(&appended)
    );
    assert_eq!(
        root_of(&bitcoin_after(&[0xf1, 4, 1, 2, 3, 4, 0x08])),
        displayed(&prepended)
    );
}

#[test]
fn reverse_and_hexlify_are_computed() {
    let mut reversed = tip();
    reversed.reverse();
    assert_eq!(
        root_of(&bitcoin_after(&[0xf2, 0x08])),
        displayed(&Sha256::digest(reversed))
    );
    assert_eq!(
        root_of(&bitcoin_after(&[0xf3, 0x08])),
        displayed(&Sha256::digest(hex::encode(tip())))
    );
}

/// sha1, ripemd160 and keccak256 are read but not computed: the height is
/// reported, the root is not guessed.
#[test]
fn an_uncomputed_operation_reports_no_root() {
    for op in [0x02, 0x03, 0x67] {
        let s = parse(&bitcoin_after(&[op]), &tip()).unwrap();
        assert_eq!(s.bitcoin(), Some((1, None)), "op 0x{op:02x}");
    }
}

/// A detached file may name its digest by any of the reference client's
/// file hashes, each with its own length; anything else is refused.
#[test]
fn every_file_hash_operation_is_read_at_its_length() {
    let raw = pending_stamp("https://a");
    for (op, len) in [(0x08u8, 32usize), (0x02, 20), (0x03, 20), (0x67, 32)] {
        let mut file = FILE_MAGIC.to_vec();
        file.extend([0x01, op]);
        file.extend(vec![7u8; len]);
        file.extend(&raw);
        let s = parse(&file, b"").unwrap_or_else(|e| panic!("op 0x{op:02x}: {e}"));
        assert_eq!(s.file_digest, Some(vec![7u8; len]), "op 0x{op:02x}");
        assert_eq!(s.calendars(), vec!["https://a"]);
    }
    let mut unknown = FILE_MAGIC.to_vec();
    unknown.extend([0x01, 0x09]);
    unknown.extend([0u8; 32]);
    assert!(parse(&unknown, b"").unwrap_err().contains("0x09"));
    let mut version2 = FILE_MAGIC.to_vec();
    version2.extend([0x02, 0x08]);
    assert!(parse(&version2, b"").unwrap_err().contains("version 2"));
}

/// Nesting up to the limit parses; one more is refused rather than
/// recursing on.
#[test]
fn nesting_is_limited_at_exactly_its_depth() {
    let at = |n: usize| bitcoin_after(&vec![0xf2; n]);
    assert!(parse(&at(MAX_DEPTH), &tip()).is_ok());
    assert!(
        parse(&at(MAX_DEPTH + 1), &tip())
            .unwrap_err()
            .contains("too deeply")
    );
}

/// A length-prefixed field may be 8192 bytes, and not one more.
#[test]
fn a_field_is_limited_at_exactly_8192_bytes() {
    let with_arg = |n: usize| {
        // varuint(n) for n < 2^14: two bytes.
        let mut ops = vec![0xf0, (n & 0x7f) as u8 | 0x80, (n >> 7) as u8];
        ops.extend(vec![0u8; n]);
        ops.push(0x08);
        bitcoin_after(&ops)
    };
    assert!(parse(&with_arg(8192), &tip()).is_ok());
    assert!(
        parse(&with_arg(8193), &tip())
            .unwrap_err()
            .contains("8193 bytes")
    );
}

#[test]
fn trailing_bytes_are_refused() {
    let mut b = pending_stamp("https://a");
    b.push(0);
    assert!(parse(&b, &tip()).unwrap_err().contains("1 trailing"));
}

/// The raw timestamp comes back out of a detached file only when the file
/// is version 1, sha256, and has a timestamp after the digest.
#[test]
fn a_raw_timestamp_is_read_only_from_a_sha256_version_1_file() {
    let raw = pending_stamp("https://a");
    let file = detached_file(&tip(), &raw);
    assert_eq!(raw_timestamp(&file), Some(&raw[..]));
    let header = FILE_MAGIC.len();
    let mut v2 = file.clone();
    v2[header] = 0x02;
    assert_eq!(raw_timestamp(&v2), None);
    let mut sha1 = file.clone();
    sha1[header + 1] = 0x02;
    assert_eq!(raw_timestamp(&sha1), None);
    assert_eq!(raw_timestamp(&detached_file(&tip(), &[])), None);
    assert_eq!(
        raw_timestamp(&detached_file(&tip(), &[0x00])),
        Some(&[0x00][..])
    );
    assert_eq!(raw_timestamp(&raw), None);
}

fn cert_with(stamp: Option<String>, tip_hex: String) -> crate::EctoLedgerCertificate {
    crate::EctoLedgerCertificate {
        version: 1,
        session_id: uuid::Uuid::nil(),
        goal: String::new(),
        goal_hash: String::new(),
        policy_hash: None,
        session_public_key: None,
        ledger_tip_hash: tip_hex,
        merkle_root: String::new(),
        event_count: 0,
        started_at: String::new(),
        completed_at: None,
        events: vec![],
        findings: vec![],
        ots_proof_hex: stamp,
        zk_proof: None,
        enclave_attestation: None,
        signature: None,
        issuer: None,
    }
}

#[test]
fn a_certificates_stamp_becomes_the_file_ots_reads() {
    let raw = pending_stamp("https://a");
    let cert = cert_with(Some(hex::encode(&raw)), hex::encode(tip()));
    assert_eq!(detached_for(&cert).unwrap(), detached_file(&tip(), &raw));
    // A stamp that already is a file is handed back as it is.
    let file = detached_file(&tip(), &raw);
    let cert = cert_with(Some(hex::encode(&file)), String::new());
    assert_eq!(detached_for(&cert).unwrap(), file);
}

#[test]
fn a_certificate_without_a_readable_stamp_has_no_file() {
    let raw = hex::encode(pending_stamp("https://a"));
    for (stamp, tip_hex, why) in [
        (None, hex::encode(tip()), "no OTS stamp"),
        (Some("zz".to_string()), hex::encode(tip()), "not hex"),
        (Some(raw.clone()), "abcd".to_string(), "32-byte"),
        (
            Some("05".to_string()),
            hex::encode(tip()),
            "unknown operation",
        ),
    ] {
        let err = detached_for(&cert_with(stamp, tip_hex)).unwrap_err();
        assert!(err.contains(why), "{err}");
    }
}

#[test]
fn garbage_is_an_error_not_a_panic() {
    for b in [
        vec![],
        vec![0x05; 32],
        vec![0xf0, 0xff, 0xff, 0xff, 0xff],
        vec![0xff; 300],
    ] {
        assert!(parse(&b, &tip()).is_err(), "{b:?}");
    }
}
