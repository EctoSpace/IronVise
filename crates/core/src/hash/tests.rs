use super::*;

#[test]
fn genesis_hash_is_64_hex_chars() {
    let h = compute_content_hash(
        GENESIS_PREVIOUS_HASH,
        0,
        r#"{"type":"genesis","message":"test"}"#,
        None,
        None,
    );
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn same_input_same_hash() {
    let a = compute_content_hash(GENESIS_PREVIOUS_HASH, 1, "{}", None, None);
    let b = compute_content_hash(GENESIS_PREVIOUS_HASH, 1, "{}", None, None);
    assert_eq!(a, b);
}

/// Regression: previously sequence/payload boundary shift produced collisions.
#[test]
fn no_sequence_payload_collision() {
    let a = compute_content_hash(GENESIS_PREVIOUS_HASH, 1, "23{}", None, None);
    let b = compute_content_hash(GENESIS_PREVIOUS_HASH, 12, "3{}", None, None);
    let c = compute_content_hash(GENESIS_PREVIOUS_HASH, 123, "{}", None, None);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

/// session_id included in hash prevents cross-session replay.
#[test]
fn session_id_changes_hash() {
    let without = compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", None, None);
    let with_a = compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", Some("aaaa-bbbb-cccc"), None);
    let with_b = compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", Some("xxxx-yyyy-zzzz"), None);
    assert_ne!(without, with_a, "session_id must change the hash");
    assert_ne!(
        with_a, with_b,
        "different sessions must produce different hashes"
    );
}

/// created_at timestamp included in hash prevents timestamp manipulation.
#[test]
fn timestamp_changes_hash() {
    let without = compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", None, None);
    let with_ts_a = compute_content_hash(
        GENESIS_PREVIOUS_HASH,
        0,
        "{}",
        None,
        Some("2025-01-01T00:00:00Z"),
    );
    let with_ts_b = compute_content_hash(
        GENESIS_PREVIOUS_HASH,
        0,
        "{}",
        None,
        Some("2025-06-01T12:00:00Z"),
    );
    assert_ne!(without, with_ts_a, "timestamp must change the hash");
    assert_ne!(
        with_ts_a, with_ts_b,
        "different timestamps must produce different hashes"
    );
}

/// session_id AND timestamp together are both bound.
#[test]
fn session_and_timestamp_combined() {
    let base = compute_content_hash(
        GENESIS_PREVIOUS_HASH,
        0,
        "{}",
        Some("sess-1"),
        Some("2025-01-01T00:00:00Z"),
    );
    let diff_ts = compute_content_hash(
        GENESIS_PREVIOUS_HASH,
        0,
        "{}",
        Some("sess-1"),
        Some("2025-06-01T00:00:00Z"),
    );
    let diff_sid = compute_content_hash(
        GENESIS_PREVIOUS_HASH,
        0,
        "{}",
        Some("sess-2"),
        Some("2025-01-01T00:00:00Z"),
    );
    assert_ne!(base, diff_ts);
    assert_ne!(base, diff_sid);
    assert_ne!(diff_ts, diff_sid);
}

/// Regression: sha256_pair boundary shift must produce distinct hashes.
#[test]
fn sha256_pair_no_boundary_collision() {
    let a = sha256_pair(b"prompt_text", b"response");
    let b_hash = sha256_pair(b"prompt_tex", b"tresponse");
    assert_ne!(a, b_hash);
}

const TS: &str = "2025-01-01T00:00:00.123456+00:00";

/// v2 binds both fields and is domain-separated from every v1 layout.
#[test]
fn v2_differs_from_all_v1_layouts() {
    let v2 = compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 0, "{}", Some("sess-1"), TS);
    for v1 in [
        compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", Some("sess-1"), Some(TS)),
        compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", Some("sess-1"), None),
        compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", None, Some(TS)),
        compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", None, None),
    ] {
        assert_ne!(v2, v1, "v2 must not collide with any v1 layout");
    }
}

/// v2 changes when either session_id or created_at changes.
#[test]
fn v2_binds_session_and_timestamp() {
    let base = compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 0, "{}", Some("sess-1"), TS);
    let diff_sid = compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 0, "{}", Some("sess-2"), TS);
    let diff_ts = compute_content_hash_v2(
        GENESIS_PREVIOUS_HASH,
        0,
        "{}",
        Some("sess-1"),
        "2025-06-01T00:00:00.000001+00:00",
    );
    let no_sid = compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 0, "{}", None, TS);
    assert_ne!(base, diff_sid);
    assert_ne!(base, diff_ts);
    assert_ne!(base, no_sid);
}

/// The multi-scheme verifier identifies each scheme, newest first.
#[test]
fn verifier_detects_every_scheme() {
    let prev = GENESIS_PREVIOUS_HASH;
    let sid = Some("sess-1");
    let cases: Vec<(String, HashScheme)> = vec![
        (
            compute_content_hash_v2(prev, 3, "{}", sid, TS),
            HashScheme::V2,
        ),
        (
            compute_content_hash(prev, 3, "{}", sid, Some(TS)),
            HashScheme::V1SessionTimestamp,
        ),
        (
            compute_content_hash(prev, 3, "{}", sid, None),
            HashScheme::V1SessionOnly,
        ),
        (
            compute_content_hash(prev, 3, "{}", None, Some(TS)),
            HashScheme::V1TimestampOnly,
        ),
        (
            compute_content_hash(prev, 3, "{}", None, None),
            HashScheme::V1Legacy,
        ),
    ];
    for (stored, expected_scheme) in cases {
        let got = verify_content_hash_any_scheme(prev, 3, "{}", sid, Some(TS), &stored);
        assert_eq!(got, Some(expected_scheme));
    }
    // A tampered hash matches no scheme.
    let tampered = "f".repeat(64);
    assert_eq!(
        verify_content_hash_any_scheme(prev, 3, "{}", sid, Some(TS), &tampered),
        None
    );
}

/// The input layouts, byte for byte. Every stored `content_hash` was
/// computed over one of these; if a layout changes, existing ledgers stop
/// verifying, so a change must fail here first.
#[test]
fn content_hash_inputs_are_pinned() {
    let prev = GENESIS_PREVIOUS_HASH;
    let bytes = |parts: &[&str]| parts.concat().into_bytes();
    assert_eq!(
        content_hash_input_v2(prev, 3, "{}", Some("sess-1"), TS),
        bytes(&["ELv2\0", prev, "\0", "3", "\0{}\0sess-1\0", TS])
    );
    assert_eq!(
        content_hash_input_v2(prev, 3, "{}", None, TS),
        bytes(&["ELv2\0", prev, "\0", "3", "\0{}\0\0", TS])
    );
    assert_eq!(
        content_hash_input(prev, 3, "{}", Some("sess-1"), Some(TS)),
        bytes(&[prev, "\0", "3", "\0{}\0sess-1\0", TS])
    );
    assert_eq!(
        content_hash_input(prev, 3, "{}", Some("sess-1"), None),
        bytes(&[prev, "\0", "3", "\0{}\0sess-1"])
    );
    assert_eq!(
        content_hash_input(prev, 3, "{}", None, Some(TS)),
        bytes(&[prev, "\0", "3", "\0{}\0", TS])
    );
    assert_eq!(
        content_hash_input(prev, 3, "{}", None, None),
        bytes(&[prev, "\0", "3", "\0{}"])
    );
}

/// SHA-256 digests computed independently (Python `hashlib`) over the
/// layouts above, and over `sha256_pair`'s length-prefixed input.
#[test]
fn sha256_digests_match_independently_computed_values() {
    let prev = GENESIS_PREVIOUS_HASH;
    let digest = |input: Vec<u8>| sha256_hex_legacy(&input);
    assert_eq!(
        digest(content_hash_input_v2(prev, 3, "{}", Some("sess-1"), TS)),
        "08d76ccd1ebdc35093fa9422b44ed3fe24de0fe5cabeb049235a26c1106ab736"
    );
    assert_eq!(
        digest(content_hash_input_v2(prev, 3, "{}", None, TS)),
        "1e3248703ae593bc6c14baefc1de29243b84079a0b23dc822ae50520dc34a353"
    );
    assert_eq!(
        digest(content_hash_input(prev, 3, "{}", Some("sess-1"), Some(TS))),
        "73f10048355ebc6e8e4c7cbaad1c736a79837ef44a0a08385d5f435be02a0ff7"
    );
    assert_eq!(
        digest(content_hash_input(prev, 3, "{}", None, None)),
        "f8477e0fa1500d76bbb3e1d2c6486026c194615381e893c22035404ab1718ef2"
    );
    assert_eq!(
        sha256_pair(b"prompt", b"response"),
        "2073110907f71dd12628c61ad98426d9362342689024671f818a0c3216f6ceb7"
    );
}

/// Without `hash-blake3`, the chain hash is SHA-256, so the stored hashes
/// above are exactly what a default build writes and reads.
#[cfg(not(feature = "hash-blake3"))]
#[test]
fn the_default_chain_hash_is_sha256() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 3, "{}", Some("sess-1"), TS),
        "08d76ccd1ebdc35093fa9422b44ed3fe24de0fe5cabeb049235a26c1106ab736"
    );
}

/// A BLAKE3 build writes BLAKE3 and still verifies every SHA-256 event
/// written before the switch.
#[cfg(feature = "hash-blake3")]
#[test]
fn a_blake3_build_still_verifies_sha256_events() {
    let sha256_v2 = "08d76ccd1ebdc35093fa9422b44ed3fe24de0fe5cabeb049235a26c1106ab736";
    assert_ne!(
        compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 3, "{}", Some("sess-1"), TS),
        sha256_v2
    );
    assert_eq!(
        verify_content_hash_any_scheme(
            GENESIS_PREVIOUS_HASH,
            3,
            "{}",
            Some("sess-1"),
            Some(TS),
            sha256_v2
        ),
        Some(HashScheme::V2)
    );
}

/// Each field is bound: the hash of one event does not verify as another
/// sequence, payload, predecessor, session or time.
#[test]
fn a_hash_verifies_only_its_own_event() {
    let prev = GENESIS_PREVIOUS_HASH;
    let stored = compute_content_hash_v2(prev, 3, "{}", Some("sess-1"), TS);
    let check = |prev: &str, seq, payload, sid, ts| {
        verify_content_hash_any_scheme(prev, seq, payload, sid, ts, &stored)
    };
    assert_eq!(
        check(prev, 3, "{}", Some("sess-1"), Some(TS)),
        Some(HashScheme::V2)
    );
    assert_eq!(
        check(&"1".repeat(64), 3, "{}", Some("sess-1"), Some(TS)),
        None
    );
    assert_eq!(check(prev, 4, "{}", Some("sess-1"), Some(TS)), None);
    assert_eq!(check(prev, 3, "{ }", Some("sess-1"), Some(TS)), None);
    assert_eq!(check(prev, 3, "{}", Some("sess-2"), Some(TS)), None);
    assert_eq!(check(prev, 3, "{}", Some("sess-1"), None), None);
}

/// Rows without a stored timestamp can only be the layouts that had none.
#[test]
fn without_a_timestamp_only_the_timeless_layouts_are_tried() {
    let prev = GENESIS_PREVIOUS_HASH;
    let sid_only = compute_content_hash(prev, 3, "{}", Some("sess-1"), None);
    let legacy = compute_content_hash(prev, 3, "{}", None, None);
    assert_eq!(
        verify_content_hash_any_scheme(prev, 3, "{}", Some("sess-1"), None, &sid_only),
        Some(HashScheme::V1SessionOnly)
    );
    assert_eq!(
        verify_content_hash_any_scheme(prev, 3, "{}", None, None, &legacy),
        Some(HashScheme::V1Legacy)
    );
    assert_eq!(
        verify_content_hash_any_scheme(prev, 3, "{}", None, None, &sid_only),
        None,
        "a session-bound hash needs its session"
    );
}

/// Relying parties recompute a goal hash as SHA-256, in every build.
#[test]
fn a_goal_hash_is_sha256_in_every_build() {
    assert_eq!(
        goal_hash("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(goal_hash_matches(&goal_hash("abc"), "abc"));
    assert!(!goal_hash_matches(&goal_hash("abc"), "abd"));
    assert!(!goal_hash_matches("", "abc"));
}

/// A session a BLAKE3 build created before the fix stored BLAKE3; it
/// still matches in such a build, and only there.
#[test]
fn an_old_blake3_goal_hash_matches_only_in_a_blake3_build() {
    let old = hex::encode(blake3_or_sha256(b"abc"));
    assert_eq!(
        goal_hash_matches(&old, "abc"),
        cfg!(feature = "hash-blake3")
    );
}

#[cfg(feature = "hash-blake3")]
fn blake3_or_sha256(input: &[u8]) -> Vec<u8> {
    blake3::hash(input).as_bytes().to_vec()
}

/// Without the feature there is no BLAKE3 to compute; a value that is not
/// SHA-256 stands in for it.
#[cfg(not(feature = "hash-blake3"))]
fn blake3_or_sha256(input: &[u8]) -> Vec<u8> {
    let mut h = Sha256::digest(input).to_vec();
    h[0] ^= 0xff;
    h
}

/// An event without a session still verifies as v2 (empty-string binding).
#[test]
fn verifier_v2_without_session() {
    let stored = compute_content_hash_v2(GENESIS_PREVIOUS_HASH, 0, "{}", None, TS);
    assert_eq!(
        verify_content_hash_any_scheme(GENESIS_PREVIOUS_HASH, 0, "{}", None, Some(TS), &stored),
        Some(HashScheme::V2)
    );
}

#[cfg(not(feature = "hash-blake3"))]
#[test]
fn sha256_hex_of_empty_input_is_the_well_known_digest() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[cfg(not(feature = "hash-blake3"))]
#[test]
fn sha256_hex_of_one_megabyte_input() {
    let data = vec![b'a'; 1024 * 1024];
    assert_eq!(
        sha256_hex(&data),
        "9bc1b2a288b26af7257a36277ae3816a7d4f16e89c1e7e77d0a5c48bad62b360"
    );
}

#[cfg(not(feature = "hash-blake3"))]
#[test]
fn sha256_hex_of_non_utf8_bytes() {
    let data: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28];
    assert!(
        std::str::from_utf8(&data).is_err(),
        "fixture must be non-UTF-8"
    );
    assert_eq!(
        sha256_hex(&data),
        "d90106ba0c7d9f14011254c532818d6fadf524dfde8e271ddfb22bbdb4b5fb6c"
    );
}

#[test]
fn sha256_hex_legacy_is_always_sha256_regardless_of_feature() {
    assert_eq!(
        sha256_hex_legacy(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn goal_hash_of_empty_goal_is_stable() {
    let h = goal_hash("");
    assert_eq!(h.len(), 64);
    assert!(goal_hash_matches(&h, ""));
}

#[test]
fn goal_hash_matches_is_case_sensitive_on_the_stored_hash() {
    let h = goal_hash("abc");
    assert!(!goal_hash_matches(&h.to_uppercase(), "abc"));
}

#[test]
fn goal_hash_matches_is_sensitive_to_goal_case_and_whitespace() {
    let h = goal_hash("abc");
    assert!(!goal_hash_matches(&h, "ABC"));
    assert!(!goal_hash_matches(&h, " abc"));
    assert!(!goal_hash_matches(&h, "abc "));
    assert!(!goal_hash_matches(&h, "abc\n"));
}

#[test]
fn verify_any_scheme_rejects_uppercase_hex() {
    let prev = GENESIS_PREVIOUS_HASH;
    let stored = compute_content_hash_v2(prev, 0, "{}", Some("s"), TS);
    assert_eq!(
        verify_content_hash_any_scheme(prev, 0, "{}", Some("s"), Some(TS), &stored.to_uppercase()),
        None
    );
}

#[test]
fn verify_any_scheme_rejects_whitespace_padded_hash() {
    let prev = GENESIS_PREVIOUS_HASH;
    let stored = compute_content_hash_v2(prev, 0, "{}", Some("s"), TS);
    let padded = format!(" {stored}");
    assert_eq!(
        verify_content_hash_any_scheme(prev, 0, "{}", Some("s"), Some(TS), &padded),
        None
    );
    let trailing = format!("{stored}\n");
    assert_eq!(
        verify_content_hash_any_scheme(prev, 0, "{}", Some("s"), Some(TS), &trailing),
        None
    );
}

#[test]
fn verify_any_scheme_rejects_wrong_length_hash() {
    let prev = GENESIS_PREVIOUS_HASH;
    let stored = compute_content_hash_v2(prev, 0, "{}", Some("s"), TS);
    let truncated = &stored[..63];
    assert_eq!(
        verify_content_hash_any_scheme(prev, 0, "{}", Some("s"), Some(TS), truncated),
        None
    );
    let extended = format!("{stored}0");
    assert_eq!(
        verify_content_hash_any_scheme(prev, 0, "{}", Some("s"), Some(TS), &extended),
        None
    );
    assert_eq!(
        verify_content_hash_any_scheme(prev, 0, "{}", Some("s"), Some(TS), ""),
        None
    );
}

#[test]
fn verify_any_scheme_rejects_empty_session_id_mismatch_against_none() {
    // A hash bound to session_id=None equals one bound to Some(""): the
    // scheme treats a missing session the same as an explicitly empty one.
    let prev = GENESIS_PREVIOUS_HASH;
    let stored_none = compute_content_hash_v2(prev, 0, "{}", None, TS);
    let stored_empty = compute_content_hash_v2(prev, 0, "{}", Some(""), TS);
    assert_eq!(stored_none, stored_empty);
    assert_eq!(
        verify_content_hash_any_scheme(prev, 0, "{}", Some(""), Some(TS), &stored_none),
        Some(HashScheme::V2)
    );
}

#[test]
fn content_hash_v2_accepts_negative_and_extreme_sequences() {
    let prev = GENESIS_PREVIOUS_HASH;
    let bytes = |parts: &[&str]| parts.concat().into_bytes();
    assert_eq!(
        content_hash_input_v2(prev, -1, "{}", None, TS),
        bytes(&["ELv2\0", prev, "\0", "-1", "\0{}\0\0", TS])
    );
    assert_eq!(
        content_hash_input_v2(prev, i64::MIN, "{}", None, TS),
        bytes(&["ELv2\0", prev, "\0", &i64::MIN.to_string(), "\0{}\0\0", TS])
    );
    assert_eq!(
        content_hash_input_v2(prev, i64::MAX, "{}", None, TS),
        bytes(&["ELv2\0", prev, "\0", &i64::MAX.to_string(), "\0{}\0\0", TS])
    );
    // Still round-trips through the verifier.
    let stored = compute_content_hash_v2(prev, -42, "{}", None, TS);
    assert_eq!(
        verify_content_hash_any_scheme(prev, -42, "{}", None, Some(TS), &stored),
        Some(HashScheme::V2)
    );
}

/// A NUL byte inside `payload_json` would shift v1's field boundary so
/// that two different inputs give the same bytes. v1 is read-only
/// compatibility code and stays as it is; stored payloads are JSON and
/// hold no raw NUL (see `a_serialized_payload_never_holds_the_v2_separator`).
#[test]
fn v1_layout_is_ambiguous_when_a_field_contains_a_nul_byte() {
    let prev = GENESIS_PREVIOUS_HASH;
    let embedded = content_hash_input(prev, 3, "a\0b", None, None);
    let split = content_hash_input(prev, 3, "a", Some("b"), None);
    assert_eq!(
        embedded, split,
        "v1 cannot distinguish a NUL inside payload_json from the session_id delimiter"
    );
}

/// v2's NUL separators are unambiguous because a stored payload is
/// serialized JSON, and JSON never carries a raw NUL: serde_json escapes
/// one in a key or a value as `\u0000`.
#[test]
fn a_serialized_payload_never_holds_the_v2_separator() {
    let payload = serde_json::json!({ "a\0b": "c\0d", "list": ["\0"] });
    let text = serde_json::to_string(&payload).unwrap();
    assert!(!text.contains('\0'), "{text:?}");
    assert!(text.contains("\\u0000"));
}
