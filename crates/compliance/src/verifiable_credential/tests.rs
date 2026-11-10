use super::*;
use ed25519_dalek::SigningKey;

fn test_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

#[test]
fn vc_jwt_has_three_parts_when_signed() {
    let key = test_key();
    let jwt = build_vc_jwt(Uuid::new_v4(), "test goal", None, Some(&key), None);
    assert_eq!(jwt.split('.').count(), 3, "signed JWT must have 3 parts");
}

#[test]
fn vc_jwt_unsigned_has_empty_signature() {
    let id = Uuid::new_v4();
    let jwt = build_vc_jwt(id, "audit target", Some("policy-hash-abc"), None, None);
    let sig_part = jwt.split('.').nth(2).unwrap();
    assert!(
        sig_part.is_empty(),
        "unsigned JWT signature part must be empty"
    );
}

#[test]
fn decode_vc_payload_roundtrip() {
    let key = test_key();
    let session_id = Uuid::new_v4();
    let jwt = build_vc_jwt(session_id, "my goal", Some("abc123"), Some(&key), None);
    let payload = decode_vc_payload(&jwt).expect("decode should succeed");
    assert_eq!(payload["jti"], format!("urn:uuid:{session_id}"),);
    let subject = &payload["vc"]["credentialSubject"];
    assert_eq!(subject["goal"], "my goal");
    assert_eq!(subject["policyHash"], "abc123");
    assert_eq!(subject["status"], "completed");
}

#[test]
fn derive_did_starts_with_did_key_z() {
    let key = test_key();
    let did = derive_did_from_signing_key(&key);
    assert!(
        did.starts_with("did:key:z"),
        "DID must start with did:key:z"
    );
}

#[test]
fn verify_signed_vc_jwt_succeeds() {
    let key = test_key();
    let session_id = Uuid::new_v4();
    let jwt = build_vc_jwt(
        session_id,
        "verify goal",
        Some("hash-xyz"),
        Some(&key),
        None,
    );
    let vk = key.verifying_key();
    let payload = verify_vc_jwt(&jwt, Some(&vk), None).expect("verification must succeed");
    assert_eq!(payload["jti"], format!("urn:uuid:{session_id}"));
    assert_eq!(payload["vc"]["credentialSubject"]["goal"], "verify goal");
}

#[test]
fn verify_unsigned_vc_jwt_without_key_succeeds() {
    let jwt = build_vc_jwt(Uuid::new_v4(), "unsigned goal", None, None, None);
    let payload = verify_vc_jwt(&jwt, None, None).expect("unsigned verification must succeed");
    assert_eq!(payload["vc"]["credentialSubject"]["goal"], "unsigned goal");
}

#[test]
fn verify_detects_unsigned_credential_when_key_required() {
    let key = test_key();
    let jwt = build_vc_jwt(Uuid::new_v4(), "unsigned", None, None, None);
    let vk = key.verifying_key();
    assert_eq!(
        verify_vc_jwt(&jwt, Some(&vk), None),
        Err(VcVerifyError::Unsigned)
    );
}

#[test]
fn verify_detects_tampered_signature() {
    let key = test_key();
    let jwt = build_vc_jwt(Uuid::new_v4(), "tamper test", None, Some(&key), None);
    // Flip one byte in the signature (last part)
    let parts: Vec<&str> = jwt.rsplitn(2, '.').collect();
    let mut sig_chars: Vec<char> = parts[0].chars().collect();
    sig_chars[0] = if sig_chars[0] == 'A' { 'B' } else { 'A' };
    let tampered = format!("{}.{}", parts[1], sig_chars.iter().collect::<String>());
    let vk = key.verifying_key();
    assert_eq!(
        verify_vc_jwt(&tampered, Some(&vk), None),
        Err(VcVerifyError::InvalidSignature)
    );
}

#[test]
fn verify_detects_malformed_jwt() {
    assert_eq!(
        verify_vc_jwt("not-a-jwt", None, None),
        Err(VcVerifyError::Malformed)
    );
    assert_eq!(
        verify_vc_jwt("only.two", None, None),
        Err(VcVerifyError::Malformed)
    );
}

#[test]
fn an_addressed_credential_verifies_only_for_its_audience() {
    let key = test_key();
    let vk = key.verifying_key();
    let aud = "https://auditor.example";
    let jwt = build_vc_jwt(Uuid::new_v4(), "g", None, Some(&key), Some(aud));
    let payload = verify_vc_jwt(&jwt, Some(&vk), Some(aud)).expect("its audience");
    assert_eq!(payload["aud"], aud);
    assert_eq!(
        verify_vc_jwt(&jwt, Some(&vk), Some("https://other.example")),
        Err(VcVerifyError::WrongAudience)
    );
    assert_eq!(
        verify_vc_jwt(&jwt, Some(&vk), None),
        Err(VcVerifyError::WrongAudience),
        "a verifier that names no audience is not the one addressed"
    );
}

#[test]
fn an_unaddressed_credential_is_for_anyone() {
    let key = test_key();
    let jwt = build_vc_jwt(Uuid::new_v4(), "g", None, Some(&key), None);
    let vk = key.verifying_key();
    assert!(verify_vc_jwt(&jwt, Some(&vk), Some("https://anyone.example")).is_ok());
    assert!(verify_vc_jwt(&jwt, Some(&vk), None).is_ok());
}

#[test]
fn a_did_key_decodes_to_the_key_it_was_made_from() {
    let key = test_key();
    let did = derive_did_from_signing_key(&key);
    assert_eq!(verifying_key_from_did(&did), Some(key.verifying_key()));
    for bad in ["did:web:example.com", "did:key:zz", "did:key:z6Mk", ""] {
        assert!(verifying_key_from_did(bad).is_none(), "{bad}");
    }
}

#[test]
fn verify_detects_a_tampered_payload_even_with_an_untouched_signature() {
    let key = test_key();
    let jwt = build_vc_jwt(Uuid::new_v4(), "original goal", None, Some(&key), None);
    let parts: Vec<&str> = jwt.split('.').collect();
    let mut payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    payload["vc"]["credentialSubject"]["goal"] = json!("attacker-controlled goal");
    let tampered_payload = b64url(payload.to_string().as_bytes());
    let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);
    let vk = key.verifying_key();
    assert_eq!(
        verify_vc_jwt(&tampered, Some(&vk), None),
        Err(VcVerifyError::InvalidSignature)
    );
}

#[test]
fn verify_rejects_jwts_with_too_few_segments() {
    for jwt in ["", "onlyonesegment"] {
        assert_eq!(
            verify_vc_jwt(jwt, None, None),
            Err(VcVerifyError::Malformed),
            "{jwt:?}"
        );
    }
}

#[test]
fn verify_rejects_an_unrecognised_algorithm() {
    let header = b64url(json!({"alg": "HS256", "typ": "JWT"}).to_string().as_bytes());
    let payload = b64url(json!({"iss": "did:key:zabc"}).to_string().as_bytes());
    let jwt = format!("{header}.{payload}.sig");
    assert_eq!(
        verify_vc_jwt(&jwt, None, None),
        Err(VcVerifyError::Malformed)
    );
}

#[test]
fn verify_rejects_padded_base64_segments() {
    // URL_SAFE_NO_PAD must not silently accept the padded variant: a
    // verifier that tolerated both would give an attacker two distinct
    // byte strings that decode to the same token.
    let header = URL_SAFE_NO_PAD.encode(json!({"alg": "none", "typ": "JWT"}).to_string());
    let padded_header = format!("{header}==");
    let payload = URL_SAFE_NO_PAD.encode(json!({"iss": "x"}).to_string());
    let jwt = format!("{padded_header}.{payload}.");
    assert_eq!(
        verify_vc_jwt(&jwt, None, None),
        Err(VcVerifyError::Malformed)
    );
}

#[test]
fn verify_detects_an_expired_credential() {
    let key = test_key();
    let header = b64url(json!({"alg": "EdDSA", "typ": "JWT"}).to_string().as_bytes());
    let payload_json = json!({
        "iss": derive_did_from_signing_key(&key),
        "sub": derive_did_from_signing_key(&key),
        "jti": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "iat": 0,
        "exp": 1, // long expired
        "vc": {"credentialSubject": {"goal": "g"}}
    });
    let payload = b64url(payload_json.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    use ed25519_dalek::Signer;
    let sig = b64url(&key.sign(signing_input.as_bytes()).to_bytes());
    let jwt = format!("{signing_input}.{sig}");
    let vk = key.verifying_key();
    assert_eq!(
        verify_vc_jwt(&jwt, Some(&vk), None),
        Err(VcVerifyError::Expired)
    );
}

#[test]
fn verifying_key_from_did_rejects_a_key_of_the_wrong_length() {
    // Correct multicodec prefix, but only 31 bytes of key material.
    let mut prefixed = vec![0xed_u8, 0x01];
    prefixed.extend_from_slice(&[9u8; 31]);
    let did = format!("did:key:z{}", bs58::encode(&prefixed).into_string());
    assert!(verifying_key_from_did(&did).is_none());
}

#[test]
fn verifying_key_from_did_rejects_the_wrong_multicodec_prefix() {
    let key = test_key().verifying_key();
    let mut prefixed = vec![0x80_u8, 0x24]; // P-256 prefix, not Ed25519's
    prefixed.extend_from_slice(key.as_bytes());
    let did = format!("did:key:z{}", bs58::encode(&prefixed).into_string());
    assert!(verifying_key_from_did(&did).is_none());
}

#[test]
fn the_issuer_is_readable_before_verification() {
    let key = test_key();
    let jwt = build_vc_jwt(Uuid::new_v4(), "g", None, Some(&key), None);
    let (iss, alg) = unverified_issuer(&jwt).unwrap();
    assert_eq!(iss, derive_did_from_signing_key(&key));
    assert_eq!(alg, "EdDSA");
    let unsigned = build_vc_jwt(Uuid::new_v4(), "g", None, None, None);
    assert_eq!(unverified_issuer(&unsigned).unwrap().1, "none");
}

#[cfg(feature = "vc-ecdsa")]
mod p256_tests {
    use super::*;

    fn p256_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_bytes(&[11u8; 32].into()).unwrap()
    }

    #[test]
    fn p256_did_starts_with_did_key_z_and_differs_from_ed25519() {
        let did = derive_did_from_p256_key(&p256_key());
        assert!(did.starts_with("did:key:z"));
        assert_ne!(did, derive_did_from_signing_key(&test_key()));
    }

    #[test]
    fn verify_signed_p256_vc_jwt_succeeds() {
        let key = p256_key();
        let jwt = build_vc_jwt_p256(Uuid::new_v4(), "p256 goal", None, &key);
        let vk = key.verifying_key();
        let payload = verify_vc_jwt_p256(&jwt, Some(vk)).expect("verification must succeed");
        assert_eq!(payload["vc"]["credentialSubject"]["goal"], "p256 goal");
    }

    #[test]
    fn verify_p256_vc_jwt_detects_a_tampered_signature() {
        let key = p256_key();
        let jwt = build_vc_jwt_p256(Uuid::new_v4(), "tamper", None, &key);
        let parts: Vec<&str> = jwt.rsplitn(2, '.').collect();
        let mut sig_chars: Vec<char> = parts[0].chars().collect();
        sig_chars[0] = if sig_chars[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}.{}", parts[1], sig_chars.iter().collect::<String>());
        let vk = key.verifying_key();
        assert_eq!(
            verify_vc_jwt_p256(&tampered, Some(vk)),
            Err(VcVerifyError::InvalidSignature)
        );
    }

    #[test]
    fn verify_p256_vc_jwt_rejects_the_wrong_verifying_key() {
        let key = p256_key();
        let other = p256::ecdsa::SigningKey::from_bytes(&[22u8; 32].into()).unwrap();
        let jwt = build_vc_jwt_p256(Uuid::new_v4(), "g", None, &key);
        assert_eq!(
            verify_vc_jwt_p256(&jwt, Some(other.verifying_key())),
            Err(VcVerifyError::InvalidSignature)
        );
    }

    #[test]
    fn verify_p256_vc_jwt_rejects_an_eddsa_header() {
        let key = test_key();
        let jwt = build_vc_jwt(Uuid::new_v4(), "g", None, Some(&key), None);
        assert_eq!(
            verify_vc_jwt_p256(&jwt, None),
            Err(VcVerifyError::Malformed)
        );
    }

    #[test]
    fn build_vc_jwt_with_scheme_dispatches_to_the_right_builder() {
        let eddsa_key = test_key();
        let via_scheme = build_vc_jwt_with_scheme(
            Uuid::nil(),
            "g",
            None,
            Some(SigningScheme::EdDSA(&eddsa_key)),
        );
        assert_eq!(unverified_issuer(&via_scheme).unwrap().1, "EdDSA");

        let p256_key = p256_key();
        let via_p256 = build_vc_jwt_with_scheme(
            Uuid::nil(),
            "g",
            None,
            Some(SigningScheme::ES256(&p256_key)),
        );
        let header_b64 = via_p256.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");

        let unsigned = build_vc_jwt_with_scheme(Uuid::nil(), "g", None, None);
        assert_eq!(unverified_issuer(&unsigned).unwrap().1, "none");
    }
}
