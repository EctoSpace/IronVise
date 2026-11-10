use super::*;
use coset::{CoseSign1Builder, HeaderBuilder};
use p384::ecdsa::SigningKey as P384SigningKey;
use p384::ecdsa::signature::Signer as _;
use p384::elliptic_curve::Generate;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::{Time, Validity};

/// Sign `tbs` and return the raw (fixed-width r‖s) signature bytes -
/// the encoding X.509 certificate signatures are *not* in (they use
/// DER), but which `p384::ecdsa::Signature::to_bytes` always produces,
/// so an explicit type keeps this unambiguous at each call site.
fn sign_raw(key: &P384SigningKey, tbs: &[u8]) -> Vec<u8> {
    let sig: p384::ecdsa::Signature = key.sign(tbs);
    sig.to_bytes().to_vec()
}

/// A fixture certificate's signed DER encoding.
struct FixtureCert {
    der: Vec<u8>,
}

fn validity_between(not_before: SystemTime, not_after: SystemTime) -> Validity {
    Validity::new(
        Time::try_from(not_before).unwrap(),
        Time::try_from(not_after).unwrap(),
    )
}

const ROOT_NAME: &str = "CN=Test Nitro Root,O=Test,C=US";
const LEAF_NAME: &str = "CN=Test Nitro Leaf,O=Test,C=US";

/// A fixture certificate's names, and whether it may sign others: all
/// the chain check reads. A root names itself as issuer and is a CA.
struct TestProfile {
    subject: Name,
    issuer: Option<Name>,
}

fn root_profile() -> TestProfile {
    TestProfile {
        subject: Name::from_str(ROOT_NAME).unwrap(),
        issuer: None,
    }
}

fn leaf_profile() -> TestProfile {
    TestProfile {
        subject: Name::from_str(LEAF_NAME).unwrap(),
        issuer: Some(Name::from_str(ROOT_NAME).unwrap()),
    }
}

impl BuilderProfile for TestProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        self.issuer.clone().unwrap_or_else(|| subject.clone())
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        if self.issuer.is_some() {
            return Ok(Vec::new());
        }
        let ca = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        Ok(vec![ca.to_extension(tbs.subject(), &[])?])
    }
}

fn spki_for(key: &P384SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap()
}

fn build_cert(
    profile: TestProfile,
    validity: Validity,
    subject_key: &P384SigningKey,
    signer: &P384SigningKey,
) -> Vec<u8> {
    let serial = SerialNumber::from(rand::random::<u32>());
    let spki = spki_for(subject_key);
    let builder = CertificateBuilder::new(profile, serial, validity, spki).unwrap();
    let cert = builder
        .build::<_, p384::ecdsa::DerSignature>(signer)
        .unwrap();
    use x509_cert::der::Encode;
    cert.to_der().unwrap()
}

/// A full root -> intermediate -> leaf chain, each P-384, each signed by
/// the one before it, valid over `[now - 1h, now + 1h]` unless a test
/// overrides a specific certificate's validity.
struct TestChain {
    root: FixtureCert,
    leaf: FixtureCert,
    leaf_key: P384SigningKey,
    enclave_key_bytes: [u8; 32], // fake X25519 public key carried as `public_key`
}

fn default_validity() -> Validity {
    let now = SystemTime::now();
    validity_between(
        now - Duration::from_secs(3600),
        now + Duration::from_secs(3600),
    )
}

fn build_test_chain() -> TestChain {
    let root_key = P384SigningKey::generate();
    let leaf_key = P384SigningKey::generate();

    let root_der = build_cert(root_profile(), default_validity(), &root_key, &root_key);
    let leaf_der = build_cert(leaf_profile(), default_validity(), &leaf_key, &root_key);

    TestChain {
        root: FixtureCert { der: root_der },
        leaf: FixtureCert { der: leaf_der },
        leaf_key,
        enclave_key_bytes: [0x42u8; 32],
    }
}

fn build_document(chain: &TestChain, nonce: &[u8], pcr0: [u8; 48]) -> Vec<u8> {
    let payload_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("module_id".into()),
            ciborium::Value::Text("test-module-v1".into()),
        ),
        (
            ciborium::Value::Text("timestamp".into()),
            ciborium::Value::Integer(1_700_000_000_000i64.into()),
        ),
        (
            ciborium::Value::Text("digest".into()),
            ciborium::Value::Text("SHA384".into()),
        ),
        (
            ciborium::Value::Text("pcrs".into()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Bytes(pcr0.to_vec()),
            )]),
        ),
        (
            ciborium::Value::Text("certificate".into()),
            ciborium::Value::Bytes(chain.leaf.der.clone()),
        ),
        (
            ciborium::Value::Text("cabundle".into()),
            ciborium::Value::Array(vec![ciborium::Value::Bytes(chain.root.der.clone())]),
        ),
        (
            ciborium::Value::Text("public_key".into()),
            ciborium::Value::Bytes(chain.enclave_key_bytes.to_vec()),
        ),
        (
            ciborium::Value::Text("nonce".into()),
            ciborium::Value::Bytes(nonce.to_vec()),
        ),
    ]);
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload_map, &mut payload_bytes).unwrap();

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build();
    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&[], |tbs| sign_raw(&chain.leaf_key, tbs));
    cose.build().to_vec().unwrap()
}

fn policy_for(chain: &TestChain) -> NitroAttestationPolicy {
    NitroAttestationPolicy {
        pinned_root_der: chain.root.der.clone(),
        ..Default::default()
    }
}

#[test]
fn aws_nitro_root_fingerprint_matches_the_published_value() {
    use sha2::{Digest, Sha256};
    let der = aws_nitro_root_der();
    let got = hex::encode(Sha256::digest(&der));
    assert_eq!(got, AWS_NITRO_ROOT_SHA256_FINGERPRINT);
}

#[test]
fn aws_nitro_root_parses_as_a_p384_self_signed_cert() {
    let der = aws_nitro_root_der();
    let (_, cert) = X509Certificate::from_der(&der).expect("embedded root parses as X.509");
    assert_eq!(cert.subject(), cert.issuer());
    p384_verifying_key(&cert, 0).expect("embedded root is an ECDSA P-384 key");
    verify_signed_by(&cert, &cert, 0).expect("embedded root is self-signed correctly");
}

#[test]
fn valid_document_passes() {
    let chain = build_test_chain();
    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    let doc = build_document(&chain, &nonce, [0xAA; 48]);
    let policy = policy_for(&chain);

    let verified = verify_attestation_document(&doc, &nonce, SystemTime::now(), &policy)
        .expect("well-formed document with a matching root and nonce must verify");
    assert_eq!(verified.module_id, "test-module-v1");
    assert_eq!(verified.public_key, Some(chain.enclave_key_bytes.to_vec()));
    assert_eq!(verified.pcrs.get(&0), Some(&vec![0xAAu8; 48]));
    assert_eq!(verified.nonce, nonce);
}

#[test]
fn wrong_root_is_rejected() {
    let chain = build_test_chain();
    let other_chain = build_test_chain();
    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    let doc = build_document(&chain, &nonce, [0xAA; 48]);
    // Pin a *different* root than the one the chain actually chains to.
    let policy = policy_for(&other_chain);

    let err = verify_attestation_document(&doc, &nonce, SystemTime::now(), &policy).unwrap_err();
    assert_eq!(err, NitroVerifyError::RootMismatch);
}

#[test]
fn expired_cert_at_verification_time_is_rejected() {
    let root_key = P384SigningKey::generate();
    let leaf_key = P384SigningKey::generate();
    let now = SystemTime::now();

    let root_der = build_cert(root_profile(), default_validity(), &root_key, &root_key);
    // Leaf's own validity window is entirely in the past.
    let expired_validity = validity_between(
        now - Duration::from_secs(7200),
        now - Duration::from_secs(3600),
    );
    let leaf_der = build_cert(leaf_profile(), expired_validity, &leaf_key, &root_key);

    let chain = TestChain {
        root: FixtureCert { der: root_der },
        leaf: FixtureCert { der: leaf_der },
        leaf_key,
        enclave_key_bytes: [0x42u8; 32],
    };
    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    let doc = build_document(&chain, &nonce, [0xAA; 48]);
    let policy = policy_for(&chain);

    let err = verify_attestation_document(&doc, &nonce, now, &policy).unwrap_err();
    assert_eq!(err, NitroVerifyError::Expired { position: 1 });
}

#[test]
fn broken_chain_signature_is_rejected() {
    let chain = build_test_chain();
    let impostor_root_key = P384SigningKey::generate();
    // Leaf is actually signed by an unrelated key, not `chain.root`'s.
    let bogus_leaf_der = build_cert(
        leaf_profile(),
        default_validity(),
        &chain.leaf_key,
        &impostor_root_key,
    );
    let mut tampered = chain;
    tampered.leaf.der = bogus_leaf_der;

    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    let doc = build_document(&tampered, &nonce, [0xAA; 48]);
    let policy = policy_for(&tampered);

    let err = verify_attestation_document(&doc, &nonce, SystemTime::now(), &policy).unwrap_err();
    assert_eq!(err, NitroVerifyError::ChainSignatureInvalid { position: 1 });
}

#[test]
fn tampered_payload_fails_the_cose_signature() {
    let chain = build_test_chain();
    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    let mut doc = build_document(&chain, &nonce, [0xAA; 48]);
    // Flip a byte inside the CBOR payload (well past the headers).
    let flip_at = doc.len() - 10;
    doc[flip_at] ^= 0xFF;
    let policy = policy_for(&chain);

    let err = verify_attestation_document(&doc, &nonce, SystemTime::now(), &policy);
    assert!(err.is_err(), "a tampered document must not verify");
}

#[test]
fn wrong_nonce_is_rejected() {
    let chain = build_test_chain();
    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    let doc = build_document(&chain, &nonce, [0xAA; 48]);
    let policy = policy_for(&chain);

    let different_nonce = b"a-completely-different-challenge".to_vec();
    let err = verify_attestation_document(&doc, &different_nonce, SystemTime::now(), &policy)
        .unwrap_err();
    assert_eq!(err, NitroVerifyError::NonceMismatch);
}

#[test]
fn pcr0_mismatch_is_rejected_when_configured() {
    let chain = build_test_chain();
    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    let doc = build_document(&chain, &nonce, [0xAA; 48]);
    let mut policy = policy_for(&chain);
    policy.pcr0 = Some(vec![0xBBu8; 48]);

    let err = verify_attestation_document(&doc, &nonce, SystemTime::now(), &policy).unwrap_err();
    assert_eq!(err, NitroVerifyError::PcrMismatch { index: 0 });
}

#[test]
fn pcr0_match_is_accepted_when_configured() {
    let chain = build_test_chain();
    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    let doc = build_document(&chain, &nonce, [0xAA; 48]);
    let mut policy = policy_for(&chain);
    policy.pcr0 = Some(vec![0xAAu8; 48]);

    verify_attestation_document(&doc, &nonce, SystemTime::now(), &policy)
        .expect("configured PCR0 matches the document's PCR0");
}

#[test]
fn non_sha384_digest_is_rejected() {
    let chain = build_test_chain();
    let nonce = b"challenge-nonce-0123456789012345".to_vec();

    let payload_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("module_id".into()),
            ciborium::Value::Text("test-module-v1".into()),
        ),
        (
            ciborium::Value::Text("timestamp".into()),
            ciborium::Value::Integer(1_700_000_000_000i64.into()),
        ),
        (
            ciborium::Value::Text("digest".into()),
            ciborium::Value::Text("SHA256".into()),
        ),
        (
            ciborium::Value::Text("pcrs".into()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Bytes(vec![0xAA; 32]),
            )]),
        ),
        (
            ciborium::Value::Text("certificate".into()),
            ciborium::Value::Bytes(chain.leaf.der.clone()),
        ),
        (
            ciborium::Value::Text("cabundle".into()),
            ciborium::Value::Array(vec![ciborium::Value::Bytes(chain.root.der.clone())]),
        ),
        (
            ciborium::Value::Text("public_key".into()),
            ciborium::Value::Bytes(chain.enclave_key_bytes.to_vec()),
        ),
        (
            ciborium::Value::Text("nonce".into()),
            ciborium::Value::Bytes(nonce.clone()),
        ),
    ]);
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload_map, &mut payload_bytes).unwrap();
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build();
    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&[], |tbs| sign_raw(&chain.leaf_key, tbs));
    let doc = cose.build().to_vec().unwrap();
    let policy = policy_for(&chain);

    let err = verify_attestation_document(&doc, &nonce, SystemTime::now(), &policy).unwrap_err();
    assert_eq!(
        err,
        NitroVerifyError::UnsupportedDigest("SHA256".to_string())
    );
}

#[test]
fn missing_field_is_rejected() {
    let chain = build_test_chain();
    let nonce = b"challenge-nonce-0123456789012345".to_vec();
    // Build a payload with `certificate` left out entirely.
    let payload_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("module_id".into()),
            ciborium::Value::Text("test-module-v1".into()),
        ),
        (
            ciborium::Value::Text("timestamp".into()),
            ciborium::Value::Integer(1_700_000_000_000i64.into()),
        ),
        (
            ciborium::Value::Text("digest".into()),
            ciborium::Value::Text("SHA384".into()),
        ),
        (
            ciborium::Value::Text("pcrs".into()),
            ciborium::Value::Map(vec![]),
        ),
        (
            ciborium::Value::Text("cabundle".into()),
            ciborium::Value::Array(vec![ciborium::Value::Bytes(chain.root.der.clone())]),
        ),
        (
            ciborium::Value::Text("public_key".into()),
            ciborium::Value::Bytes(chain.enclave_key_bytes.to_vec()),
        ),
        (
            ciborium::Value::Text("nonce".into()),
            ciborium::Value::Bytes(nonce.clone()),
        ),
    ]);
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload_map, &mut payload_bytes).unwrap();
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build();
    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&[], |tbs| sign_raw(&chain.leaf_key, tbs));
    let doc = cose.build().to_vec().unwrap();
    let policy = policy_for(&chain);

    let err = verify_attestation_document(&doc, &nonce, SystemTime::now(), &policy).unwrap_err();
    assert_eq!(err, NitroVerifyError::MissingField("certificate"));
}

/// A genuine Nitro attestation document, captured in production and
/// redistributed under Apache-2.0 by
/// `evervault/attestation-doc-validation`
/// (`test-data/valid-attestation-doc-base64`, fetched 2026-10-24 from
/// <https://github.com/evervault/attestation-doc-validation>, stored
/// here as `crates/host/tests/fixtures/nitro-sample-attestation.cbor`).
/// Its `cabundle[0]` is byte-for-byte the real AWS root embedded above
/// (checked independently with `cmp` before writing this test).
///
/// Its leaf and intermediate certificates expired in September 2023 -
/// Nitro issues short-lived leaf certificates - so this verifies the
/// chain at the time the document itself recorded (extracted from the
/// document, not invented), per AWS's own "Certificate validity" rule:
/// the check is against the verifier's reference time, and that
/// reference time is this document's own moment of creation rather
/// than today's wall clock.
#[test]
fn real_aws_sample_document_verifies_against_the_real_root_at_its_own_timestamp() {
    let raw_cose: &[u8] = include_bytes!("../../../tests/fixtures/nitro-sample-attestation.cbor");

    // Pull the document's own `timestamp` and `nonce` so this test can
    // hand the verifier the (`time`, `expected_nonce`) the real capture
    // was actually made with, instead of inventing new ones.
    let cose_sign1 = CoseSign1::from_tagged_slice(raw_cose)
        .or_else(|_| CborSerializable::from_slice(raw_cose))
        .expect("fixture is a valid COSE_Sign1");
    let payload = cose_sign1.payload.as_ref().expect("fixture has a payload");
    let value: ciborium::Value =
        ciborium::from_reader(payload.as_slice()).expect("fixture payload is valid CBOR");
    let map = match &value {
        ciborium::Value::Map(m) => m,
        _ => panic!("fixture payload is not a CBOR map"),
    };
    let timestamp_ms = uint_field(map, "timestamp").expect("fixture has a timestamp");
    let nonce = bytes_field(map, "nonce").expect("fixture has a nonce");

    let time = SystemTime::UNIX_EPOCH + Duration::from_millis(timestamp_ms);
    let policy = NitroAttestationPolicy::with_aws_root();

    let verified = verify_attestation_document(raw_cose, &nonce, time, &policy).expect(
        "a genuine AWS-signed document must verify against the real embedded root at its own timestamp",
    );
    assert_eq!(
        verified.module_id,
        "i-0918f6c55e3b61d89-enc018aa8b8e2285d13"
    );
    assert_eq!(verified.pcrs.len(), 16);
    // This real capture has no `public_key` (it is optional per AWS's
    // CDDL) - confirms the field is genuinely optional, not just
    // untested.
    assert_eq!(verified.public_key, None);
}
