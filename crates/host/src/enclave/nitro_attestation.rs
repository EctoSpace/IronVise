//! AWS Nitro Enclaves attestation document verification.
//!
//! Implements the checks AWS documents under "Verifying the root of trust"
//! (<https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>):
//!
//! 1. Decode the CBOR object and map it to a `COSE_Sign1` structure (`coset`).
//! 2. Decode the CBOR attestation-document payload (`ciborium`), per the CDDL
//!    AWS publishes on the same page:
//!
//!    ```text
//!    AttestationDocument = {
//!        module_id: text,
//!        timestamp: uint .size 8,       ; ms since UNIX epoch
//!        digest: digest,                ; "SHA384" in every real document
//!        pcrs: { + index => pcr },
//!        certificate: cert,             ; signing cert, DER
//!        cabundle: [* cert],            ; root first, then intermediates
//!        ? public_key: user_data,
//!        ? user_data: user_data,
//!        ? nonce: user_data,
//!    }
//!    ```
//!
//! 3. Verify the certificate chain: `cabundle[0]` (root) must match the
//!    pinned AWS Nitro root exactly, each cert must be signed by the next
//!    one's public key (ECDSA P-384 / SHA-384), each must be a CA except the
//!    final `certificate` (the leaf that signs the document), and every
//!    certificate in the chain must be valid (`notBefore..=notAfter`) at the
//!    verification time the caller supplies.
//! 4. Verify the `COSE_Sign1` signature (ES384) over the Sig_structure, using
//!    the leaf certificate's public key.
//! 5. Verify `nonce` equals the host's own challenge, byte for byte
//!    (constant-time). This closes the reflected-response issue: a response
//!    whose nonce does not match the current challenge is refused outright,
//!    whatever else in it would otherwise check out.
//! 6. Apply the configured PCR policy (PCR0/1/2/8): when a value is
//!    configured for a register, the document's value for that register
//!    must match exactly or the whole document is refused.
//!
//! ## Dependency choice
//!
//! Certificate parsing uses `x509-parser` (RustCrypto-adjacent, maintained by
//! rusticata; ~190M downloads at the time of writing) purely for structure -
//! it is used with its default features, **not** its `verify`/`verify-aws`
//! feature, which pulls in `ring`. All cryptographic verification here goes
//! through RustCrypto's `p384`/`ecdsa` crates instead, the same family this
//! workspace already uses for `p256` (VC-ECDSA) signing, so
//! no new crypto backend enters the dependency graph and `der`/`ecdsa`/`spki`
//! resolve to the exact versions already pinned by those crates (checked:
//! `der 0.7.10`, `ecdsa 0.16.9`, `spki 0.7.3`, `const-oid 0.9.6` - no second
//! generation of the RustCrypto `formats`/`elliptic-curves` stack appears in
//! the lockfile). Two small crates purpose-built for Nitro
//! (`nitro_attest` 0.2.0, ~22k downloads, last published 2025-02-24; and
//! `nsm-nitro-enclave-utils` 0.1.x, MPL-2.0) exist but are both pre-1.0 and
//! far less reviewed than the primitives they would wrap, so for a
//! crypto-critical, audit-focused code path this module does the chain and
//! signature checks itself on top of RustCrypto rather than depending on
//! either.
//!
//! ## The pinned root
//!
//! `AWS_NITRO_ROOT_PEM` below is the exact text of
//! `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`'s
//! `root.pem`, fetched and checked against the SHA-256 fingerprint AWS
//! publishes on the "Verifying the root of trust" page
//! (`64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`).
//! `aws_nitro_root_fingerprint_matches_the_published_value` below recomputes
//! the SHA-256 of the embedded DER and pins it to the same hex string, so a
//! future edit of the constant that silently changes the root is caught.

use std::collections::BTreeMap;
use std::time::SystemTime;

use coset::{
    CborSerializable, CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable, iana,
};
use p384::ecdsa::signature::Verifier as _;
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use subtle::ConstantTimeEq;
use x509_parser::oid_registry::{
    OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_SIG_ECDSA_WITH_SHA384,
};
use x509_parser::prelude::{ASN1Time, FromDer, X509Certificate};

/// The AWS Nitro Enclaves root certificate (G1), exactly as published in
/// `AWS_NitroEnclaves_Root-G1.zip`. SHA-256 of the DER encoding:
/// `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`
/// (`64:1A:03:...` as AWS prints it), which matches the fingerprint on
/// <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>.
/// Subject/issuer: `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`. Valid
/// 2019-10-28 to 2049-10-28 (ECDSA P-384 self-signed, 30-year lifetime).
const AWS_NITRO_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
";

/// SHA-256 fingerprint AWS publishes for the root above, as a lowercase hex
/// string, so the embedded PEM can be checked against it in a test without
/// network access.
pub const AWS_NITRO_ROOT_SHA256_FINGERPRINT: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

/// Decode `AWS_NITRO_ROOT_PEM` to DER. The text is a fixed compile-time
/// constant of known-good base64, so this never fails in practice; a broken
/// constant should be a loud panic, not a silent empty root.
pub fn aws_nitro_root_der() -> Vec<u8> {
    pem_to_der(AWS_NITRO_ROOT_PEM).expect("AWS_NITRO_ROOT_PEM is a valid embedded PEM certificate")
}

/// Minimal PEM -> DER decoder (strip `-----BEGIN/END-----` lines, base64
/// decode the rest). Avoids pulling a PEM-parsing crate into the production
/// dependency graph for one constant; `base64` is already a plain dependency
/// of this crate.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| format!("invalid base64 in PEM: {e}"))
}

/// Expected PCR values. `None` means "not checked" for that register.
#[derive(Debug, Clone, Default)]
pub struct NitroAttestationPolicy {
    /// Pinned root CA certificate, DER-encoded. Production uses
    /// [`aws_nitro_root_der`]; tests inject their own root so the chain
    /// logic can be exercised without the real AWS PKI.
    pub pinned_root_der: Vec<u8>,
    pub pcr0: Option<Vec<u8>>,
    pub pcr1: Option<Vec<u8>>,
    pub pcr2: Option<Vec<u8>>,
    pub pcr8: Option<Vec<u8>>,
}

impl NitroAttestationPolicy {
    /// Policy pinned to the real AWS Nitro root, with no PCR values
    /// configured (enclave identity unchecked beyond the signature chain).
    pub fn with_aws_root() -> Self {
        Self {
            pinned_root_der: aws_nitro_root_der(),
            ..Default::default()
        }
    }

    /// Read `ECTO_ENCLAVE_REMOTE_PCR{0,1,2,8}` (hex-encoded SHA-384 digests)
    /// on top of the AWS root. Unset or unparsable variables leave that
    /// register unchecked.
    pub fn from_env() -> Self {
        Self {
            pinned_root_der: aws_nitro_root_der(),
            pcr0: pcr_from_env("ECTO_ENCLAVE_REMOTE_PCR0"),
            pcr1: pcr_from_env("ECTO_ENCLAVE_REMOTE_PCR1"),
            pcr2: pcr_from_env("ECTO_ENCLAVE_REMOTE_PCR2"),
            pcr8: pcr_from_env("ECTO_ENCLAVE_REMOTE_PCR8"),
        }
    }

    fn configured(&self) -> [(u8, &Option<Vec<u8>>); 4] {
        [
            (0, &self.pcr0),
            (1, &self.pcr1),
            (2, &self.pcr2),
            (8, &self.pcr8),
        ]
    }
}

fn pcr_from_env(var: &str) -> Option<Vec<u8>> {
    let hex_str = std::env::var(var).ok()?;
    match hex::decode(hex_str.trim()) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::warn!("[enclave/nitro_attestation] {var} is not valid hex ({e}); ignoring");
            None
        }
    }
}

/// Fields extracted from a verified attestation document.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub module_id: String,
    /// `timestamp` field from the payload, ms since UNIX epoch, as recorded
    /// by the enclave. Not used for the certificate-validity check (that
    /// uses the caller's own `time`, per AWS's documented "current date"
    /// rule) - kept here only for logging/diagnostics.
    pub document_timestamp_ms: u64,
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// Raw `public_key` bytes, when the document carries one - it is
    /// optional per AWS's own CDDL (real captures may omit it entirely;
    /// see `real_aws_sample_document_...` below). Deliberately returned
    /// without a length or format check beyond presence: this module
    /// verifies the *document*, not a particular consumer's key format.
    /// `remote.rs` requires it present and enforces the 32-byte X25519
    /// shape its protocol needs.
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
}

/// Why an attestation document was refused. `Display` gives a message
/// suitable for the `Result<_, String>` boundary the rest of this crate
/// uses (`NitroVerifyError::to_string()`), while callers that want to branch
/// on the failure kind (tests) can match the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NitroVerifyError {
    InvalidCose(String),
    PayloadNotCbor(String),
    PayloadNotAMap,
    MissingField(&'static str),
    WrongFieldType(&'static str),
    UnsupportedDigest(String),
    EmptyCaBundle,
    CertParse { position: usize, reason: String },
    NotEcdsaP384 { position: usize },
    NotYetValid { position: usize },
    Expired { position: usize },
    IssuerSubjectMismatch { position: usize },
    NotACertificateAuthority { position: usize },
    WrongSignatureAlgorithm { position: usize },
    ChainSignatureInvalid { position: usize },
    RootMismatch,
    CoseAlgorithmMismatch,
    CoseSignatureInvalid(String),
    MissingNonce,
    NonceMismatch,
    PcrWrongLength { index: u8, len: usize },
    PcrMismatch { index: u8 },
}

impl std::fmt::Display for NitroVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCose(e) => write!(f, "invalid COSE_Sign1: {e}"),
            Self::PayloadNotCbor(e) => write!(f, "attestation payload is not valid CBOR: {e}"),
            Self::PayloadNotAMap => write!(f, "attestation payload is not a CBOR map"),
            Self::MissingField(name) => write!(f, "attestation document missing field `{name}`"),
            Self::WrongFieldType(name) => write!(f, "field `{name}` has the wrong CBOR type"),
            Self::UnsupportedDigest(d) => {
                write!(f, "unsupported digest `{d}` (only SHA384 is accepted)")
            }
            Self::EmptyCaBundle => write!(f, "cabundle is empty"),
            Self::CertParse { position, reason } => {
                write!(f, "certificate chain[{position}] failed to parse: {reason}")
            }
            Self::NotEcdsaP384 { position } => {
                write!(f, "certificate chain[{position}] is not an ECDSA P-384 key")
            }
            Self::NotYetValid { position } => {
                write!(
                    f,
                    "certificate chain[{position}] is not yet valid at the verification time"
                )
            }
            Self::Expired { position } => {
                write!(
                    f,
                    "certificate chain[{position}] is expired at the verification time"
                )
            }
            Self::IssuerSubjectMismatch { position } => write!(
                f,
                "certificate chain[{position}]'s issuer does not match chain[{}]'s subject",
                position.saturating_sub(1)
            ),
            Self::NotACertificateAuthority { position } => {
                write!(
                    f,
                    "certificate chain[{position}] is not a CA but signs another certificate"
                )
            }
            Self::WrongSignatureAlgorithm { position } => write!(
                f,
                "certificate chain[{position}] is not signed with ecdsa-with-SHA384"
            ),
            Self::ChainSignatureInvalid { position } => {
                write!(
                    f,
                    "certificate chain[{position}]'s signature does not verify"
                )
            }
            Self::RootMismatch => {
                write!(f, "cabundle[0] does not match the pinned root certificate")
            }
            Self::CoseAlgorithmMismatch => {
                write!(f, "COSE_Sign1 protected header alg is not ES384")
            }
            Self::CoseSignatureInvalid(e) => write!(f, "COSE_Sign1 signature does not verify: {e}"),
            Self::MissingNonce => write!(f, "attestation document has no nonce"),
            Self::NonceMismatch => {
                write!(f, "attestation document nonce does not match the challenge")
            }
            Self::PcrWrongLength { index, len } => {
                write!(f, "PCR{index} is {len} bytes, expected 48 (SHA-384)")
            }
            Self::PcrMismatch { index } => {
                write!(f, "PCR{index} does not match the configured policy")
            }
        }
    }
}

impl std::error::Error for NitroVerifyError {}

/// Verify a raw COSE_Sign1 Nitro attestation document.
///
/// `expected_nonce` is the challenge the host generated and sent with the
/// attestation request; `time` is the verification time used for every
/// certificate's validity window (AWS's own guidance: "the current date",
/// supplied by the caller for determinism in tests); `policy` carries the
/// pinned root and any configured PCR values.
pub fn verify_attestation_document(
    raw_cose: &[u8],
    expected_nonce: &[u8],
    time: SystemTime,
    policy: &NitroAttestationPolicy,
) -> Result<VerifiedAttestation, NitroVerifyError> {
    let cose_sign1 = CoseSign1::from_tagged_slice(raw_cose)
        .or_else(|_| CborSerializable::from_slice(raw_cose))
        .map_err(|e| NitroVerifyError::InvalidCose(e.to_string()))?;

    if cose_sign1.protected.header.alg
        != Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384))
    {
        return Err(NitroVerifyError::CoseAlgorithmMismatch);
    }

    let payload = cose_sign1
        .payload
        .as_ref()
        .ok_or(NitroVerifyError::MissingField("payload"))?;
    let value: ciborium::Value = ciborium::from_reader(payload.as_slice())
        .map_err(|e| NitroVerifyError::PayloadNotCbor(e.to_string()))?;
    let map = match &value {
        ciborium::Value::Map(m) => m,
        _ => return Err(NitroVerifyError::PayloadNotAMap),
    };

    let module_id = text_field(map, "module_id")?;
    let digest = text_field(map, "digest")?;
    if digest != "SHA384" {
        return Err(NitroVerifyError::UnsupportedDigest(digest));
    }
    let document_timestamp_ms = uint_field(map, "timestamp")?;
    let pcrs = pcrs_field(map)?;
    let certificate = bytes_field(map, "certificate")?;
    let cabundle = cabundle_field(map)?;
    let public_key = bytes_field_opt(map, "public_key");
    let user_data = bytes_field_opt(map, "user_data");
    let nonce = bytes_field(map, "nonce").map_err(|_| NitroVerifyError::MissingNonce)?;

    if nonce.len() != expected_nonce.len() || nonce.ct_ne(expected_nonce).into() {
        return Err(NitroVerifyError::NonceMismatch);
    }

    for (index, pcr) in &pcrs {
        if pcr.len() != 48 {
            return Err(NitroVerifyError::PcrWrongLength {
                index: *index,
                len: pcr.len(),
            });
        }
    }
    for (index, expected) in policy.configured() {
        if let Some(expected) = expected {
            match pcrs.get(&index) {
                Some(actual) if actual == expected => {}
                _ => return Err(NitroVerifyError::PcrMismatch { index }),
            }
        }
    }

    if cabundle.is_empty() {
        return Err(NitroVerifyError::EmptyCaBundle);
    }
    if cabundle[0] != policy.pinned_root_der {
        return Err(NitroVerifyError::RootMismatch);
    }

    // Chain order per AWS: cabundle[0] (root) .. cabundle[last] (closest
    // intermediate), then the signing `certificate` (leaf) at the end.
    let mut chain_der = cabundle.clone();
    chain_der.push(certificate.clone());

    let chain: Vec<X509Certificate<'_>> = chain_der
        .iter()
        .enumerate()
        .map(|(position, der)| {
            X509Certificate::from_der(der)
                .map(|(_rest, cert)| cert)
                .map_err(|e| NitroVerifyError::CertParse {
                    position,
                    reason: e.to_string(),
                })
        })
        .collect::<Result<_, _>>()?;

    let verify_time = ASN1Time::from_timestamp(unix_seconds(time))
        .map_err(|_| NitroVerifyError::NotYetValid { position: 0 })?;

    // The root signs itself.
    verify_cert_validity(&chain[0], 0, verify_time)?;
    verify_signed_by(&chain[0], &chain[0], 0)?;

    for position in 1..chain.len() {
        let child = &chain[position];
        let parent = &chain[position - 1];
        verify_cert_validity(child, position, verify_time)?;
        if parent.subject() != child.issuer() {
            return Err(NitroVerifyError::IssuerSubjectMismatch { position });
        }
        if !parent.is_ca() {
            return Err(NitroVerifyError::NotACertificateAuthority {
                position: position - 1,
            });
        }
        verify_signed_by(parent, child, position)?;
    }

    let leaf = chain.last().expect("chain has at least the root");
    let leaf_key = p384_verifying_key(leaf, chain.len() - 1)?;

    let verify_result: Result<(), String> =
        cose_sign1.verify_signature(&[], |sig_bytes, tbs_data| {
            let signature = P384Signature::from_slice(sig_bytes)
                .map_err(|e| format!("malformed COSE signature: {e}"))?;
            leaf_key
                .verify(tbs_data, &signature)
                .map_err(|e| format!("signature mismatch: {e}"))
        });
    verify_result.map_err(NitroVerifyError::CoseSignatureInvalid)?;

    Ok(VerifiedAttestation {
        module_id,
        document_timestamp_ms,
        pcrs,
        public_key,
        user_data,
        nonce,
    })
}

fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

fn verify_cert_validity(
    cert: &X509Certificate<'_>,
    position: usize,
    at: ASN1Time,
) -> Result<(), NitroVerifyError> {
    let validity = cert.validity();
    if at < validity.not_before {
        return Err(NitroVerifyError::NotYetValid { position });
    }
    if at > validity.not_after {
        return Err(NitroVerifyError::Expired { position });
    }
    Ok(())
}

/// Verify that `child` was signed by `parent`'s key (ECDSA P-384 / SHA-384,
/// DER-encoded signature, as X.509 certificates carry it).
fn verify_signed_by(
    parent: &X509Certificate<'_>,
    child: &X509Certificate<'_>,
    child_position: usize,
) -> Result<(), NitroVerifyError> {
    if child.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA384 {
        return Err(NitroVerifyError::WrongSignatureAlgorithm {
            position: child_position,
        });
    }
    let parent_position = if std::ptr::eq(parent, child) {
        child_position
    } else {
        child_position - 1
    };
    let parent_key = p384_verifying_key(parent, parent_position)?;
    let signature = P384Signature::from_der(&child.signature_value.data).map_err(|_| {
        NitroVerifyError::ChainSignatureInvalid {
            position: child_position,
        }
    })?;
    parent_key
        .verify(child.tbs_certificate.as_ref(), &signature)
        .map_err(|_| NitroVerifyError::ChainSignatureInvalid {
            position: child_position,
        })
}

fn p384_verifying_key(
    cert: &X509Certificate<'_>,
    position: usize,
) -> Result<P384VerifyingKey, NitroVerifyError> {
    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(NitroVerifyError::NotEcdsaP384 { position });
    }
    let is_p384 = spki
        .algorithm
        .parameters
        .as_ref()
        .map(|p| p.data == OID_NIST_EC_P384.as_bytes())
        .unwrap_or(false);
    if !is_p384 {
        return Err(NitroVerifyError::NotEcdsaP384 { position });
    }
    P384VerifyingKey::from_sec1_bytes(&spki.subject_public_key.data)
        .map_err(|_| NitroVerifyError::NotEcdsaP384 { position })
}

fn map_get<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(k, v)| match k {
        ciborium::Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn text_field(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &'static str,
) -> Result<String, NitroVerifyError> {
    match map_get(map, key) {
        Some(ciborium::Value::Text(t)) => Ok(t.clone()),
        Some(_) => Err(NitroVerifyError::WrongFieldType(key)),
        None => Err(NitroVerifyError::MissingField(key)),
    }
}

fn uint_field(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &'static str,
) -> Result<u64, NitroVerifyError> {
    match map_get(map, key) {
        Some(ciborium::Value::Integer(i)) => {
            let i: i128 = (*i).into();
            u64::try_from(i).map_err(|_| NitroVerifyError::WrongFieldType(key))
        }
        Some(_) => Err(NitroVerifyError::WrongFieldType(key)),
        None => Err(NitroVerifyError::MissingField(key)),
    }
}

fn bytes_field(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &'static str,
) -> Result<Vec<u8>, NitroVerifyError> {
    match map_get(map, key) {
        Some(ciborium::Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(NitroVerifyError::WrongFieldType(key)),
        None => Err(NitroVerifyError::MissingField(key)),
    }
}

fn bytes_field_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &'static str,
) -> Option<Vec<u8>> {
    match map_get(map, key) {
        Some(ciborium::Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    }
}

fn cabundle_field(
    map: &[(ciborium::Value, ciborium::Value)],
) -> Result<Vec<Vec<u8>>, NitroVerifyError> {
    match map_get(map, "cabundle") {
        Some(ciborium::Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                ciborium::Value::Bytes(b) => Ok(b.clone()),
                _ => Err(NitroVerifyError::WrongFieldType("cabundle")),
            })
            .collect(),
        Some(_) => Err(NitroVerifyError::WrongFieldType("cabundle")),
        None => Err(NitroVerifyError::MissingField("cabundle")),
    }
}

fn pcrs_field(
    map: &[(ciborium::Value, ciborium::Value)],
) -> Result<BTreeMap<u8, Vec<u8>>, NitroVerifyError> {
    match map_get(map, "pcrs") {
        Some(ciborium::Value::Map(entries)) => {
            let mut out = BTreeMap::new();
            for (k, v) in entries {
                let index = match k {
                    ciborium::Value::Integer(i) => {
                        let i: i128 = (*i).into();
                        u8::try_from(i).map_err(|_| NitroVerifyError::WrongFieldType("pcrs"))?
                    }
                    _ => return Err(NitroVerifyError::WrongFieldType("pcrs")),
                };
                let bytes = match v {
                    ciborium::Value::Bytes(b) => b.clone(),
                    _ => return Err(NitroVerifyError::WrongFieldType("pcrs")),
                };
                out.insert(index, bytes);
            }
            Ok(out)
        }
        Some(_) => Err(NitroVerifyError::WrongFieldType("pcrs")),
        None => Err(NitroVerifyError::MissingField("pcrs")),
    }
}

#[cfg(test)]
mod tests;
