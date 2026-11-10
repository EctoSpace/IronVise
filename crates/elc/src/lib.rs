//! The IronVise Audit Certificate (`.elc`): its data model, the canonical
//! JSON its signature covers, and the offline verifier.
//!
//! This crate is the one implementation of certificate verification. It used
//! to live twice, in the `verify-cert` binary and again in `ectoledger
//! verify-certificate`, documented as "same checks". They were not: the second
//! copy skipped the sequence-gap check, silently ignored findings that cited
//! events the certificate does not contain, and took any bytes containing the
//! Bitcoin attestation marker as an anchor. Both commands, and the browser
//! verifier built from `crates/elc-wasm`, now call [`verify::verify`].
//!
//! It builds for `wasm32-unknown-unknown` unchanged. Keep it free of I/O.
//! The specification a third party would implement from is `docs/reference/elc-spec.md`.

pub mod against;
pub mod ots;
pub mod verify;

use ectoledger_core::merkle::MerkleProof;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Confidentiality tier for the enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclaveLevel {
    /// Level 1 - mlock'd host memory, zeroized on drop.
    SoftwareHardened,
    /// Level 2 - Apple Hypervisor Framework (aarch64 bare-metal unikernel).
    AppleHypervisor,
    /// Level 3 - Remote hardware enclave (AWS Nitro / AMD SEV-SNP).
    RemoteHardwareEnclave,
}

impl std::fmt::Display for EnclaveLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SoftwareHardened => write!(f, "software_hardened"),
            Self::AppleHypervisor => write!(f, "apple_hypervisor"),
            Self::RemoteHardwareEnclave => write!(f, "remote_hardware_enclave"),
        }
    }
}

/// Enclave Attestation Pillar embedded in the `.elc` certificate.
///
/// Records which confidentiality tier was active during the session and
/// the measurement hash of the enclave binary (or remote attestation report).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnclaveAttestationPillar {
    /// Confidentiality tier (software_hardened / apple_hypervisor / remote_hardware_enclave).
    pub level: EnclaveLevel,
    /// SHA-256 hash of the enclave measurement.
    pub measurement_hash: String,
    /// Raw attestation blob (hex-encoded).  Present only for hardware enclaves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_attestation_hex: Option<String>,
}

/// One entry in the event chain embedded in the certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertEventEntry {
    pub sequence: i64,
    pub content_hash: String,
}

/// A finding as captured in the certificate, enriched with its Merkle proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertFinding {
    pub title: String,
    pub severity: String,
    /// Ledger sequence numbers that support this finding.
    pub evidence_sequence: Vec<i64>,
    /// Exact quotes from those observations.
    pub evidence_quotes: Vec<String>,
    /// Merkle inclusion proofs for each evidence event (one proof per sequence entry).
    pub merkle_proofs: Vec<MerkleProof>,
}

/// The complete IronVise Audit Certificate.
/// Serialized with keys sorted alphabetically for deterministic signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EctoLedgerCertificate {
    pub version: u32,
    pub session_id: Uuid,
    pub goal: String,
    pub goal_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_public_key: Option<String>,
    /// SHA-256 content_hash of the last event in the session.
    pub ledger_tip_hash: String,
    /// Merkle root of all event content_hashes in sequence order.
    pub merkle_root: String,
    pub event_count: u64,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Full chain for reconstruction (sequence + content_hash pairs).
    pub events: Vec<CertEventEntry>,
    /// Audit findings with Merkle proof paths.
    pub findings: Vec<CertFinding>,
    /// OpenTimestamps stamp over the ledger tip hash (hex-encoded binary blob).
    /// `null` if OTS submission was skipped or failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ots_proof_hex: Option<String>,
    /// SP1 zero-knowledge proof over the full audit session (Base64-encoded proof bytes).
    ///
    /// SECURITY: This field is EXPLICITLY EXCLUDED from the Ed25519 signing payload
    /// (see `canonical_json_for_signing`). The signature covers the audit evidence; the
    /// ZK proof is independently verifiable via `sp1_sdk::ProverClient::verify`.
    /// `null` if `prove-audit` was not run for this session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zk_proof: Option<serde_json::Value>,
    /// Enclave Attestation Pillar - records which confidentiality tier was active
    /// and the enclave binary measurement.  Included in the Ed25519 signing payload
    /// so that enclave evidence is tamper-evident.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave_attestation: Option<EnclaveAttestationPillar>,
    /// Ed25519 signature over the canonical JSON of all other fields (hex).
    /// To verify: remove this field, `zk_proof` and `issuer`, re-serialize as
    /// canonical JSON, verify against `session_public_key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The installation's countersignature, over the same canonical bytes as
    /// `signature` behind [`ISSUER_DOMAIN`]. Outside the session signature, so
    /// an installation can sign an export after the session key is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<IssuerSignature>,
}

/// A countersignature by the installation that issued the certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerSignature {
    /// The issuer's Ed25519 public key, lowercase hex.
    pub public_key: String,
    /// Ed25519 signature over [`issuer_signing_bytes`], hex.
    pub signature: String,
}

/// Prefix of the bytes an issuer signs, so an issuer signature can never be
/// replayed as a session signature over the same content, or the reverse.
pub const ISSUER_DOMAIN: &str = "ectoledger-issuer-v1\n";

/// What an issuer signs: [`ISSUER_DOMAIN`] followed by the canonical JSON.
pub fn issuer_signing_bytes(cert: &EctoLedgerCertificate) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = ISSUER_DOMAIN.as_bytes().to_vec();
    bytes.extend_from_slice(canonical_json_for_signing(cert)?.as_bytes());
    Ok(bytes)
}

/// Add (or replace) the installation's countersignature.
pub fn countersign(
    cert: &mut EctoLedgerCertificate,
    issuer: &ed25519_dalek::SigningKey,
) -> Result<(), serde_json::Error> {
    use ed25519_dalek::Signer;
    let signature = issuer.sign(&issuer_signing_bytes(cert)?);
    cert.issuer = Some(IssuerSignature {
        public_key: hex::encode(issuer.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    });
    Ok(())
}

/// Parse a certificate from the bytes of a `.elc` file.
pub fn parse_certificate(bytes: &[u8]) -> Result<EctoLedgerCertificate, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Serializes a certificate to canonical JSON suitable for signing: every
/// object's keys sorted at every level, compact, per `docs/reference/elc-spec.md` §5.
///
/// SECURITY MANDATE: `signature`, `zk_proof` and `issuer` are explicitly stripped from the
/// JSON object before the signing bytes are computed. This ensures:
///   1. The signature cannot be included in its own computation (circular dependency).
///   2. Attaching or modifying a ZK proof never invalidates or changes the Ed25519 signature.
///
/// Verifiers must reproduce this stripping before checking the signature.
///
/// The sort is done here, recursively, rather than left to `serde_json::Map`:
/// relying on nested maps being `BTreeMap`s only holds while serde_json's
/// `preserve_order` feature is off. Cargo unifies features across a build,
/// and the desktop app pulls in a dependency that switches it on, so sorting
/// only the top level would make this function produce different bytes
/// depending on which binary it is linked into. The output is unchanged for
/// every build that does not have the feature on.
pub fn canonical_json_for_signing(
    cert: &EctoLedgerCertificate,
) -> Result<String, serde_json::Error> {
    let mut val = serde_json::to_value(cert)?;
    if let Some(obj) = val.as_object_mut() {
        obj.remove("signature");
        // SECURITY: Explicitly strip zk_proof so that embedding or modifying a ZK proof
        // never affects the Ed25519 signature covering the underlying audit evidence.
        obj.remove("zk_proof");
        // The issuer countersigns these same bytes; it is not part of them.
        obj.remove("issuer");
    }
    serde_json::to_string(&sort_keys(val))
}

/// Any JSON value as canonical JSON: keys sorted at every level, compact.
/// The same rule as the signing bytes (§5), for other hashes that must not
/// depend on key order.
pub fn canonical_json(value: &serde_json::Value) -> Result<String, serde_json::Error> {
    serde_json::to_string(&sort_keys(value.clone()))
}

/// Rebuild every object with its keys inserted in sorted order, so the result
/// serialises sorted whether `serde_json::Map` is a `BTreeMap` or an `IndexMap`.
fn sort_keys(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, sort_keys(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

/// The signing bytes a `preserve_order` build produced: top-level keys sorted,
/// nested objects in field declaration order. Not the format; accepted by the
/// verifier so a genuine certificate from such a build is not reported as
/// tampered. Built from the typed fields, so it does not depend on which
/// features this crate was compiled with.
pub(crate) fn legacy_json_for_signing(
    cert: &EctoLedgerCertificate,
) -> Result<String, serde_json::Error> {
    fn put<T: Serialize>(
        out: &mut Vec<(&'static str, String)>,
        key: &'static str,
        value: &T,
    ) -> Result<(), serde_json::Error> {
        out.push((key, serde_json::to_string(value)?));
        Ok(())
    }
    let mut fields: Vec<(&'static str, String)> = Vec::new();
    put(&mut fields, "version", &cert.version)?;
    put(&mut fields, "session_id", &cert.session_id)?;
    put(&mut fields, "goal", &cert.goal)?;
    put(&mut fields, "goal_hash", &cert.goal_hash)?;
    if let Some(v) = &cert.policy_hash {
        put(&mut fields, "policy_hash", v)?;
    }
    if let Some(v) = &cert.session_public_key {
        put(&mut fields, "session_public_key", v)?;
    }
    put(&mut fields, "ledger_tip_hash", &cert.ledger_tip_hash)?;
    put(&mut fields, "merkle_root", &cert.merkle_root)?;
    put(&mut fields, "event_count", &cert.event_count)?;
    put(&mut fields, "started_at", &cert.started_at)?;
    if let Some(v) = &cert.completed_at {
        put(&mut fields, "completed_at", v)?;
    }
    put(&mut fields, "events", &cert.events)?;
    put(&mut fields, "findings", &cert.findings)?;
    if let Some(v) = &cert.ots_proof_hex {
        put(&mut fields, "ots_proof_hex", v)?;
    }
    if let Some(v) = &cert.enclave_attestation {
        put(&mut fields, "enclave_attestation", v)?;
    }
    fields.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = String::from("{");
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(k)?);
        out.push(':');
        out.push_str(v);
    }
    out.push('}');
    Ok(out)
}

#[cfg(test)]
mod canonical_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sample() -> EctoLedgerCertificate {
        EctoLedgerCertificate {
            version: 1,
            session_id: Uuid::nil(),
            goal: "g".into(),
            goal_hash: "h".into(),
            policy_hash: None,
            session_public_key: Some("ab".into()),
            ledger_tip_hash: "t".into(),
            merkle_root: "m".into(),
            event_count: 1,
            started_at: "2026-01-01T00:00:00Z".into(),
            completed_at: None,
            events: vec![CertEventEntry {
                sequence: 1,
                content_hash: "c".into(),
            }],
            findings: vec![],
            ots_proof_hex: None,
            zk_proof: Some(serde_json::json!("proof")),
            enclave_attestation: Some(EnclaveAttestationPillar {
                level: EnclaveLevel::SoftwareHardened,
                measurement_hash: "x".into(),
                raw_attestation_hex: None,
            }),
            signature: Some("sig".into()),
            issuer: None,
        }
    }

    /// The algorithm this crate replaced, verbatim: sort the top level only.
    fn top_level_sort_only(cert: &EctoLedgerCertificate) -> String {
        let mut val = serde_json::to_value(cert).unwrap();
        let obj = val.as_object_mut().unwrap();
        obj.remove("signature");
        obj.remove("zk_proof");
        let sorted: BTreeMap<String, serde_json::Value> =
            val.as_object().unwrap().clone().into_iter().collect();
        serde_json::to_string(&sorted).unwrap()
    }

    /// The legacy bytes, exactly: top-level keys sorted, nested objects in
    /// field declaration order (`sequence` before `content_hash`), absent
    /// options left out. A certificate signed by a `preserve_order` build
    /// verifies only if these are its bytes to the last comma.
    #[test]
    fn the_legacy_signing_bytes_are_pinned() {
        assert_eq!(
            legacy_json_for_signing(&sample()).unwrap(),
            concat!(
                r#"{"enclave_attestation":{"level":"software_hardened","measurement_hash":"x"},"#,
                r#""event_count":1,"events":[{"sequence":1,"content_hash":"c"}],"findings":[],"#,
                r#""goal":"g","goal_hash":"h","ledger_tip_hash":"t","merkle_root":"m","#,
                r#""session_id":"00000000-0000-0000-0000-000000000000","session_public_key":"ab","#,
                r#""started_at":"2026-01-01T00:00:00Z","version":1}"#
            )
        );
    }

    /// Every optional field, when present, is in the legacy bytes, and they
    /// say the same as the canonical bytes, in another order.
    #[test]
    fn the_legacy_form_covers_every_signed_field() {
        let mut cert = sample();
        cert.policy_hash = Some("p".into());
        cert.completed_at = Some("2026-01-01T00:01:00Z".into());
        cert.ots_proof_hex = Some("00".into());
        let legacy: serde_json::Value =
            serde_json::from_str(&legacy_json_for_signing(&cert).unwrap()).unwrap();
        let canonical: serde_json::Value =
            serde_json::from_str(&canonical_json_for_signing(&cert).unwrap()).unwrap();
        assert_eq!(legacy, canonical);
    }

    #[test]
    fn canonical_json_sorts_every_level_and_is_compact() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{ "b": 1, "a": { "d": [ { "z": 1, "y": 2 } ], "c": null } }"#)
                .unwrap();
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":{"c":null,"d":[{"y":2,"z":1}]},"b":1}"#
        );
    }

    /// `Display` is what reports print; it must name a level as the
    /// certificate does.
    #[test]
    fn an_enclave_level_displays_as_it_serialises() {
        for level in [
            EnclaveLevel::SoftwareHardened,
            EnclaveLevel::AppleHypervisor,
            EnclaveLevel::RemoteHardwareEnclave,
        ] {
            assert_eq!(
                format!("\"{level}\""),
                serde_json::to_string(&level).unwrap()
            );
        }
    }

    #[test]
    fn nested_keys_are_sorted_whatever_the_serde_json_features() {
        let s = canonical_json_for_signing(&sample()).unwrap();
        assert!(
            s.contains(r#"{"content_hash":"c","sequence":1}"#),
            "nested keys must be sorted: {s}"
        );
        assert!(s.contains(
            r#""enclave_attestation":{"level":"software_hardened","measurement_hash":"x"}"#
        ));
        assert!(!s.contains("zk_proof") && !s.contains("\"signature\""));
    }

    #[test]
    fn the_old_algorithm_produced_either_the_canonical_or_the_legacy_bytes() {
        // Run this suite twice: plain, and with
        // `--features serde_json/preserve_order`. Without the feature the old
        // algorithm equals the canonical form (so no previously valid
        // certificate changes verdict); with it, it equals the legacy form the
        // verifier accepts.
        let cert = sample();
        let old = top_level_sort_only(&cert);
        let canonical = canonical_json_for_signing(&cert).unwrap();
        let legacy = legacy_json_for_signing(&cert).unwrap();
        assert!(
            old == canonical || old == legacy,
            "old={old}\ncanonical={canonical}\nlegacy={legacy}"
        );
        assert_ne!(
            canonical, legacy,
            "the sample must tell the two forms apart"
        );
    }

    #[test]
    fn parse_certificate_rejects_empty_input() {
        assert!(parse_certificate(b"").is_err());
    }

    #[test]
    fn parse_certificate_rejects_a_byte_order_mark() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(serde_json::to_vec(&sample()).unwrap().as_slice());
        assert!(parse_certificate(&bytes).is_err());
    }

    #[test]
    fn parse_certificate_rejects_trailing_garbage() {
        let mut bytes = serde_json::to_vec(&sample()).unwrap();
        bytes.extend_from_slice(b"not json");
        assert!(parse_certificate(&bytes).is_err());
    }

    #[test]
    fn parse_certificate_rejects_absurdly_deep_nesting() {
        let depth = 200_000;
        let mut text = "[".repeat(depth);
        text.push_str(&"]".repeat(depth));
        assert!(parse_certificate(text.as_bytes()).is_err());
    }

    #[test]
    fn parse_certificate_round_trips_a_real_certificate() {
        let bytes = serde_json::to_vec(&sample()).unwrap();
        let parsed = parse_certificate(&bytes).unwrap();
        assert_eq!(parsed.session_id, sample().session_id);
        assert_eq!(parsed.goal, sample().goal);
        assert_eq!(parsed.events.len(), sample().events.len());
    }

    #[test]
    fn countersign_produces_a_verifiable_issuer_signature() {
        use ed25519_dalek::Verifier;
        let mut cert = sample();
        cert.issuer = None;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        countersign(&mut cert, &issuer).unwrap();
        let sig = cert.issuer.as_ref().unwrap();
        assert_eq!(
            sig.public_key,
            hex::encode(issuer.verifying_key().to_bytes())
        );
        let bytes = issuer_signing_bytes(&cert).unwrap();
        let signature =
            ed25519_dalek::Signature::try_from(hex::decode(&sig.signature).unwrap().as_slice())
                .unwrap();
        assert!(issuer.verifying_key().verify(&bytes, &signature).is_ok());
    }

    #[test]
    fn countersigning_twice_replaces_the_first_signature() {
        let mut cert = sample();
        let first = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let second = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        countersign(&mut cert, &first).unwrap();
        let first_sig = cert.issuer.clone().unwrap();
        countersign(&mut cert, &second).unwrap();
        let second_sig = cert.issuer.clone().unwrap();
        assert_ne!(first_sig.public_key, second_sig.public_key);
    }

    #[test]
    fn issuer_signing_bytes_is_domain_separated_from_the_canonical_signing_bytes() {
        let cert = sample();
        let issuer_bytes = issuer_signing_bytes(&cert).unwrap();
        let canonical = canonical_json_for_signing(&cert).unwrap();
        assert!(issuer_bytes.starts_with(ISSUER_DOMAIN.as_bytes()));
        assert_ne!(issuer_bytes, canonical.as_bytes());
        assert!(issuer_bytes.ends_with(canonical.as_bytes()));
    }

    #[test]
    fn canonical_json_preserves_float_and_unicode_escape_values() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"b": 1.5, "a": "héllo \"quoted\""}"#).unwrap();
        let out = canonical_json(&v).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(reparsed, v);
        assert!(out.starts_with(r#"{"a":"#));
    }

    #[test]
    fn canonical_json_last_value_wins_for_duplicate_keys_like_serde_json_itself() {
        let v: serde_json::Value = serde_json::from_str(r#"{"a": 1, "a": 2}"#).unwrap();
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":2}"#);
    }
}
