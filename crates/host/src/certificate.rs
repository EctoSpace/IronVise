// IronVise Audit Certificate (.elc)
//
// Produces a self-contained, cryptographically verifiable audit record from a completed session.
// The certificate bundles:
//   - The full event hash-chain (sequence + content_hash pairs)
//   - A binary Merkle tree over all event content_hashes
//   - Per-finding Merkle inclusion proofs
//   - An (optional) OpenTimestamps stamp over the ledger tip hash
//   - An (optional) SP1 ZK proof bytes (Base64-encoded) embedded as `zk_proof`
//   - An Ed25519 signature over the canonical JSON of all other fields
//
// The canonical JSON is produced with keys sorted alphabetically via `serde_json::to_string`
// on a `BTreeMap`, so the signature can be re-verified deterministically on any platform.
//
// SECURITY: Both `signature` and `zk_proof` are stripped from the payload before the
// Ed25519 signing bytes are computed. This prevents either field from affecting its own
// verification and ensures the signature covers exactly the audit evidence, nothing else.

use crate::ledger;
use crate::merkle::{self, MerkleError};
use crate::ots::{self, OtsError};
use crate::schema::{AuditFinding, LedgerEventRow, SessionRow};
use crate::signing;
use ed25519_dalek::SigningKey;
use sqlx::{PgPool, SqlitePool};
use uuid::Uuid;

// The data model and the canonical signing bytes live in `ectoledger-elc`, so
// the verifier (and the browser build of it) shares them without linking the
// database layer. Re-exported here so every existing path keeps working.
pub use ectoledger_elc::{
    CertEventEntry, CertFinding, EctoLedgerCertificate, EnclaveAttestationPillar,
    canonical_json_for_signing,
};

/// Error type for certificate operations.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("session not found")]
    SessionNotFound,
    #[error("the signing key given is not this session's key, so the certificate would not verify")]
    KeyMismatch,
    #[error("issuer key: {0}")]
    Issuer(String),
    #[error("session has no events")]
    NoEvents,
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("ots: {0}")]
    Ots(#[from] OtsError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("merkle: {0}")]
    Merkle(#[from] MerkleError),
}

/// Embed raw SP1 proof bytes into the certificate as a Base64-encoded JSON string.
///
/// The `proof_bytes` are the raw bytes returned by `proof.bytes()` from the SP1 SDK.
/// They are Base64-encoded (standard alphabet, no padding stripping) and stored in
/// `cert.zk_proof` as a `serde_json::Value::String`.
///
/// This field is stripped from the signing payload by `canonical_json_for_signing`,
/// so embedding a proof never invalidates an existing `cert.signature`.
pub fn embed_zk_proof(cert: &mut EctoLedgerCertificate, proof_bytes: &[u8]) {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(proof_bytes);
    cert.zk_proof = Some(serde_json::Value::String(encoded));
}

/// Convert an [`EnclaveAttestation`] captured during a session into its
/// certificate pillar representation.
fn attestation_to_pillar(
    att: &crate::enclave::runtime::EnclaveAttestation,
) -> EnclaveAttestationPillar {
    EnclaveAttestationPillar {
        level: att.level,
        measurement_hash: att.measurement_hash.clone(),
        raw_attestation_hex: att.raw_attestation.as_ref().map(hex::encode),
    }
}

/// Build a complete `EctoLedgerCertificate` for the given session (PostgreSQL).
pub async fn build_certificate(
    pool: &PgPool,
    session_id: Uuid,
    signing_key: Option<&SigningKey>,
    submit_ots: bool,
    enclave_attestation: Option<&crate::enclave::runtime::EnclaveAttestation>,
) -> Result<EctoLedgerCertificate, CertificateError> {
    let sessions = ledger::list_sessions(pool)
        .await
        .map_err(CertificateError::Db)?;
    let session: SessionRow = sessions
        .into_iter()
        .find(|s| s.id == session_id)
        .ok_or(CertificateError::SessionNotFound)?;
    let events: Vec<LedgerEventRow> = ledger::get_events_by_session(pool, session_id)
        .await
        .map_err(CertificateError::Db)?;
    build_certificate_from_rows(
        session_id,
        &session,
        &events,
        signing_key,
        submit_ots,
        enclave_attestation,
    )
    .await
}

/// Build a complete `EctoLedgerCertificate` for the given session (SQLite).
pub async fn build_certificate_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
    signing_key: Option<&SigningKey>,
    submit_ots: bool,
    enclave_attestation: Option<&crate::enclave::runtime::EnclaveAttestation>,
) -> Result<EctoLedgerCertificate, CertificateError> {
    let sessions = ledger::sqlite::list_sessions_sqlite(pool)
        .await
        .map_err(CertificateError::Db)?;
    let session: SessionRow = sessions
        .into_iter()
        .find(|s| s.id == session_id)
        .ok_or(CertificateError::SessionNotFound)?;
    let events: Vec<LedgerEventRow> =
        ledger::sqlite::get_events_by_session_sqlite(pool, session_id)
            .await
            .map_err(CertificateError::Db)?;
    build_certificate_from_rows(
        session_id,
        &session,
        &events,
        signing_key,
        submit_ots,
        enclave_attestation,
    )
    .await
}

/// Shared certificate assembly once session metadata and events are loaded.
pub async fn build_certificate_from_rows(
    session_id: Uuid,
    session: &SessionRow,
    events: &[LedgerEventRow],
    signing_key: Option<&SigningKey>,
    submit_ots: bool,
    enclave_attestation: Option<&crate::enclave::runtime::EnclaveAttestation>,
) -> Result<EctoLedgerCertificate, CertificateError> {
    let resolved_attestation: Option<crate::enclave::runtime::EnclaveAttestation> =
        if let Some(att) = enclave_attestation {
            Some(att.clone())
        } else if let Some(ref json) = session.enclave_attestation_json {
            serde_json::from_str(json).ok()
        } else {
            None
        };

    if events.is_empty() {
        return Err(CertificateError::NoEvents);
    }

    let ledger_tip_hash = events
        .last()
        .ok_or(CertificateError::NoEvents)?
        .content_hash
        .clone();

    let content_hashes: Vec<&str> = events.iter().map(|e| e.content_hash.as_str()).collect();
    let tree = merkle::build_merkle_tree(&content_hashes).map_err(CertificateError::Merkle)?;
    let merkle_root = merkle::root(&tree).map_err(CertificateError::Merkle)?;

    let hash_to_leaf: std::collections::HashMap<&str, usize> = content_hashes
        .iter()
        .enumerate()
        .map(|(i, h)| (*h, i))
        .collect();

    let findings = extract_findings_with_proofs(events, &tree, &hash_to_leaf);

    let ots_proof_hex = if submit_ots {
        match ots::submit_ots_stamp(&ledger_tip_hash).await {
            Ok(bytes) => Some(hex::encode(bytes)),
            Err(e) => {
                tracing::warn!(
                    "OTS submission failed (certificate will have null ots_proof_hex): {}",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    // SHA-256 of the goal, which is what every verifier recomputes. A stored
    // hash that matches no hash of this goal is carried as it is, so the
    // certificate shows the mismatch instead of papering over it.
    let goal_hash = match session.goal_hash.as_deref() {
        Some(stored) if !crate::hash::goal_hash_matches(stored, &session.goal) => {
            stored.to_string()
        }
        _ => crate::hash::goal_hash(&session.goal),
    };

    let cert_events: Vec<CertEventEntry> = events
        .iter()
        .map(|e| CertEventEntry {
            sequence: e.sequence,
            content_hash: e.content_hash.clone(),
        })
        .collect();

    let mut cert = EctoLedgerCertificate {
        version: 1,
        session_id,
        goal: session.goal.clone(),
        goal_hash,
        policy_hash: session.policy_hash.clone(),
        session_public_key: session.session_public_key.clone(),
        ledger_tip_hash,
        merkle_root,
        event_count: events.len() as u64,
        started_at: session.created_at.to_rfc3339(),
        completed_at: session.finished_at.map(|t| t.to_rfc3339()),
        events: cert_events,
        findings,
        ots_proof_hex,
        zk_proof: None,
        enclave_attestation: resolved_attestation.as_ref().map(attestation_to_pillar),
        signature: None,
        issuer: None,
    };

    if let Some(sk) = signing_key {
        if cert.session_public_key.as_deref()
            != Some(signing::public_key_hex(&sk.verifying_key()).as_str())
        {
            return Err(CertificateError::KeyMismatch);
        }
        let payload = canonical_json_for_signing(&cert).map_err(CertificateError::Serialize)?;
        let sig = signing::sign_content_hash(sk, &payload);
        cert.signature = Some(sig);
    }
    if let Some(issuer) = crate::issuer::load().map_err(CertificateError::Issuer)? {
        ectoledger_elc::countersign(&mut cert, &issuer).map_err(CertificateError::Serialize)?;
    }

    Ok(cert)
}

/// Extract `AuditFinding` entries from the last `complete` action event and enrich with Merkle proofs.
fn extract_findings_with_proofs(
    events: &[LedgerEventRow],
    tree: &merkle::MerkleTree,
    hash_to_leaf: &std::collections::HashMap<&str, usize>,
) -> Vec<CertFinding> {
    // Build a sequence → content_hash lookup to find evidence proofs.
    let seq_to_hash: std::collections::HashMap<i64, &str> = events
        .iter()
        .map(|e| (e.sequence, e.content_hash.as_str()))
        .collect();

    let raw_findings: Vec<AuditFinding> = events
        .iter()
        .rev()
        .find_map(|e| {
            if let crate::schema::EventPayload::Action { name, params } = &e.payload
                && name == "complete"
                && let Some(f) = params.get("findings")
            {
                return serde_json::from_value::<Vec<AuditFinding>>(f.clone()).ok();
            }
            None
        })
        .unwrap_or_default();

    raw_findings
        .into_iter()
        .map(|f| {
            // One proof per evidence sequence, kept in step. This used
            // `filter_map`, so a sequence the session does not have got no
            // proof and every later proof moved up one place; the verifier
            // pairs them by position, so the verdict then depended on where
            // the phantom sequence sat. A sequence that cannot be proven is
            // dropped from the certificate, with its quote when quotes are
            // one per sequence: the certificate claims only evidence it can
            // prove.
            let quotes_aligned = f.evidence_quotes.len() == f.evidence_sequence.len();
            let mut evidence_sequence = Vec::new();
            let mut evidence_quotes = Vec::new();
            let mut merkle_proofs = Vec::new();
            for (i, seq) in f.evidence_sequence.iter().enumerate() {
                let proof = seq_to_hash
                    .get(seq)
                    .and_then(|hash| hash_to_leaf.get(hash))
                    .and_then(|leaf| merkle::proof(tree, *leaf).ok());
                match proof {
                    Some(p) => {
                        evidence_sequence.push(*seq);
                        merkle_proofs.push(p);
                        if quotes_aligned {
                            evidence_quotes.push(f.evidence_quotes[i].clone());
                        }
                    }
                    None => tracing::warn!(
                        "finding '{}' cites sequence {} which is not in this session; \
                         left out of the certificate",
                        f.title,
                        seq
                    ),
                }
            }
            if !quotes_aligned {
                evidence_quotes = f.evidence_quotes;
            }

            CertFinding {
                title: f.title,
                severity: format!("{:?}", f.severity).to_lowercase(),
                evidence_sequence,
                evidence_quotes,
                merkle_proofs,
            }
        })
        .collect()
}

/// Serialize a certificate to pretty-printed JSON and write it to a file.
pub fn write_certificate_file(
    cert: &EctoLedgerCertificate,
    path: &std::path::Path,
) -> Result<(), CertificateError> {
    let json = serde_json::to_string_pretty(cert).map_err(CertificateError::Serialize)?;
    std::fs::write(path, json.as_bytes()).map_err(CertificateError::Io)
}

/// Read a certificate from a `.elc` file.
pub fn read_certificate_file(
    path: &std::path::Path,
) -> Result<EctoLedgerCertificate, CertificateError> {
    let bytes = std::fs::read(path).map_err(CertificateError::Io)?;
    serde_json::from_slice(&bytes).map_err(CertificateError::Serialize)
}

#[cfg(test)]
mod sqlite_cert_tests;
