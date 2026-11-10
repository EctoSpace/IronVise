//! Individual certificate checks.

use super::*;

pub(super) fn sig_fail(detail: impl Into<String>) -> (Check, Option<String>, bool) {
    (
        Check::new("signature", Status::Fail, "Signature", detail),
        None,
        false,
    )
}

pub(super) fn check_signature(
    cert: &EctoLedgerCertificate,
    req: &Requirements,
    issuer_signed: bool,
) -> (Check, Option<String>, bool) {
    let Some(sig_hex) = &cert.signature else {
        if req.expected_key.is_some() {
            return sig_fail(
                " - there is no session signature, and --expected-key names a session key.",
            );
        }
        if req.signature && !issuer_signed {
            return sig_fail(
                " - the certificate is unsigned, and a signature was required. Nothing here \
                 identifies an issuer.",
            );
        }
        let detail = if issuer_signed {
            " - no session signature; the issuer's countersignature covers the content"
        } else {
            " - certificate has no signature (unsigned)"
        };
        return (
            Check::new("signature", Status::Warn, "Signature", detail),
            None,
            true,
        );
    };
    let Some(pk_hex) = &cert.session_public_key else {
        return sig_fail(" - no session_public_key in certificate");
    };

    // Checked before the signature verifies, not after: a signature that
    // verifies against a key nobody vouched for proves only that whoever made
    // the certificate had a key.
    if let Some(expected) = &req.expected_key
        && !pk_hex.trim().eq_ignore_ascii_case(expected)
    {
        return sig_fail(format!(
            " - signed by {}…, not by the expected key {}…",
            prefix(pk_hex, 16),
            prefix(expected, 16)
        ));
    }

    let canonical = match canonical_json_for_signing(cert) {
        Ok(s) => s,
        Err(e) => return sig_fail(format!(" - canonical JSON error: {e}")),
    };

    let pk_bytes = match hex::decode(pk_hex.trim()) {
        Ok(b) => b,
        Err(e) => return sig_fail(format!(" - invalid public key hex: {e}")),
    };
    let Some(vk) = pk_bytes
        .as_slice()
        .try_into()
        .ok()
        .and_then(|b: &[u8; 32]| VerifyingKey::from_bytes(b).ok())
    else {
        return sig_fail(" - could not parse ed25519 public key");
    };

    let sig_bytes = match hex::decode(sig_hex.trim()) {
        Ok(b) => b,
        Err(e) => return sig_fail(format!(" - invalid signature hex: {e}")),
    };
    let sig: Signature = match sig_bytes.as_slice().try_into() {
        Ok(s) => s,
        Err(e) => return sig_fail(format!(" - could not parse ed25519 signature: {e}")),
    };

    let key = Some(pk_hex.trim().to_lowercase());
    if vk.verify(canonical.as_bytes(), &sig).is_ok() {
        return (
            Check::new("signature", Status::Pass, "Signature valid", " (ed25519)"),
            key,
            true,
        );
    }

    // Certificates exported by builds that had serde_json's `preserve_order`
    // switched on (the desktop app, which links the host library alongside a
    // dependency that enables it) were signed over nested objects in field
    // order rather than sorted order. Same content, same key, different bytes.
    // Accept that form, and say so, rather than calling a genuine certificate
    // tampered. See `legacy_json_for_signing`.
    if let Ok(legacy) = legacy_json_for_signing(cert)
        && legacy != canonical
        && vk.verify(legacy.as_bytes(), &sig).is_ok()
    {
        return (
            Check::new("signature", Status::Pass, "Signature valid", " (ed25519)").with_notes(
                vec![
                    "Signed over the pre-0.8 field-order form some desktop builds produced, \
                     not the sorted form in docs/reference/elc-spec.md §5. The content is covered all the \
                     same; re-export it for the canonical form."
                        .to_string(),
                ],
            ),
            key,
            true,
        );
    }

    (
        Check::new(
            "signature",
            Status::Fail,
            "Signature INVALID",
            " - certificate may have been tampered",
        ),
        None,
        false,
    )
}

/// `None` for the check when there is no countersignature and none was
/// required: an old certificate should not gain a line it never had.
pub(super) fn check_issuer(
    cert: &EctoLedgerCertificate,
    req: &Requirements,
) -> (Option<Check>, Option<IssuerVerdict>, bool) {
    let fail = |title: &'static str, detail: String| {
        (
            Some(Check::new("issuer", Status::Fail, title, detail)),
            None,
            false,
        )
    };
    let Some(countersig) = &cert.issuer else {
        return match &req.issuer {
            Some(required) => fail(
                "Issuer",
                format!(
                    " - not countersigned, and issuer {}… was required",
                    prefix(required, 16)
                ),
            ),
            None => (None, None, true),
        };
    };
    let key = countersig.public_key.trim().to_lowercase();
    if let Some(required) = &req.issuer
        && key != *required
    {
        return fail(
            "Issuer",
            format!(
                " - countersigned by {}…, not by the required issuer {}…",
                prefix(&key, 16),
                prefix(required, 16)
            ),
        );
    }
    let vk = hex::decode(&key)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok());
    let sig = hex::decode(countersig.signature.trim())
        .ok()
        .and_then(|b| Signature::try_from(b.as_slice()).ok());
    let (Some(vk), Some(sig)) = (vk, sig) else {
        return fail(
            "Issuer",
            " - unreadable issuer key or signature".to_string(),
        );
    };
    let signed = match crate::issuer_signing_bytes(cert) {
        Ok(bytes) => vk.verify(&bytes, &sig).is_ok(),
        Err(e) => return fail("Issuer", format!(" - canonical JSON error: {e}")),
    };
    if !signed {
        return fail(
            "Issuer countersignature INVALID",
            " - the content is not what the issuer signed".to_string(),
        );
    }
    let expected = req.issuer.is_some();
    let detail = if expected {
        format!(" (the required issuer {}…)", prefix(&key, 16))
    } else {
        format!(" (key {}…; pass --issuer to require it)", prefix(&key, 16))
    };
    (
        Some(Check::new(
            "issuer",
            Status::Pass,
            "Issuer countersignature valid",
            detail,
        )),
        Some(IssuerVerdict { key, expected }),
        true,
    )
}

pub(super) fn check_hash_chain(cert: &EctoLedgerCertificate) -> Check {
    let fail = |d: String| Check::new("hash_chain", Status::Fail, "Hash chain", d);
    if cert.events.is_empty() {
        return Check::new(
            "hash_chain",
            Status::Warn,
            "Hash chain",
            " - no events to verify",
        );
    }

    // The certificate only embeds (sequence, content_hash) pairs, not the
    // payloads. The offline check is structural: sequences must be
    // consecutive, the last content_hash must equal `ledger_tip_hash`, and the
    // count must match `event_count`. The Merkle check below pins every hash.
    let mut prev_seq: Option<i64> = None;
    for entry in &cert.events {
        if let Some(prev) = prev_seq
            && entry.sequence != prev + 1
        {
            return fail(format!(
                " - sequence gap: expected {}, got {}",
                prev + 1,
                entry.sequence
            ));
        }
        prev_seq = Some(entry.sequence);
    }

    let actual_tip = &cert
        .events
        .last()
        .expect("non-empty: guarded by is_empty early return above")
        .content_hash;
    if actual_tip != &cert.ledger_tip_hash {
        return fail(format!(
            " - ledger_tip_hash mismatch: expected {}, got {}",
            cert.ledger_tip_hash, actual_tip
        ));
    }

    if cert.events.len() as u64 != cert.event_count {
        return fail(format!(
            " - event_count mismatch: declared {}, actual {}",
            cert.event_count,
            cert.events.len()
        ));
    }

    Check::new(
        "hash_chain",
        Status::Pass,
        "Hash chain intact",
        format!(
            " ({} events, tip {}…)",
            cert.events.len(),
            prefix(&cert.ledger_tip_hash, 8)
        ),
    )
}

pub(super) fn check_merkle_proofs(cert: &EctoLedgerCertificate) -> Check {
    // The root is recomputed first and unconditionally: a session with no
    // findings still commits to every event hash, and skipping the root for it
    // would leave those hashes editable without detection.
    let content_hashes: Vec<&str> = cert
        .events
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();
    let tree = match merkle::build_merkle_tree(&content_hashes) {
        Ok(t) => t,
        Err(e) => {
            return Check::new(
                "merkle",
                Status::Fail,
                "Merkle build error",
                format!(" - {e}"),
            );
        }
    };
    let expected_root = match merkle::root(&tree) {
        Ok(r) => r,
        Err(e) => {
            return Check::new(
                "merkle",
                Status::Fail,
                "Merkle root error",
                format!(" - {e}"),
            );
        }
    };

    if expected_root != cert.merkle_root {
        return Check::new(
            "merkle",
            Status::Fail,
            "Merkle root",
            format!(
                " - mismatch: expected {}, computed {}",
                cert.merkle_root, expected_root
            ),
        );
    }

    if cert.findings.is_empty() {
        return Check::new(
            "merkle",
            Status::Pass,
            "Merkle root",
            format!(
                " - matches the {} embedded event hashes (no findings to prove)",
                cert.events.len()
            ),
        );
    }

    let seq_to_hash: std::collections::HashMap<i64, &str> = cert
        .events
        .iter()
        .map(|e| (e.sequence, e.content_hash.as_str()))
        .collect();

    let mut total = 0usize;
    let mut problems = Vec::new();
    for finding in &cert.findings {
        // Evidence and proofs pair by position, so they must be the same
        // length. `zip` would otherwise stop at the shorter list and leave the
        // extra evidence unproven without saying so. The builder (certificate.rs)
        // keeps the two lists in step; dropping the proof for a sequence it
        // cannot find would shift the pairing instead.
        if finding.evidence_sequence.len() != finding.merkle_proofs.len() {
            problems.push(format!(
                "finding '{}' cites {} evidence event(s) but carries {} proof(s)",
                finding.title,
                finding.evidence_sequence.len(),
                finding.merkle_proofs.len()
            ));
        }
        for (i, (&seq, proof)) in finding
            .evidence_sequence
            .iter()
            .zip(&finding.merkle_proofs)
            .enumerate()
        {
            total += 1;
            let Some(hash) = seq_to_hash.get(&seq) else {
                problems.push(format!(
                    "finding '{}' references unknown sequence {}",
                    finding.title, seq
                ));
                continue;
            };
            if !merkle::verify_proof(&cert.merkle_root, hash, proof).unwrap_or(false) {
                problems.push(format!(
                    "proof {} for finding '{}' (seq {}) is invalid",
                    i, finding.title, seq
                ));
            }
        }
    }

    if problems.is_empty() {
        Check::new(
            "merkle",
            Status::Pass,
            "Merkle proofs valid",
            format!(
                " ({} findings, {} evidence sequences verified)",
                cert.findings.len(),
                total
            ),
        )
    } else {
        Check::new(
            "merkle",
            Status::Fail,
            "Merkle proofs",
            format!(" - {} problem(s) across {} proofs", problems.len(), total),
        )
        .with_notes(problems)
    }
}

pub(super) fn check_goal_hash(cert: &EctoLedgerCertificate) -> Check {
    let computed = hex::encode(Sha256::digest(cert.goal.as_bytes()));
    if computed != cert.goal_hash {
        return Check::new(
            "goal_hash",
            Status::Fail,
            "Goal hash",
            format!(
                " - mismatch: declared {}, computed {}",
                cert.goal_hash, computed
            ),
        );
    }
    Check::new(
        "goal_hash",
        Status::Pass,
        "Goal hash matches declared goal",
        "",
    )
}

/// Returns the check and whether a Bitcoin attestation was found. The check
/// fails only when a stamp names a digest other than this certificate's tip;
/// otherwise it informs, and `Requirements::anchor` decides whether a missing
/// Bitcoin attestation matters.
///
/// Offline, this reads the attestation and the Merkle root its block must
/// carry; confirming that root against Bitcoin needs the network (`ots
/// verify`, with the file `verify-cert --export-ots` writes).
pub(super) fn check_ots(cert: &EctoLedgerCertificate, req: &Requirements) -> (Check, bool) {
    let warn = |d: String| Check::new("ots", Status::Warn, "OTS timestamp", d);
    let Ok(tip) = hex::decode(cert.ledger_tip_hash.trim()) else {
        return (
            warn(" - ledger_tip_hash is not hex; stamp not read".into()),
            false,
        );
    };

    // A separately kept, possibly upgraded, .ots file takes precedence.
    if let Some(file) = &req.ots_file {
        return match crate::ots::parse(file, &tip) {
            Err(e) => (
                Check::new(
                    "ots",
                    Status::Fail,
                    "OTS file",
                    format!(" - could not be read: {e}"),
                ),
                false,
            ),
            Ok(stamp) if stamp.file_digest.as_deref() != Some(&tip[..]) => (
                Check::new(
                    "ots",
                    Status::Fail,
                    "OTS file",
                    " - stamps a different digest than this certificate's ledger_tip_hash",
                ),
                false,
            ),
            Ok(stamp) => ots_outcome(&stamp, "OTS file"),
        };
    }

    let Some(ots_hex) = &cert.ots_proof_hex else {
        return (
            warn(" - no OTS proof in certificate (skipped)".into()),
            false,
        );
    };
    let bytes = match hex::decode(ots_hex) {
        Ok(b) => b,
        Err(e) => return (warn(format!(" - invalid hex in ots_proof_hex: {e}")), false),
    };
    match crate::ots::parse(&bytes, &tip) {
        Err(e) => (
            warn(format!(
                " - stamp present ({} bytes) but not readable as OpenTimestamps: {e}",
                bytes.len()
            )),
            false,
        ),
        Ok(stamp) if stamp.file_digest.as_ref().is_some_and(|d| d[..] != tip[..]) => (
            Check::new(
                "ots",
                Status::Fail,
                "OTS timestamp",
                " - the stamp names a different digest than ledger_tip_hash",
            ),
            false,
        ),
        Ok(stamp) => ots_outcome(&stamp, "OTS timestamp"),
    }
}

pub(super) fn ots_outcome(stamp: &crate::ots::Stamp, title: &str) -> (Check, bool) {
    if let Some((height, root)) = stamp.bitcoin() {
        let mut notes = vec![format!("Bitcoin block {height}")];
        if let Some(root) = root {
            notes.push(format!("that block's Merkle root must be {root}"));
        }
        notes.push("Offline, the block is not fetched: confirm with `ots verify`.".into());
        return (
            Check::new(
                "ots",
                Status::Pass,
                format!("{title} - Bitcoin attestation"),
                "",
            )
            .with_notes(notes),
            true,
        );
    }
    let calendars = stamp.calendars();
    let mut notes = vec![
        "This is a calendar server's promise, not a Bitcoin attestation. Upgrade it once a \
         block confirms: `verify-cert --export-ots tip.ots`, then `ots upgrade tip.ots`, \
         then `verify-cert --ots tip.ots`."
            .to_string(),
    ];
    notes.extend(calendars.iter().map(|c| format!("calendar: {c}")));
    (
        Check::new(
            "ots",
            Status::Warn,
            title.to_string(),
            " - pending: submitted to a calendar, not yet confirmed on Bitcoin",
        )
        .with_notes(notes),
        false,
    )
}

pub(super) fn check_enclave_attestation(cert: &EctoLedgerCertificate) -> Check {
    let Some(att) = &cert.enclave_attestation else {
        return Check::new(
            "enclave",
            Status::Warn,
            "Enclave",
            " - no enclave attestation pillar (session ran without an enclave)",
        );
    };
    let mut notes = vec![
        format!("Level       : {}", att.level),
        format!("Measurement : {}", att.measurement_hash),
    ];
    match &att.raw_attestation_hex {
        Some(blob) => notes.push(format!(
            "Raw blob    : {} bytes (hex-encoded)",
            blob.len() / 2
        )),
        None => notes.push("Raw blob    : not present (software-level attestation)".to_string()),
    }
    // The pillar is covered by the signature, so it is what the signer
    // claimed; nothing here checks the attestation against a hardware root.
    Check::new(
        "enclave",
        Status::Warn,
        "Enclave attestation",
        " - claimed by the signer; its evidence is not verified by this tool",
    )
    .with_notes(notes)
}

/// `zk_proof` is left out of the signed bytes so a proof can be attached
/// later; it is neither signed nor checked here, and says so when present.
pub(super) fn check_zk_proof(cert: &EctoLedgerCertificate) -> Option<Check> {
    cert.zk_proof.as_ref()?;
    Some(Check::new(
        "zk_proof",
        Status::Warn,
        "ZK proof",
        " - present but not verified by this tool, and not covered by the signature",
    ))
}
