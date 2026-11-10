//! `ironvise report`, `ironvise replay`, `ironvise verify-session`,
//! `ironvise verify-certificate`, `ironvise verify-vc`

use colored::Colorize;
use uuid::Uuid;

/// Replay events for a session with colored output.
pub async fn run_replay(
    pool: &sqlx::PgPool,
    session: Uuid,
    to_step: Option<u32>,
    inject_observation: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let events = crate::ledger::get_events_by_session(pool, session).await?;
    print_replay(events, to_step, inject_observation);
    Ok(())
}

/// Shared replay display logic used by both Postgres and SQLite variants.
fn print_replay(
    events: Vec<crate::schema::LedgerEventRow>,
    to_step: Option<u32>,
    inject_observation: Vec<String>,
) {
    use crate::schema::EventPayload;

    let limit = to_step.map(|n| n as usize).unwrap_or(events.len());
    let inject_map: std::collections::HashMap<i64, String> = inject_observation
        .iter()
        .filter_map(|s| {
            let s = s.trim();
            let rest = s.strip_prefix("seq=")?;
            let (seq, payload) = rest.split_once(':')?;
            let seq = seq.trim().parse::<i64>().ok()?;
            Some((seq, payload.to_string()))
        })
        .collect();

    for (i, ev) in events.into_iter().take(limit).enumerate() {
        let step = i + 1;
        let payload_display = if let Some(injected) = inject_map.get(&ev.sequence) {
            if let EventPayload::Observation { .. } = &ev.payload {
                serde_json::to_string_pretty(&EventPayload::Observation {
                    content: format!("[INJECTED] {injected}"),
                })
                .unwrap_or_default()
            } else {
                serde_json::to_string_pretty(&ev.payload).unwrap_or_default()
            }
        } else {
            serde_json::to_string_pretty(&ev.payload).unwrap_or_default()
        };
        let (label, color_fn): (&str, fn(&str) -> colored::ColoredString) = match &ev.payload {
            EventPayload::Genesis { .. } => ("genesis", |s: &str| s.green()),
            EventPayload::PromptInput { .. } => ("prompt_input", |s: &str| s.green()),
            EventPayload::Thought { .. } => ("thought", |s: &str| s.blue()),
            EventPayload::GuardDenial { .. } => ("guard_denial", |s: &str| s.red()),
            EventPayload::TripwireRejection { .. } => ("tripwire_rejection", |s: &str| s.red()),
            EventPayload::SchemaError { .. } => ("schema_error", |s: &str| s.red()),
            EventPayload::CircuitBreaker { .. } => ("circuit_breaker", |s: &str| s.yellow()),
            EventPayload::Action { .. } => ("action", |s: &str| s.yellow()),
            EventPayload::Observation { .. } => ("observation", |s: &str| s.magenta()),
            EventPayload::ApprovalRequired { .. } | EventPayload::ApprovalDecision { .. } => {
                ("approval", |s: &str| s.cyan())
            }
            EventPayload::CrossLedgerSeal { .. } => ("cross_ledger_seal", |s: &str| s.white()),
            EventPayload::Anchor { .. } => ("anchor", |s: &str| s.white()),
            EventPayload::KeyRotation { .. } => ("key_rotation", |s: &str| s.cyan()),
            EventPayload::KeyRevocation { .. } => ("key_revocation", |s: &str| s.red()),
            EventPayload::VerifiableCredential { .. } => {
                ("verifiable_credential", |s: &str| s.green())
            }
            EventPayload::ChatMessage { .. } => ("chat", |s: &str| s.blue()),
            EventPayload::DataReceipt { .. } => ("data_receipt", |s: &str| s.cyan()),
        };
        println!(
            "{}",
            color_fn(&format!("[step {}] {} #{}", step, label, ev.sequence))
        );
        println!("{payload_display}");
        println!();
    }
}

/// Verify event signatures for a session (ed25519).
pub async fn run_verify_session(
    pool: &sqlx::PgPool,
    session: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let verdict = crate::ledger::postgres::verify_session_detailed(pool, session).await?;
    match verdict {
        crate::ledger::SessionVerdict::Verified {
            signatures,
            unsigned,
        } => {
            println!("Verified {signatures} event signatures for session {session}.");
            if unsigned > 0 {
                // Say what the signatures do not cover, rather than letting a
                // count of signatures read as a count of events.
                println!(
                    "{unsigned} further event(s) are unsigned by design (client-asserted, \
                     seals, anchors, pre-0.8 approval copies) and covered by the hash chain only."
                );
            }
            Ok(())
        }
        other => Err(format!("Verification FAILED for session {session}: {other}").into()),
    }
}

/// The session's saved signing key, to sign its certificate with: `audit`
/// saves one when given a password. `None` when there is no key file or the
/// password is left blank; an error when the file does not open, so a wrong
/// password never quietly yields an unsigned certificate.
pub fn saved_session_key(
    key_dir: &std::path::Path,
    session: Uuid,
    password: impl FnOnce() -> Option<String>,
) -> Result<Option<ed25519_dalek::SigningKey>, String> {
    let failed = |e: crate::signing::SigningError| {
        format!("the saved signing key for session {session} did not open: {e}")
    };
    let Some(file) = crate::signing::read_key_file(key_dir, session).map_err(failed)? else {
        return Ok(None);
    };
    let Some(password) = password().filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    // v0.6.3 files have no commitment. They still authenticate the session id.
    // build_certificate refuses any key that is not the session's registered one.
    if file.commitment_hex.is_empty() {
        let key = crate::signing::decrypt_legacy_signing_key(&file, session, &password)
            .map_err(failed)?;
        // The certificate can be signed either way. The rewrite only happens
        // after that decrypt, and the original file is kept beside it.
        if let Err(e) = crate::signing::upgrade_legacy_key_file(key_dir, session, &key, &password) {
            tracing::warn!(
                "opened the v0.6.3 signing key for session {} but left it in the old format: {}",
                session,
                e
            );
        }
        Ok(Some(key))
    } else {
        crate::signing::decrypt_signing_key(&file, session, &password)
            .map(Some)
            .map_err(failed)
    }
}

/// [`saved_session_key`] from the configured key directory, with the password
/// from `--key-password-fd`, `ECTO_KEY_PASSWORD` or a prompt.
pub fn certificate_signing_key(
    session: Uuid,
    key_password_fd: Option<i32>,
) -> Result<Option<ed25519_dalek::SigningKey>, String> {
    let key = saved_session_key(
        &crate::config::session_key_dir(),
        session,
        || match key_password_fd {
            Some(fd) => crate::signing::read_password_from_fd(fd),
            None => crate::signing::prompt_or_env_password(
                "Password for this session's saved signing key (blank: write the certificate unsigned): ",
            ),
        },
    )?;
    if key.is_none() {
        println!(
            "The certificate will be unsigned: no saved signing key was opened for this \
             session (`audit` saves one when given a password)."
        );
    }
    Ok(key)
}

/// Export audit report for a session.
pub async fn run_report(
    pool: &sqlx::PgPool,
    session: Uuid,
    format: String,
    output: Option<std::path::PathBuf>,
    no_ots: bool,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if format.to_lowercase() == "certificate" {
        let out_path = output
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(format!("audit-{session}.elc")));
        println!("Building IronVise Audit Certificate for session {session}...");
        let cert = crate::certificate::build_certificate(
            pool,
            session,
            signing_key,
            !no_ots,
            None, // enclave attestation: not available from CLI report command
        )
        .await
        .map_err(|e| format!("certificate build failed: {e}"))?;
        crate::certificate::write_certificate_file(&cert, &out_path)
            .map_err(|e| format!("write certificate failed: {e}"))?;
        println!("Certificate written to {}", out_path.display());
        println!("Verify with: verify-cert {}", out_path.display());
    } else {
        let report = crate::report::build_report(pool, session).await?;
        print_report(&report, session, format, output)?;
    }
    Ok(())
}

/// Shared report format + output logic used by both Postgres and SQLite variants.
fn print_report(
    report: &crate::report::AuditReport,
    session: Uuid,
    format: String,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let out = match format.to_lowercase().as_str() {
        "sarif" => serde_json::to_string_pretty(&crate::report::report_to_sarif(report, session))
            .unwrap_or_default(),
        "html" => crate::report::report_to_html(report, session),
        "github_actions" => crate::report::report_to_github_actions(report),
        "gitlab_codequality" => serde_json::to_string_pretty(
            &crate::report::report_to_gitlab_codequality(report, session),
        )
        .unwrap_or_default(),
        _ => serde_json::to_string_pretty(report).unwrap_or_default(),
    };
    if let Some(path) = output {
        std::fs::write(&path, &out).map_err(|e| {
            tracing::error!("Write failed: {}", e);
            e
        })?;
        println!("Report written to {}", path.display());
    } else {
        println!("{out}");
    }

    let has_high_or_critical = report
        .findings
        .iter()
        .any(|f| matches!(f.severity.as_str(), "high" | "critical"));
    if has_high_or_critical {
        return Err("IronVise: High or Critical findings detected - failing pipeline.".into());
    }
    Ok(())
}

/// Verify an IronVise Audit Certificate (.elc) file.
/// `ironvise verify-certificate`: the in-binary twin of the standalone
/// `verify-cert`, so verification is available without shipping a second file.
///
/// Delegates to `ectoledger_elc::verify` rather than carrying a second
/// implementation: a separate "same checks" implementation is how one could
/// end up skipping the sequence-gap check, ignoring findings that cite events
/// the certificate does not contain, or taking any bytes holding the Bitcoin
/// attestation marker as an anchor. Both call sites share one implementation
/// to verify against (see `verify_cert.rs`'s inspection-vs-authentication
/// split), so there is exactly one place to get this right.
///
/// `require_signature` is what separates inspection from authentication. The
/// hash chain, Merkle root and goal hash are all recomputed from the
/// certificate's own contents, so a certificate forged from scratch satisfies
/// every one of them. Only the signature ties the document to a key, and only
/// `expected_key` ties that key to anyone.
pub fn run_verify_certificate(
    file: &std::path::Path,
    require_signature: bool,
    expected_key: Option<&str>,
    require_anchor: bool,
    ots: Option<&std::path::Path>,
    export_ots: Option<&std::path::Path>,
    issuer: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::certificate::read_certificate_file;
    use ectoledger_elc::verify::{Requirements, verify};

    let cert =
        read_certificate_file(file).map_err(|e| format!("Could not read certificate: {e}"))?;
    if let Some(out) = export_ots {
        let bytes = ectoledger_elc::ots::detached_for(&cert)
            .map_err(|e| format!("Could not export the stamp: {e}"))?;
        std::fs::write(out, bytes)?;
        println!(
            "Wrote the stamp to {0}. Once a block confirms it: `ots upgrade {0}`, then \
             `ironvise verify-certificate --ots {0} <certificate>`.",
            out.display()
        );
    }
    let ots_file = match ots {
        Some(p) => {
            Some(std::fs::read(p).map_err(|e| format!("Could not read {}: {e}", p.display()))?)
        }
        None => None,
    };
    let report = verify(
        &cert,
        &Requirements {
            signature: require_signature,
            expected_key: expected_key.map(str::to_string),
            anchor: require_anchor,
            ots_file,
            issuer: issuer.map(str::to_string),
        }
        .normalised(),
    );
    print!("{}", report.render_checks(false));
    println!();
    if !report.is_valid() {
        // main prints the error; printing the verdict here too would say it twice.
        return Err(report.verdict_line().into());
    }
    println!("{}", report.verdict_line());
    Ok(())
}

/// `verify-session --against`: check the ledger against a certificate cut
/// from it earlier and held outside the database.
///
/// The certificate is verified first, with a signature required: an unsigned
/// one proves nothing about the past, since whoever rewrote the ledger could
/// have written it too. Then `ectoledger_elc::against::compare` checks the
/// session's key, every event hash the certificate covers, and whether any are
/// gone. Events after the certificate's tip are reported, not failed.
pub async fn run_verify_against_certificate(
    pool: &crate::pool::DatabasePool,
    session: Uuid,
    cert_path: &std::path::Path,
    expected_key: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use ectoledger_elc::against::{LedgerView, compare};
    use ectoledger_elc::verify::{Requirements, verify};

    let cert = crate::certificate::read_certificate_file(cert_path)
        .map_err(|e| format!("Could not read certificate: {e}"))?;
    let report = verify(
        &cert,
        &Requirements {
            signature: true,
            expected_key: expected_key.map(str::to_string),
            anchor: false,
            ots_file: None,
            issuer: None,
        },
    );
    if !report.is_valid() {
        print!("{}", report.render_checks(false));
        return Err(format!(
            "The certificate does not verify, so it cannot vouch for the ledger: {}",
            report.verdict_line()
        )
        .into());
    }

    let key = pool
        .list_sessions()
        .await?
        .into_iter()
        .find(|s| s.id == session)
        .ok_or_else(|| format!("No session {session} in this ledger"))?
        .session_public_key;
    let events: Vec<(i64, String)> = pool
        .get_events_by_session(session)
        .await?
        .into_iter()
        .map(|e| (e.sequence, e.content_hash))
        .collect();
    let session_str = session.to_string();
    let result = compare(
        &cert,
        &LedgerView {
            session_id: &session_str,
            session_public_key: key.as_deref(),
            events: &events,
        },
    );
    if !result.agrees() {
        return Err(format!(
            "The ledger contradicts {}: {}",
            cert_path.display(),
            result.problems.join("; ")
        )
        .into());
    }
    println!(
        "The ledger agrees with {} ({} events covered{}).",
        cert_path.display(),
        cert.events.len(),
        if result.events_after_certificate > 0 {
            format!(
                "; {} later event(s) are not covered by it",
                result.events_after_certificate
            )
        } else {
            String::new()
        }
    );
    Ok(())
}

/// Decode and verify a W3C VC-JWT issued by IronVise.
pub fn run_verify_vc(
    jwt: &str,
    issuer_hex: Option<&str>,
    audience: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::verifiable_credential::{VcVerifyError, verify_vc_jwt};
    use ed25519_dalek::VerifyingKey;

    let verifying_key: Option<VerifyingKey> = if let Some(hex_str) = issuer_hex {
        let key_bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("--issuer-hex is not valid hex: {e}"))?;
        if key_bytes.len() != 32 {
            return Err(format!(
                "--issuer-hex must be 32 bytes (64 hex chars), got {} bytes",
                key_bytes.len()
            )
            .into());
        }
        let arr: [u8; 32] = key_bytes.try_into().unwrap();
        Some(
            VerifyingKey::from_bytes(&arr)
                .map_err(|e| format!("invalid Ed25519 verifying key: {e}"))?,
        )
    } else {
        None
    };

    match verify_vc_jwt(jwt, verifying_key.as_ref(), audience) {
        Ok(payload) => {
            let pretty =
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
            if verifying_key.is_some() {
                println!("✓  VC-JWT signature valid (Ed25519)");
            } else {
                println!("⚠  VC-JWT decoded (signature not verified - no --issuer-hex provided)");
            }
            println!();
            println!("{pretty}");
            Ok(())
        }
        Err(VcVerifyError::Expired) => {
            Err("✗  VC-JWT has EXPIRED (exp claim is in the past).".into())
        }
        Err(VcVerifyError::InvalidSignature) => Err("✗  VC-JWT signature is INVALID.".into()),
        Err(VcVerifyError::Unsigned) => Err(
            "✗  VC-JWT is UNSIGNED (alg=none) but --issuer-hex was provided. \
             Remove --issuer-hex to decode without signature verification."
                .into(),
        ),
        Err(VcVerifyError::Malformed) => {
            Err("✗  VC-JWT is MALFORMED (expected header.payload.signature).".into())
        }
        Err(VcVerifyError::WrongAudience) => Err(
            "✗  VC-JWT is addressed to another audience. Pass --audience with the verifier's \
             own identifier; a VC that names an audience is refused without one."
                .into(),
        ),
    }
}

/// Replay events for a session (SQLite variant).
pub async fn run_replay_sqlite(
    pool: &sqlx::SqlitePool,
    session: uuid::Uuid,
    to_step: Option<u32>,
    inject_observation: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let events = crate::ledger::sqlite::get_events_by_session_sqlite(pool, session).await?;
    print_replay(events, to_step, inject_observation);
    Ok(())
}

/// Verify event signatures for a session (SQLite variant).
pub async fn run_verify_session_sqlite(
    pool: &sqlx::SqlitePool,
    session: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let verdict = crate::ledger::sqlite::verify_session_detailed_sqlite(pool, session).await?;
    match verdict {
        crate::ledger::SessionVerdict::Verified {
            signatures,
            unsigned,
        } => {
            println!("All {signatures} event signatures verified for session {session}.");
            if unsigned > 0 {
                // Say what the signatures do not cover, rather than letting a
                // count of signatures read as a count of events.
                println!(
                    "{unsigned} further event(s) are unsigned by design (client-asserted, \
                     seals, anchors, pre-0.8 approval copies) and covered by the hash chain only."
                );
            }
            Ok(())
        }
        other => Err(format!("Verification FAILED for session {session}: {other}").into()),
    }
}

/// Export audit report for a session (SQLite variant).
pub async fn run_report_sqlite(
    pool: &sqlx::SqlitePool,
    session: uuid::Uuid,
    format: String,
    output: Option<std::path::PathBuf>,
    no_ots: bool,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if format.to_lowercase() == "certificate" {
        let cert =
            crate::certificate::build_certificate_sqlite(pool, session, signing_key, !no_ots, None)
                .await?;
        let out =
            output.unwrap_or_else(|| std::path::PathBuf::from(format!("audit-{session}.elc")));
        crate::certificate::write_certificate_file(&cert, &out)?;
        println!("Certificate written to {}", out.display());
        return Ok(());
    }
    let report = crate::report::build_report_sqlite(pool, session).await?;
    print_report(&report, session, format, output)
}

/// How a `verify-ledger` survey came out.
///
/// Returned rather than turned straight into an exit code, because the two
/// callers want different things from the same numbers: the CLI prints a
/// summary and only fails under `--strict`, while tests assert on the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerSurvey {
    pub surveyed: usize,
    pub failed: usize,
}

impl LedgerSurvey {
    /// True when every surveyed session verified.
    pub fn all_verified(&self) -> bool {
        self.failed == 0
    }
}

/// `ironvise verify-ledger` - survey every session, read-only.
///
/// 0.8.0 tightened `verify-session` so that signatures bind their events
/// (the 0.8.0 changelog, F-1). That is a stricter check than any
/// previous release ran, so before it starts refusing sessions an operator
/// should be able to ask, without risk, "does this affect anything I have?".
/// This never writes.
///
/// It also does not decide the exit code. A bad session is a *finding* here,
/// not a tool failure - that is the whole difference between this command and
/// `verify-session` - so the count comes back and `main` chooses, which is
/// what makes `--strict` possible without giving the default a second meaning.
pub async fn run_verify_ledger_sqlite(
    pool: &sqlx::SqlitePool,
    show_all: bool,
) -> Result<LedgerSurvey, Box<dyn std::error::Error + Send + Sync>> {
    let ids: Vec<String> =
        match sqlx::query_scalar::<_, String>("SELECT id FROM agent_sessions ORDER BY created_at")
            .fetch_all(pool)
            .await
        {
            Ok(ids) => ids,
            Err(e) if is_missing_ledger_tables(&e) => return Err(no_ledger_here().into()),
            Err(e) => return Err(e.into()),
        };

    let mut failed = 0usize;
    for id in &ids {
        let Ok(session) = uuid::Uuid::parse_str(id) else {
            continue;
        };
        let verdict = crate::ledger::sqlite::verify_session_detailed_sqlite(pool, session).await?;
        if verdict.is_verified() {
            if show_all {
                println!("  ok    {session}  {verdict}");
            }
        } else {
            failed += 1;
            println!("  FAIL  {session}  {verdict}");
        }
    }
    report_ledger_summary(ids.len(), failed);
    Ok(LedgerSurvey {
        surveyed: ids.len(),
        failed,
    })
}

/// PostgreSQL variant of [`run_verify_ledger_sqlite`].
pub async fn run_verify_ledger(
    pool: &sqlx::PgPool,
    show_all: bool,
) -> Result<LedgerSurvey, Box<dyn std::error::Error + Send + Sync>> {
    let sessions = match crate::ledger::list_sessions(pool).await {
        Ok(s) => s,
        Err(e) if is_missing_ledger_tables(&e) => return Err(no_ledger_here().into()),
        Err(e) => return Err(e.into()),
    };
    let mut failed = 0usize;
    for s in &sessions {
        let verdict = crate::ledger::postgres::verify_session_detailed(pool, s.id).await?;
        if verdict.is_verified() {
            if show_all {
                println!("  ok    {}  {}", s.id, verdict);
            }
        } else {
            failed += 1;
            println!("  FAIL  {}  {}", s.id, verdict);
        }
    }
    report_ledger_summary(sessions.len(), failed);
    Ok(LedgerSurvey {
        surveyed: sessions.len(),
        failed,
    })
}

/// Does this error mean "the ledger schema is not here" rather than a genuine
/// query failure?
///
/// `verify-ledger` deliberately does not run migrations - it must not alter the
/// database it was asked to inspect - so pointing it at an empty or unrelated
/// database now surfaces a missing-table error instead of silently creating the
/// schema. That is the right behaviour, but a raw driver error dump is not a
/// useful way to say it.
fn is_missing_ledger_tables(e: &sqlx::Error) -> bool {
    match e {
        // PostgreSQL 42P01: undefined_table.
        sqlx::Error::Database(db) => {
            db.code().as_deref() == Some("42P01") || db.message().contains("no such table")
        }
        _ => false,
    }
}

fn no_ledger_here() -> String {
    // Deliberately one line: main prints the boxed error with Debug, so an
    // embedded newline would come out as a literal `\n`.
    "no ledger in this database - the agent_events/agent_sessions tables do not exist. \
     verify-ledger is read-only and will not create or migrate a schema, so check that \
     DATABASE_URL points at an existing ledger."
        .to_string()
}

fn report_ledger_summary(total: usize, failed: usize) {
    println!();
    if failed == 0 {
        println!("{total} session(s) surveyed, all verify under the 0.8.0 rules.");
    } else {
        println!(
            "{total} session(s) surveyed, {failed} do not verify.\n\
             \n\
             Before assuming tampering, check the boring explanations first: a\n\
             ledger written by v0.6.4's SQLite backend cannot verify its own\n\
             events at all (a key-ordering defect fixed in 0.7.0, see\n\
             docs/reference/schema.md), and a restored or hand-edited row will look the\n\
             same as an attack from here. `AlteredAfterSigning` is the verdict\n\
             that has no innocent explanation."
        );
    }
}

#[cfg(test)]
mod signing_tests;
