// Audit report export: SARIF 2.1, JSON, HTML.

use crate::ledger;
use crate::schema::{AuditFinding, EventPayload, LedgerEventRow, SessionRow};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct AuditReport {
    pub session: SessionRow,
    pub ledger_hash: String,
    pub verification_status: ChainVerificationStatus,
    pub findings: Vec<VerifiedFinding>,
    pub timeline: Vec<AuditEventSummary>,
    pub metrics: AuditMetrics,
}

#[derive(Clone, Debug, Serialize)]
pub enum ChainVerificationStatus {
    Verified,
    Failed,
    NotChecked,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifiedFinding {
    pub severity: String,
    pub title: String,
    pub evidence: String,
    pub recommendation: String,
    pub evidence_sequences: Vec<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEventSummary {
    pub sequence: i64,
    pub kind: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditMetrics {
    pub event_count: usize,
    pub finding_count: usize,
}

pub async fn build_report(pool: &PgPool, session_id: Uuid) -> Result<AuditReport, ReportError> {
    let session = ledger::list_sessions(pool)
        .await
        .map_err(ReportError::Db)?
        .into_iter()
        .find(|s| s.id == session_id)
        .ok_or(ReportError::SessionNotFound(session_id))?;

    let events = ledger::get_events_by_session(pool, session_id)
        .await
        .map_err(ReportError::Db)?;

    let verification_status = if events.is_empty() {
        ChainVerificationStatus::NotChecked
    } else if ledger::verify_chain(
        pool,
        events.first().unwrap().sequence,
        events.last().unwrap().sequence,
    )
    .await
    .map_err(ReportError::Db)?
    {
        ChainVerificationStatus::Verified
    } else {
        ChainVerificationStatus::Failed
    };

    build_report_from_events(session, events, verification_status)
}

/// Build an audit report from a SQLite-backed ledger.
pub async fn build_report_sqlite(
    pool: &sqlx::SqlitePool,
    session_id: Uuid,
) -> Result<AuditReport, ReportError> {
    let session = ledger::sqlite::list_sessions_sqlite(pool)
        .await
        .map_err(ReportError::Db)?
        .into_iter()
        .find(|s| s.id == session_id)
        .ok_or(ReportError::SessionNotFound(session_id))?;

    let events = ledger::sqlite::get_events_by_session_sqlite(pool, session_id)
        .await
        .map_err(ReportError::Db)?;

    let verification_status = if events.is_empty() {
        ChainVerificationStatus::NotChecked
    } else if ledger::sqlite::verify_chain_sqlite(
        pool,
        events.first().unwrap().sequence,
        events.last().unwrap().sequence,
    )
    .await
    .map_err(ReportError::Db)?
    {
        ChainVerificationStatus::Verified
    } else {
        ChainVerificationStatus::Failed
    };

    build_report_from_events(session, events, verification_status)
}

/// Shared report assembly: extracts findings, builds timeline, computes metrics.
fn build_report_from_events(
    session: SessionRow,
    events: Vec<LedgerEventRow>,
    verification_status: ChainVerificationStatus,
) -> Result<AuditReport, ReportError> {
    let ledger_hash = events
        .last()
        .map(|e| e.content_hash.clone())
        .unwrap_or_else(|| "none".to_string());

    let mut findings = Vec::new();
    for ev in &events {
        if let EventPayload::Action { name, params } = &ev.payload
            && name == "complete"
            && let Some(fv) = params.get("findings")
            && let Ok(fs) = serde_json::from_value::<Vec<AuditFinding>>(fv.clone())
        {
            for f in fs {
                findings.push(VerifiedFinding {
                    severity: format!("{:?}", f.severity).to_lowercase(),
                    title: f.title,
                    evidence: f.evidence,
                    recommendation: f.recommendation,
                    evidence_sequences: f.evidence_sequence,
                });
            }
        }
    }

    let timeline: Vec<AuditEventSummary> = events.iter().map(event_summary).collect();

    let metrics = AuditMetrics {
        event_count: events.len(),
        finding_count: findings.len(),
    };

    Ok(AuditReport {
        session,
        ledger_hash,
        verification_status,
        findings,
        timeline,
        metrics,
    })
}

fn event_summary(e: &LedgerEventRow) -> AuditEventSummary {
    let (kind, summary) = match &e.payload {
        EventPayload::Genesis { message, .. } => ("genesis", message.clone()),
        EventPayload::PromptInput { content } => ("prompt_input", format!("Goal: {content}")),
        EventPayload::Thought { content } => (
            "thought",
            if content.chars().count() > 80 {
                format!("{}...", content.chars().take(80).collect::<String>())
            } else {
                content.clone()
            },
        ),
        EventPayload::DataReceipt {
            tool,
            source,
            text_sha256,
            text_bytes,
            ..
        } => (
            "data_receipt",
            format!(
                "{tool} {} returned {text_bytes} bytes in {} text(s), recorded by SHA-256",
                source.as_deref().unwrap_or(""),
                text_sha256.len()
            ),
        ),
        EventPayload::SchemaError {
            message,
            attempt,
            max_attempts,
        } => (
            "schema_error",
            format!("({attempt}/{max_attempts}) {message}"),
        ),
        EventPayload::GuardDenial {
            action,
            reason,
            enforced,
        } => (
            "guard_denial",
            format!(
                "{} {}: {}",
                action.as_deref().unwrap_or("action"),
                if *enforced { "prevented" } else { "flagged" },
                reason
            ),
        ),
        EventPayload::TripwireRejection {
            action,
            reason,
            stage,
            enforced,
        } => (
            "tripwire_rejection",
            format!(
                "{} {} at {}: {}",
                action.as_deref().unwrap_or("prompt"),
                if *enforced { "prevented" } else { "flagged" },
                stage,
                reason
            ),
        ),
        EventPayload::CircuitBreaker {
            reason,
            consecutive_failures,
        } => (
            "circuit_breaker",
            format!("({consecutive_failures} consecutive failures) {reason}"),
        ),
        EventPayload::Action { name, params } => ("action", format!("{name} {params:?}")),
        EventPayload::Observation { content } => (
            "observation",
            if content.len() > 80 {
                let truncated: String = content.chars().take(80).collect();
                format!("{truncated}...")
            } else {
                content.clone()
            },
        ),
        EventPayload::ApprovalRequired {
            gate_id,
            action_name,
            action_params_summary,
        } => (
            "approval_required",
            format!("gate {gate_id}: {action_name} {action_params_summary}"),
        ),
        EventPayload::ApprovalDecision {
            gate_id,
            approved,
            reason,
        } => (
            "approval_decision",
            format!(
                "gate {}: {} {}",
                gate_id,
                if *approved { "approved" } else { "denied" },
                reason.as_deref().unwrap_or("")
            ),
        ),
        EventPayload::CrossLedgerSeal {
            seal_hash,
            session_ids,
            ..
        } => (
            "cross_ledger_seal",
            format!(
                "seal {} covering {} sessions",
                &seal_hash[..16],
                session_ids.len()
            ),
        ),
        EventPayload::Anchor {
            ledger_tip_hash,
            bitcoin_block_height,
            ..
        } => (
            "anchor",
            format!(
                "OTS anchor tip {} block {:?}",
                &ledger_tip_hash[..16],
                bitcoin_block_height
            ),
        ),
        EventPayload::KeyRotation {
            new_public_key,
            rotation_index,
        } => (
            "key_rotation",
            format!(
                "rotation {} new_key {}",
                rotation_index,
                &new_public_key[..16.min(new_public_key.len())]
            ),
        ),
        EventPayload::KeyRevocation {
            revoked_public_key,
            reason,
        } => (
            "key_revocation",
            format!(
                "revoked key {} reason: {}",
                &revoked_public_key[..16.min(revoked_public_key.len())],
                reason
            ),
        ),
        EventPayload::VerifiableCredential { .. } => (
            "verifiable_credential",
            "W3C VC-JWT issued for this session".to_string(),
        ),
        EventPayload::ChatMessage { role, content, .. } => (
            "chat_message",
            format!(
                "[{}] {}",
                role,
                if content.chars().nth(80).is_some() {
                    format!("{}...", content.chars().take(80).collect::<String>())
                } else {
                    content.clone()
                }
            ),
        ),
    };
    AuditEventSummary {
        sequence: e.sequence,
        kind: kind.to_string(),
        summary,
    }
}

pub fn report_to_sarif(report: &AuditReport, session_id: Uuid) -> serde_json::Value {
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let rule_id = format!("finding-{}", i + 1);
            let level = match f.severity.as_str() {
                "critical" => "error",
                "high" => "error",
                "medium" => "warning",
                _ => "note",
            };
            let locations: Vec<serde_json::Value> = f
                .evidence_sequences
                .iter()
                .map(|&seq| {
                    serde_json::json!({
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": format!("ledger://session/{}/sequence/{}", session_id, seq)
                            },
                            "region": { "startLine": 1 }
                        }
                    })
                })
                .collect();
            serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": f.title },
                "locations": if locations.is_empty() {
                    vec![serde_json::json!({ "physicalLocation": { "artifactLocation": { "uri": "ledger://" } } })]
                } else {
                    locations
                }
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "IronVise",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/EctoSpace/EctoLedger",
                    "rules": report.findings.iter().enumerate().map(|(i, f)| {
                        serde_json::json!({
                            "id": format!("finding-{}", i + 1),
                            "name": f.title,
                            "shortDescription": { "text": f.evidence },
                            "defaultConfiguration": { "level": "warning" }
                        })
                    }).collect::<Vec<_>>()
                }
            },
            "results": results,
            "properties": {
                "ledgerHash": report.ledger_hash,
                "verificationStatus": format!("{:?}", report.verification_status),
                "sessionId": report.session.id.to_string()
            }
        }]
    })
}

pub fn report_to_html(report: &AuditReport, session_id: Uuid) -> String {
    let status_class = match &report.verification_status {
        crate::report::ChainVerificationStatus::Verified => "verified",
        crate::report::ChainVerificationStatus::Failed => "failed",
        crate::report::ChainVerificationStatus::NotChecked => "unknown",
    };
    let findings_rows: String = report
        .findings
        .iter()
        .map(|f| {
            let seq_links: String = f
                .evidence_sequences
                .iter()
                .map(|seq| format!("<a href=\"#seq-{seq}\">#{seq}</a> "))
                .collect();
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                f.severity,
                html_escape(&f.title),
                html_escape(&f.evidence),
                html_escape(&f.recommendation),
                seq_links
            )
        })
        .collect();
    let timeline_rows: String = report
        .timeline
        .iter()
        .map(|e| {
            format!(
                r#"<tr id="seq-{}"><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                e.sequence,
                e.sequence,
                e.kind,
                html_escape(&e.summary)
            )
        })
        .collect();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><title>Audit Report - {}</title>
<style>
  body {{ font-family: system-ui; margin: 24px; background: #0d1117; color: #c9d1d9; }}
  .hash {{ font-family: monospace; word-break: break-all; }}
  .verified {{ color: #3fb950; }}
  .failed {{ color: #f85149; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
  th, td {{ border: 1px solid #30363d; padding: 8px; text-align: left; }}
  th {{ background: #21262d; }}
  a {{ color: #58a6ff; }}
</style>
</head>
<body>
<h1>Audit Report</h1>
<p><strong>Session:</strong> {}<br/>
<strong>Goal:</strong> {}<br/>
<strong>Ledger hash:</strong> <span class="hash">{}</span><br/>
<strong>Chain verification:</strong> <span class="{}">{:?}</span></p>
<h2>Findings ({})</h2>
<table><thead><tr><th>Severity</th><th>Title</th><th>Evidence</th><th>Recommendation</th><th>Ledger refs</th></tr></thead>
<tbody>{}</tbody></table>
<h2>Timeline</h2>
<table><thead><tr><th>Seq</th><th>Kind</th><th>Summary</th></tr></thead>
<tbody>{}</tbody></table>
</body></html>"#,
        session_id,
        session_id,
        html_escape(&report.session.goal),
        report.ledger_hash,
        status_class,
        report.verification_status,
        report.findings.len(),
        findings_rows,
        timeline_rows
    )
}

/// Workflow-command escaping, as GitHub's toolkit does it. Finding text comes
/// from the model and the audited system; unescaped, a newline in it starts a
/// new workflow command (`::set-output`, `::add-mask`, …) in the CI log.
fn escape_actions_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_actions_property(s: &str) -> String {
    escape_actions_data(s)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

/// Emits GitHub Actions workflow command strings so findings appear inline in CI logs.
///
/// Severity mapping:
///   critical / high  → `::error`
///   medium           → `::warning`
///   low / other      → `::notice`
pub fn report_to_github_actions(report: &AuditReport) -> String {
    report
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let level = match f.severity.as_str() {
                "critical" | "high" => "error",
                "medium" => "warning",
                _ => "notice",
            };
            let seq_refs: String = f
                .evidence_sequences
                .iter()
                .map(|s| format!("ledger seq: {s}"))
                .collect::<Vec<_>>()
                .join(", ");
            let detail = if seq_refs.is_empty() {
                f.evidence.clone()
            } else {
                format!("{} [{}]", f.evidence, seq_refs)
            };
            format!(
                "::{level} title={title}::{detail}",
                level = level,
                title = escape_actions_property(&format!(
                    "{} Finding #{} - {}",
                    f.severity,
                    i + 1,
                    f.title
                )),
                detail = escape_actions_data(&detail),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Emits a GitLab Code Quality JSON array (Code Climate subset).
///
/// Severity mapping:
///   critical → `"critical"`, high → `"major"`, medium → `"minor"`, low/other → `"info"`
pub fn report_to_gitlab_codequality(report: &AuditReport, session_id: Uuid) -> serde_json::Value {
    use sha2::{Digest, Sha256};

    let entries: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let gl_severity = match f.severity.as_str() {
                "critical" => "critical",
                "high" => "major",
                "medium" => "minor",
                _ => "info",
            };
            // Deterministic fingerprint: sha256(session_id + title)
            let mut hasher = Sha256::new();
            hasher.update(session_id.as_bytes());
            hasher.update(f.title.as_bytes());
            let fingerprint = hex::encode(hasher.finalize());

            let begin_line = f.evidence_sequences.first().copied().unwrap_or(1);
            serde_json::json!({
                "description": f.title,
                "severity": gl_severity,
                "fingerprint": fingerprint,
                "location": {
                    "path": "ledger",
                    "lines": { "begin": begin_line }
                }
            })
        })
        .collect();

    serde_json::Value::Array(entries)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("session not found: {0}")]
    SessionNotFound(Uuid),
}

#[cfg(test)]
mod actions_tests {
    use super::*;

    fn report_with(title: &str, evidence: &str) -> AuditReport {
        AuditReport {
            session: SessionRow {
                id: Uuid::nil(),
                goal: "g".into(),
                goal_hash: None,
                status: "completed".into(),
                llm_backend: None,
                llm_model: None,
                created_at: chrono::Utc::now(),
                finished_at: None,
                policy_hash: None,
                session_public_key: None,
                session_did: None,
                enclave_attestation_json: None,
            },
            ledger_hash: String::new(),
            verification_status: ChainVerificationStatus::NotChecked,
            findings: vec![VerifiedFinding {
                severity: "high".into(),
                title: title.into(),
                evidence: evidence.into(),
                recommendation: String::new(),
                evidence_sequences: vec![],
            }],
            timeline: vec![],
            metrics: AuditMetrics {
                event_count: 0,
                finding_count: 1,
            },
        }
    }

    #[test]
    fn escapes_follow_the_actions_toolkit() {
        assert_eq!(escape_actions_data("100%\r\nx"), "100%25%0D%0Ax");
        assert_eq!(escape_actions_property("a:b,c%\n"), "a%3Ab%2Cc%25%0A");
        assert_eq!(escape_actions_data("a:b,c"), "a:b,c");
    }

    #[test]
    fn a_finding_cannot_start_its_own_workflow_command() {
        let out = report_to_github_actions(&report_with(
            "t::x,y",
            "leak\n::add-mask::secret\r\n::set-output name=a::b",
        ));
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.starts_with("::error title=high Finding #1 - t%3A%3Ax%2Cy::"));
        let detail = out.split_once("%2Cy::").unwrap().1;
        assert_eq!(
            detail,
            "leak%0A::add-mask::secret%0D%0A::set-output name=a::b"
        );
    }
}

#[cfg(test)]
mod summary_tests {
    use super::*;

    fn row(payload: EventPayload) -> LedgerEventRow {
        LedgerEventRow {
            id: 1,
            sequence: 1,
            previous_hash: String::new(),
            content_hash: String::new(),
            payload,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn a_long_chat_message_with_multibyte_text_is_cut_at_80_characters() {
        // A two-byte character straddles byte 80, where a byte slice panics.
        let content = format!("{}é{}", "a".repeat(79), "b".repeat(40));
        let summary = event_summary(&row(EventPayload::ChatMessage {
            role: "user".into(),
            content,
            backend: None,
            model: None,
        }));
        assert_eq!(summary.kind, "chat_message");
        assert_eq!(summary.summary, format!("[user] {}é...", "a".repeat(79)));
    }

    #[test]
    fn a_long_observation_with_multibyte_text_is_cut_at_80_characters() {
        let content = "日本語".repeat(40);
        let summary = event_summary(&row(EventPayload::Observation { content }));
        assert_eq!(summary.summary.chars().count(), 83);
    }
}
