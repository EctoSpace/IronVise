//! `ironvise import-openshell`: turn NVIDIA OpenShell's decision log into
//! signed, hash-chained receipts.
//!
//! OpenShell writes OCSF 1.8.0 JSON lines (`/var/log/openshell-ocsf.*.log`
//! inside a sandbox, or the gateway's OCSF log). Its own docs call collection
//! best-effort and not proof of a complete history, and no record carries a
//! hash, signature or sequence number. The import adds that: one ledger
//! session per sandbox, every record signed with the SHA-256 of its original
//! line, the session sealed, and a signed `.elc` receipt written for it.
//!
//! In `enforcement: audit` mode OpenShell logs a violating request as
//! `Allowed`; only the second word of `message` says `audit`. Those records
//! are imported as decision `audit`, not as a plain allow.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::pool::DatabasePool;
use crate::schema::EventPayload;

const BACKEND_LABEL: &str = "openshell-import";
/// Scope for OCSF `metadata.uid` in `consumed_requests`: a record imported
/// once is skipped the next time the same log is imported.
const DEDUP_SCOPE: &str = "openshell-ocsf";

/// How OpenShell decided, read from `action_id` and the audit-mode marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Denied,
    /// Allowed only because the endpoint is in audit mode: would have been denied.
    Audit,
    /// Any other record (observed, modified, lifecycle, config).
    Other,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Decision::Allowed => "allowed",
            Decision::Denied => "denied",
            Decision::Audit => "audit",
            Decision::Other => "other",
        }
    }
}

pub fn decision(record: &Value) -> Decision {
    let audit = record["message"]
        .as_str()
        .and_then(|m| m.split_whitespace().nth(1))
        == Some("audit");
    match record["action_id"].as_i64() {
        Some(1) if audit => Decision::Audit,
        Some(1) => Decision::Allowed,
        Some(2) => Decision::Denied,
        _ => Decision::Other,
    }
}

fn target(record: &Value) -> String {
    if let Some(url) = record.get("http_request").and_then(|r| r.get("url")) {
        let s = |k: &str| url[k].as_str().unwrap_or_default().to_string();
        return format!("{}://{}{}", s("scheme"), s("hostname"), s("path"));
    }
    let ep = &record["dst_endpoint"];
    let host = ep["domain"].as_str().or(ep["ip"].as_str()).unwrap_or("?");
    match ep["port"].as_i64() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// The ledger event for one record. `line` is the raw line, hashed as read.
pub fn to_event(record: &Value, line: &str, file: &str, line_no: usize) -> EventPayload {
    let decision = decision(record);
    let class = record["class_name"].as_str().unwrap_or("OCSF event");
    let rule = record["firewall_rule"]["name"].as_str().unwrap_or("-");
    let engine = record["firewall_rule"]["type"].as_str().unwrap_or("?");
    let params = json!({
        "source": DEDUP_SCOPE,
        "file": file,
        "line": line_no,
        "line_sha256": hex::encode(Sha256::digest(line.as_bytes())),
        "event_uid": record["metadata"]["uid"],
        "time_ms": record["time"],
        "decision": decision.as_str(),
        "rule": rule,
        "engine": engine,
        "target": target(record),
        "actor": record["actor"]["process"]["name"],
        "record": record,
    });
    let name = format!("openshell:{}", class.to_lowercase().replace(' ', "_"));
    match decision {
        Decision::Denied => EventPayload::TripwireRejection {
            action: Some(name),
            reason: format!(
                "OpenShell denied {} (rule {rule}, engine {engine}): {}",
                target(record),
                record["status_detail"]
                    .as_str()
                    .or(record["message"].as_str())
                    .unwrap_or("no reason given")
            ),
            stage: format!("openshell:{engine}"),
            enforced: true,
        },
        Decision::Allowed | Decision::Audit => EventPayload::Action { name, params },
        Decision::Other => EventPayload::Observation {
            content: params.to_string(),
        },
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Sandbox id → ledger session.
    pub sessions: BTreeMap<String, Uuid>,
    pub imported: usize,
    pub duplicates: usize,
    /// `file:line` of lines that are not JSON objects.
    pub malformed: Vec<String>,
    pub by_decision: BTreeMap<&'static str, usize>,
    pub receipts: Vec<PathBuf>,
}

struct Open {
    id: Uuid,
    goal: String,
    key: Arc<SigningKey>,
}

/// Import `files` into `pool`; write one signed receipt per sandbox session
/// into `out`.
pub async fn import(pool: &DatabasePool, files: &[PathBuf], out: &Path) -> Result<Report, String> {
    let mut report = Report::default();
    let mut open: BTreeMap<String, Open> = BTreeMap::new();
    for path in files {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let file = path.display().to_string();
        for (i, line) in text.lines().enumerate() {
            let line_no = i + 1;
            if line.trim().is_empty() {
                continue;
            }
            let Ok(record @ Value::Object(_)) = serde_json::from_str::<Value>(line) else {
                report.malformed.push(format!("{file}:{line_no}"));
                continue;
            };
            // OpenShell gives every record a fresh `metadata.uid`; a record
            // without one is recognised by its bytes instead.
            let dedup_id = match record["metadata"]["uid"].as_str() {
                Some(uid) => uid.to_string(),
                None => format!("sha256:{}", hex::encode(Sha256::digest(line.as_bytes()))),
            };
            if !pool
                .consume_request(DEDUP_SCOPE, &dedup_id, BACKEND_LABEL)
                .await
                .map_err(|e| format!("dedup check: {e}"))?
            {
                report.duplicates += 1;
                continue;
            }
            let sandbox = record["container"]["uid"]
                .as_str()
                .unwrap_or("unknown-sandbox")
                .to_string();
            if !open.contains_key(&sandbox) {
                let name = record["container"]["name"].as_str().unwrap_or("?");
                let goal = format!("OpenShell sandbox {name} ({sandbox})");
                let (session, key) = pool
                    .create_session(&goal, BACKEND_LABEL, "n/a", None)
                    .await
                    .map_err(|e| format!("creating a session: {e}"))?;
                open.insert(
                    sandbox.clone(),
                    Open {
                        id: session.id,
                        goal,
                        key: Arc::new(key),
                    },
                );
            }
            let s = &open[&sandbox];
            pool.append_event(
                to_event(&record, line, &file, line_no),
                Some(s.id),
                Some(&s.goal),
                Some(s.key.as_ref()),
            )
            .await
            .map_err(|e| format!("recording {file}:{line_no}: {e}"))?;
            report.imported += 1;
            *report
                .by_decision
                .entry(decision(&record).as_str())
                .or_default() += 1;
        }
    }

    if !open.is_empty() {
        std::fs::create_dir_all(out).map_err(|e| format!("creating {}: {e}", out.display()))?;
    }
    for (sandbox, s) in open {
        pool.finish_session(s.id, "completed")
            .await
            .map_err(|e| format!("sealing {}: {e}", s.id))?;
        let key = Some(s.key.as_ref());
        let cert = match pool {
            DatabasePool::Postgres(pg) => {
                crate::certificate::build_certificate(pg, s.id, key, false, None).await
            }
            DatabasePool::Sqlite(sq) => {
                crate::certificate::build_certificate_sqlite(sq, s.id, key, false, None).await
            }
        }
        .map_err(|e| format!("receipt for {}: {e}", s.id))?;
        let path = out.join(format!("openshell-{}.elc", s.id));
        crate::certificate::write_certificate_file(&cert, &path)
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        report.receipts.push(path);
        report.sessions.insert(sandbox, s.id);
    }
    Ok(report)
}

pub async fn run(
    pool: DatabasePool,
    files: &[PathBuf],
    out: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let r = import(&pool, files, out).await?;
    println!(
        "Imported {} OpenShell records ({}), {} already imported, {} malformed.",
        r.imported,
        r.by_decision
            .iter()
            .map(|(d, n)| format!("{n} {d}"))
            .collect::<Vec<_>>()
            .join(", "),
        r.duplicates,
        r.malformed.len()
    );
    for (sandbox, id) in &r.sessions {
        println!("  sandbox {sandbox}  ->  session {id}");
    }
    for p in &r.receipts {
        println!("  receipt {}", p.display());
    }
    if !r.malformed.is_empty() {
        eprintln!(
            "Not imported (not a JSON object): {}",
            r.malformed.join(", ")
        );
    }
    if r.by_decision.contains_key("audit") {
        println!(
            "Note: `audit` records were ALLOWED only because their endpoint is in audit \
             mode; OpenShell would have denied them."
        );
    }
    Ok(())
}
