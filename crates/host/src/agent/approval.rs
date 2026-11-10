//! A policy approval gate: a human approves or rejects the action, on the
//! terminal or from the dashboard, before a timeout decides for them.

use super::{AgentError, CognitiveLoop};
use crate::approvals::{ApprovalState, PendingApproval};
use crate::intent::ProposedIntent;
use crate::policy::ApprovalGateRule;
use crate::schema::EventPayload;
use std::io::Write;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// How long a gate waits when the policy names no timeout.
const DEFAULT_TIMEOUT_SECS: u64 = 300;
/// How often the dashboard's decision is checked.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

impl CognitiveLoop<'_> {
    /// Records the request, waits for the decision and records it. True when
    /// the action may run.
    pub(super) async fn approve(
        &self,
        intent: &ProposedIntent,
        gate: &ApprovalGateRule,
    ) -> Result<bool, AgentError> {
        let gate_id = Uuid::new_v4().to_string();
        let timeout = Duration::from_secs(gate.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECS));
        let allow_on_timeout = gate.on_timeout.as_deref() == Some("allow");
        let params = serde_json::to_string(&intent.params).unwrap_or_else(|_| "{}".to_string());
        self.record(EventPayload::ApprovalRequired {
            gate_id: gate_id.clone(),
            action_name: intent.action.clone(),
            action_params_summary: params.clone(),
        })
        .await?;

        let mut store_error = None;
        let decision = if self.config.interactive {
            ask_on_terminal(&intent.action, &params, timeout).await
        } else if let Some(state) = &self.config.approval_state {
            let pending = PendingApproval {
                gate_id: gate_id.clone(),
                action_name: intent.action.clone(),
                action_params_summary: params,
                created_at: chrono::Utc::now(),
            };
            let session = self.config.session_id.unwrap_or_default();
            match wait_for_dashboard(state, session, pending, timeout).await {
                Ok(decision) => decision,
                Err(e) => {
                    store_error = Some(e.to_string());
                    None
                }
            }
        } else {
            None
        };
        let channel = if self.config.interactive {
            "cli"
        } else {
            "api"
        };
        let (approved, reason) = match decision {
            Some((approved, Some(r))) if !r.trim().is_empty() => {
                (approved, format!("operator:{channel}: {}", r.trim()))
            }
            Some((approved, _)) => (approved, format!("operator:{channel}")),
            None => {
                let outcome = if allow_on_timeout { "allow" } else { "deny" };
                let asked = self.config.interactive || self.config.approval_state.is_some();
                let reason = if let Some(e) = &store_error {
                    format!("approval store unavailable ({e}); on_timeout={outcome}")
                } else if asked {
                    format!(
                        "timeout: no decision within {}s; on_timeout={outcome}",
                        timeout.as_secs()
                    )
                } else {
                    format!("no approver configured; on_timeout={outcome}")
                };
                (allow_on_timeout, reason)
            }
        };

        // The only record of the decision, signed like every other event: the
        // approvals API writes none of its own, so the operator's reason
        // travels here, and a timeout is never recorded as an operator's.
        self.record(EventPayload::ApprovalDecision {
            gate_id: gate_id.clone(),
            approved,
            reason: Some(reason.clone()),
        })
        .await?;
        let verdict = if approved { "approved" } else { "denied" };
        self.record_thought(format!("Approval gate '{gate_id}' {verdict} ({reason})."))
            .await?;
        Ok(approved)
    }
}

/// Asks on the terminal: the operator's answer, or `None` at the timeout.
/// The answer is read on a thread of its own: a read from tokio's stdin
/// cannot be cancelled, and would hold a runtime thread after the timeout.
async fn ask_on_terminal(
    action: &str,
    params: &str,
    timeout: Duration,
) -> Option<(bool, Option<String>)> {
    eprintln!();
    eprintln!("[APPROVAL REQUIRED]");
    eprintln!("  Action : {action}");
    eprintln!("  Params : {params}");
    eprint!("Approve? [y/N] (times out in {}s): ", timeout.as_secs());
    let _ = std::io::stderr().flush();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let yes =
            std::io::stdin().read_line(&mut line).is_ok() && line.trim().eq_ignore_ascii_case("y");
        let _ = tx.blocking_send(yes);
    });
    tokio::select! {
        answer = rx.recv() => answer.map(|yes| (yes, None)),
        _ = tokio::time::sleep(timeout) => None,
    }
}

/// Publishes the request where `GET /api/approvals/:id/pending` shows
/// it, so the operator sees what they are approving, then waits for the
/// decision the dashboard posts: the decision, or `None` at the timeout, when
/// the request is withdrawn so a late click is refused. On PostgreSQL the
/// decision may be posted to any instance.
async fn wait_for_dashboard(
    state: &ApprovalState,
    session: Uuid,
    pending: PendingApproval,
    timeout: Duration,
) -> Result<Option<(bool, Option<String>)>, sqlx::Error> {
    let gate_id = pending.gate_id.clone();
    state.publish(session, pending).await?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(decision) = state.take(session, &gate_id).await? {
            return Ok(Some(decision));
        }
        if Instant::now() >= deadline {
            return state.withdraw(session, &gate_id).await;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
