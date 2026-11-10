//! Human-in-the-loop approval queue.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;

#[derive(serde::Serialize)]
pub(crate) struct PendingApprovalResponse {
    pending: Option<PendingApproval>,
}

pub(crate) async fn get_pending_approval(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<PendingApprovalResponse>, (StatusCode, String)> {
    let pending = state
        .approval_state
        .pending(session_id)
        .await
        .map_err(store_unavailable)?;
    Ok(axum::Json(PendingApprovalResponse { pending }))
}

fn store_unavailable(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!("approval store: {e}");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "the approval store could not be reached".into(),
    )
}

pub(crate) async fn post_approval_decision(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<ApprovalDecisionRequest>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    // Only Admin may approve or deny actions.
    if role != Role::Admin {
        return Err((
            StatusCode::FORBIDDEN,
            "Only an admin token may decide".into(),
        ));
    }
    // A decision answers a question the loop is asking. Accepting one for a
    // gate nobody is waiting on left an approval in memory that no action
    // matched, and a ledger record of a decision that decided nothing.
    //
    // Check-and-record is one operation in `ApprovalState::decide` (a write
    // lock in memory, one conditional UPDATE on PostgreSQL): a separate check
    // and record let concurrent approve/deny for the same gate both pass the
    // check and both return 200.
    let gate_id = body.gate_id.clone();
    // Not written to the ledger here. This handler has no session key, so its
    // record was unsigned: indistinguishable from one someone with database
    // access appended, and a duplicate of the signed record the loop writes
    // when it consumes this decision (agent.rs), which carries the reason.
    let outcome = state
        .approval_state
        .decide(session_id, body.gate_id, body.approved, body.reason)
        .await
        .map_err(store_unavailable)?;
    match outcome {
        crate::approvals::DecisionOutcome::Recorded => {
            Ok(axum::Json(serde_json::json!({ "ok": true })))
        }
        crate::approvals::DecisionOutcome::NotPending
        | crate::approvals::DecisionOutcome::GateMismatch => Err((
            StatusCode::CONFLICT,
            format!(
                "No pending approval gate '{gate_id}' for this session: it was already \
                 decided, timed out, or never asked"
            ),
        )),
    }
}
