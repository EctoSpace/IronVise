//! Human-in-the-loop approval gates: the request a loop is waiting on, and
//! the decision an operator posts for it.
//!
//! On PostgreSQL the `pending_approvals` table holds both, so a gate opened
//! by a loop on one instance can be decided through any other. On SQLite,
//! which one instance serves, they are held in memory. Either way the async
//! methods below are the interface; the store behind them is chosen once,
//! from the ledger's pool ([`ApprovalState::for_pool`]).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

type DecisionMap = HashMap<(Uuid, String), (bool, Option<String>)>;

/// Result of [`ApprovalState::try_record_decision`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionOutcome {
    /// The decision matched the pending gate and was recorded.
    Recorded,
    /// Nothing is pending for this session: already decided, timed out, or
    /// never asked.
    NotPending,
    /// Something else is pending for this session, not the named gate.
    GateMismatch,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingApproval {
    pub gate_id: String,
    pub action_name: String,
    pub action_params_summary: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub gate_id: String,
    pub approved: bool,
    pub reason: Option<String>,
}

pub struct ApprovalState {
    pending: RwLock<HashMap<Uuid, PendingApproval>>,
    decisions: RwLock<DecisionMap>,
    /// Set on PostgreSQL: the shared store, used instead of the maps.
    shared: Option<sqlx::PgPool>,
}

impl ApprovalState {
    /// Held in this process's memory.
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            decisions: RwLock::new(HashMap::new()),
            shared: None,
        }
    }

    /// Held in PostgreSQL, shared by every instance on that database.
    pub fn shared(pool: sqlx::PgPool) -> Self {
        Self {
            shared: Some(pool),
            ..Self::new()
        }
    }

    /// Shared on PostgreSQL, in memory on SQLite.
    pub fn for_pool(pool: &crate::pool::DatabasePool) -> Self {
        match pool.as_pg() {
            Some(pg) => Self::shared(pg.clone()),
            None => Self::new(),
        }
    }

    /// Publishes the request a loop now waits on.
    pub async fn publish(
        &self,
        session_id: Uuid,
        approval: PendingApproval,
    ) -> Result<(), sqlx::Error> {
        match &self.shared {
            Some(pool) => db_set_pending(pool, session_id, &approval).await,
            None => {
                self.set_pending(session_id, approval);
                Ok(())
            }
        }
    }

    /// The request a session's loop is waiting on, if any.
    pub async fn pending(&self, session_id: Uuid) -> Result<Option<PendingApproval>, sqlx::Error> {
        match &self.shared {
            Some(pool) => db_get_pending(pool, session_id).await,
            None => Ok(self.get_pending(session_id)),
        }
    }

    /// Records an operator's decision, only for the gate that is pending.
    pub async fn decide(
        &self,
        session_id: Uuid,
        gate_id: String,
        approved: bool,
        reason: Option<String>,
    ) -> Result<DecisionOutcome, sqlx::Error> {
        match &self.shared {
            Some(pool) => db_decide(pool, session_id, &gate_id, approved, reason.as_deref()).await,
            None => Ok(self.try_record_decision(session_id, gate_id, approved, reason)),
        }
    }

    /// The decision for a gate, consumed, once one has been posted.
    pub async fn take(
        &self,
        session_id: Uuid,
        gate_id: &str,
    ) -> Result<Option<(bool, Option<String>)>, sqlx::Error> {
        match &self.shared {
            Some(pool) => db_take_decision(pool, session_id, gate_id).await,
            None => Ok(self.take_decision(session_id, gate_id)),
        }
    }

    /// Withdraws a gate at its timeout; a decision that arrived first stands.
    pub async fn withdraw(
        &self,
        session_id: Uuid,
        gate_id: &str,
    ) -> Result<Option<(bool, Option<String>)>, sqlx::Error> {
        match &self.shared {
            Some(pool) => db_withdraw(pool, session_id, gate_id).await,
            None => Ok(self.expire(session_id, gate_id)),
        }
    }

    /// Forgets everything about a session that has ended.
    pub async fn forget(&self, session_id: Uuid) -> Result<(), sqlx::Error> {
        match &self.shared {
            Some(pool) => db_cleanup_session(pool, session_id).await,
            None => {
                self.cleanup_session(session_id);
                Ok(())
            }
        }
    }

    pub fn set_pending(&self, session_id: Uuid, approval: PendingApproval) {
        self.pending
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session_id, approval);
    }

    pub fn get_pending(&self, session_id: Uuid) -> Option<PendingApproval> {
        self.pending
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session_id)
            .cloned()
    }

    pub fn record_decision(
        &self,
        session_id: Uuid,
        gate_id: String,
        approved: bool,
        reason: Option<String>,
    ) {
        self.decisions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert((session_id, gate_id), (approved, reason));
        self.pending
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
    }

    /// Check-and-record as a single write-lock hold, so two racing decisions
    /// for the same gate cannot both observe it pending: whichever acquires
    /// the `pending` write lock first removes the entry, and the loser sees
    /// it already gone. Used by the REST handler, which (unlike
    /// `record_decision`) must reject a decision for a gate nobody is
    /// waiting on instead of recording it unconditionally.
    pub fn try_record_decision(
        &self,
        session_id: Uuid,
        gate_id: String,
        approved: bool,
        reason: Option<String>,
    ) -> DecisionOutcome {
        let mut pending = self.pending.write().unwrap_or_else(|e| e.into_inner());
        match pending.get(&session_id) {
            Some(p) if p.gate_id == gate_id => {
                // Stored before `pending` is released, so `expire` sees the
                // gate either still pending or already decided, never neither.
                self.decisions
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert((session_id, gate_id), (approved, reason));
                pending.remove(&session_id);
                DecisionOutcome::Recorded
            }
            Some(_) => DecisionOutcome::GateMismatch,
            None => DecisionOutcome::NotPending,
        }
    }

    pub fn take_decision(&self, session_id: Uuid, gate_id: &str) -> Option<(bool, Option<String>)> {
        self.decisions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(session_id, gate_id.to_string()))
    }

    /// Withdraws the request for a gate that timed out, so a decision posted
    /// later is refused (`NotPending`) instead of accepted for nobody. A
    /// decision that arrived first is returned, and stands.
    pub fn expire(&self, session_id: Uuid, gate_id: &str) -> Option<(bool, Option<String>)> {
        let mut pending = self.pending.write().unwrap_or_else(|e| e.into_inner());
        if pending
            .get(&session_id)
            .is_some_and(|p| p.gate_id == gate_id)
        {
            pending.remove(&session_id);
        }
        self.decisions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(session_id, gate_id.to_string()))
    }

    /// Remove all pending approvals and decisions for a given session.
    /// Must be called when a session completes, aborts, or fails to prevent
    /// unbounded growth of the in-memory maps.
    pub fn cleanup_session(&self, session_id: Uuid) {
        self.pending
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
        self.decisions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(sid, _), _| *sid != session_id);
    }
}

impl Default for ApprovalState {
    fn default() -> Self {
        Self::new()
    }
}

// The PostgreSQL store. Each decision is a single conditional statement, so
// two instances racing on one gate cannot both record it, and a timeout and
// a decision cannot both win.

async fn db_set_pending(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    approval: &PendingApproval,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO pending_approvals (session_id, gate_id, action_name, action_params_summary, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (session_id, gate_id) DO UPDATE
            SET action_name = EXCLUDED.action_name,
                action_params_summary = EXCLUDED.action_params_summary,
                approved = NULL,
                reason = NULL,
                decided_at = NULL",
    )
    .bind(session_id)
    .bind(&approval.gate_id)
    .bind(&approval.action_name)
    .bind(&approval.action_params_summary)
    .bind(approval.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

async fn db_get_pending(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> Result<Option<PendingApproval>, sqlx::Error> {
    let row: Option<(String, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT gate_id, action_name, action_params_summary, created_at
         FROM pending_approvals
         WHERE session_id = $1 AND approved IS NULL
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(
        |(gate_id, action_name, action_params_summary, created_at)| PendingApproval {
            gate_id,
            action_name,
            action_params_summary,
            created_at,
        },
    ))
}

async fn db_decide(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    gate_id: &str,
    approved: bool,
    reason: Option<&str>,
) -> Result<DecisionOutcome, sqlx::Error> {
    let recorded = sqlx::query(
        "UPDATE pending_approvals
         SET approved = $1, reason = $2, decided_at = NOW()
         WHERE session_id = $3 AND gate_id = $4 AND approved IS NULL",
    )
    .bind(approved)
    .bind(reason)
    .bind(session_id)
    .bind(gate_id)
    .execute(pool)
    .await?
    .rows_affected()
        > 0;
    if recorded {
        return Ok(DecisionOutcome::Recorded);
    }
    Ok(match db_get_pending(pool, session_id).await? {
        Some(_) => DecisionOutcome::GateMismatch,
        None => DecisionOutcome::NotPending,
    })
}

async fn db_take_decision(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    gate_id: &str,
) -> Result<Option<(bool, Option<String>)>, sqlx::Error> {
    let row: Option<(bool, Option<String>)> = sqlx::query_as(
        "WITH taken AS (
             DELETE FROM pending_approvals
             WHERE session_id = $1 AND gate_id = $2 AND approved IS NOT NULL
             RETURNING approved, reason
         )
         SELECT approved, reason FROM taken LIMIT 1",
    )
    .bind(session_id)
    .bind(gate_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

async fn db_withdraw(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    gate_id: &str,
) -> Result<Option<(bool, Option<String>)>, sqlx::Error> {
    let row: Option<(Option<bool>, Option<String>)> = sqlx::query_as(
        "DELETE FROM pending_approvals WHERE session_id = $1 AND gate_id = $2
         RETURNING approved, reason",
    )
    .bind(session_id)
    .bind(gate_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(approved, reason)| approved.map(|a| (a, reason))))
}

async fn db_cleanup_session(pool: &sqlx::PgPool, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM pending_approvals WHERE session_id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod pending_tests;
