//! Adapter from storage operations to the shared ledger API.

use super::*;
use async_trait::async_trait;

#[async_trait]
impl ledger_api::LedgerBackend for SqliteLedger {
    async fn append_event(
        &self,
        payload: ledger_api::RawPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key_bytes: Option<&[u8]>,
    ) -> Result<ledger_api::AppendResult, ledger_api::LedgerError> {
        // Goal-hash verification: reject events whose goal doesn't match the
        // session's stored goal hash, matching the Postgres backend's behaviour.
        if let (Some(sid), Some(goal)) = (session_id, session_goal) {
            let stored: Option<(String,)> =
                sqlx::query_as("SELECT goal_hash FROM agent_sessions WHERE id = ?1")
                    .bind(sid.to_string())
                    .fetch_optional(&self.0)
                    .await
                    .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
            match stored {
                Some((h,)) if crate::hash::goal_hash_matches(&h, goal) => {}
                _ => return Err(ledger_api::LedgerError::GoalMismatch),
            }
        }

        let typed: EventPayload = serde_json::from_value(payload)
            .map_err(|e| ledger_api::LedgerError::Serialize(e.to_string()))?;
        let sk = match signing_key_bytes {
            Some(b) => {
                let arr: [u8; 32] = b.try_into().map_err(|_| {
                    ledger_api::LedgerError::Serialize(
                        "signing key must be exactly 32 bytes".to_string(),
                    )
                })?;
                Some(ed25519_dalek::SigningKey::from_bytes(&arr))
            }
            None => None,
        };
        let res = append_event_sqlite(&self.0, &typed, session_id, session_goal, sk.as_ref())
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        Ok(ledger_api::AppendResult {
            id: res.id,
            sequence: res.sequence,
            previous_hash: res.previous_hash,
            content_hash: res.content_hash,
            created_at: res.created_at,
        })
    }

    async fn create_session(
        &self,
        params: ledger_api::NewSession,
    ) -> Result<(ledger_api::Session, Vec<u8>), ledger_api::LedgerError> {
        let (row, sk) = create_session_sqlite(
            &self.0,
            &params.goal,
            &params.llm_backend,
            &params.llm_model,
            params.policy_hash.as_deref(),
            params.session_did.as_deref(),
        )
        .await
        .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        let s = ledger_api::Session {
            id: row.id,
            goal: row.goal,
            goal_hash: row.goal_hash,
            status: row.status,
            llm_backend: row.llm_backend,
            llm_model: row.llm_model,
            created_at: row.created_at,
            finished_at: row.finished_at,
            policy_hash: row.policy_hash,
            session_public_key: row.session_public_key,
            session_did: row.session_did,
        };
        Ok((s, sk.to_bytes().to_vec()))
    }

    async fn seal_session(
        &self,
        session_id: Uuid,
        status: &str,
    ) -> Result<(), ledger_api::LedgerError> {
        finish_session_sqlite(&self.0, session_id, status)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))
    }

    async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ledger_api::LedgerEvent>, ledger_api::LedgerError> {
        // Delegate to the free function to avoid duplicating the query.
        let rows = get_events_by_session_sqlite(&self.0, session_id)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                let payload = serde_json::to_value(&r.payload)
                    .map_err(|e| ledger_api::LedgerError::Serialize(e.to_string()))?;
                Ok(ledger_api::LedgerEvent {
                    id: r.id,
                    sequence: r.sequence,
                    previous_hash: r.previous_hash,
                    content_hash: r.content_hash,
                    payload,
                    created_at: r.created_at,
                })
            })
            .collect()
    }

    async fn list_sessions(&self) -> Result<Vec<ledger_api::Session>, ledger_api::LedgerError> {
        // Delegate to the free function to avoid duplicating query + UUID parsing.
        let rows = list_sessions_sqlite(&self.0)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| ledger_api::Session {
                id: r.id,
                goal: r.goal,
                goal_hash: r.goal_hash,
                status: r.status,
                llm_backend: r.llm_backend,
                llm_model: r.llm_model,
                created_at: r.created_at,
                finished_at: r.finished_at,
                policy_hash: r.policy_hash,
                session_public_key: r.session_public_key,
                session_did: r.session_did,
            })
            .collect())
    }

    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, ledger_api::LedgerError> {
        verify_chain_sqlite(&self.0, from, to)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))
    }

    async fn prove_compliance(&self, session_id: Uuid) -> Result<Vec<u8>, ledger_api::LedgerError> {
        let events = self.get_events_by_session(session_id).await?;
        let bundle = serde_json::json!({
            "session_id": session_id,
            "event_count": events.len(),
            "events": events.iter().map(|e| serde_json::json!({
                "sequence": e.sequence,
                "content_hash": e.content_hash,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_vec(&bundle).map_err(|e| ledger_api::LedgerError::Serialize(e.to_string()))
    }
}

// Tests
