//! Adapter from storage operations to the shared ledger API.

use super::*;
use async_trait::async_trait;

#[async_trait]
impl ledger_api::LedgerBackend for PostgresLedger {
    async fn append_event(
        &self,
        payload: ledger_api::RawPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key_bytes: Option<&[u8]>,
    ) -> Result<ledger_api::AppendResult, ledger_api::LedgerError> {
        let typed_payload: EventPayload = serde_json::from_value(payload)
            .map_err(|e| ledger_api::LedgerError::Serialize(e.to_string()))?;
        let sk = match signing_key_bytes {
            Some(b) => {
                let arr: &[u8; 32] = b.try_into().map_err(|_| {
                    ledger_api::LedgerError::Serialize(
                        "signing key must be exactly 32 bytes".to_string(),
                    )
                })?;
                Some(ed25519_dalek::SigningKey::from_bytes(arr))
            }
            None => None,
        };
        let res = append_event(
            &self.0,
            typed_payload,
            session_id,
            session_goal,
            sk.as_ref(),
        )
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
        let (row, sk) = create_session_with_did(
            &self.0,
            &params.goal,
            &params.llm_backend,
            &params.llm_model,
            params.policy_hash.as_deref(),
            params.session_did.as_deref(),
        )
        .await
        .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        let session = ledger_api::Session {
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
            session_did: params.session_did,
        };
        Ok((session, sk.to_bytes().to_vec()))
    }

    async fn seal_session(
        &self,
        session_id: Uuid,
        status: &str,
    ) -> Result<(), ledger_api::LedgerError> {
        finish_session(&self.0, session_id, status)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))
    }

    async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ledger_api::LedgerEvent>, ledger_api::LedgerError> {
        let rows = get_events_by_session(&self.0, session_id)
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
        let rows = list_sessions(&self.0)
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
                session_did: None,
            })
            .collect())
    }

    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, ledger_api::LedgerError> {
        verify_chain(&self.0, from, to)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))
    }

    async fn prove_compliance(&self, session_id: Uuid) -> Result<Vec<u8>, ledger_api::LedgerError> {
        // Phase 1: return a JSON-serialised summary of all events in the session.
        let events = get_events_by_session(&self.0, session_id)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
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
