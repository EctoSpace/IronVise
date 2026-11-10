//! `DatabasePool` as the `ledger_api` traits, for callers that hold an
//! `Arc<dyn LedgerBackend>`.

//!
//! The trait surface lets test doubles, and later other storage, stand in for
//! the enum the server uses.

use super::DatabasePool;
use crate::ledger;
use crate::schema::{EventPayload, SessionRow};
use async_trait::async_trait;
use ledger_api::{LedgerAdmin, LedgerBackend, LedgerError};
use uuid::Uuid;

#[async_trait]
impl LedgerBackend for DatabasePool {
    async fn append_event(
        &self,
        payload: ledger_api::RawPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key_bytes: Option<&[u8]>,
    ) -> Result<ledger_api::AppendResult, LedgerError> {
        let typed_payload: EventPayload =
            serde_json::from_value(payload).map_err(|e| LedgerError::Serialize(e.to_string()))?;
        let sk = match signing_key_bytes {
            Some(b) => {
                let arr: &[u8; 32] = b.try_into().map_err(|_| {
                    LedgerError::Serialize("signing key must be exactly 32 bytes".to_string())
                })?;
                Some(ed25519_dalek::SigningKey::from_bytes(arr))
            }
            None => None,
        };
        let res = self
            .append_event(typed_payload, session_id, session_goal, sk.as_ref())
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
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
    ) -> Result<(ledger_api::Session, Vec<u8>), LedgerError> {
        let (row, sk) = self
            .create_session_with_did(
                &params.goal,
                &params.llm_backend,
                &params.llm_model,
                params.policy_hash.as_deref(),
                params.session_did.as_deref(),
            )
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
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
            session_did: row.session_did,
        };
        Ok((session, sk.to_bytes().to_vec()))
    }

    async fn seal_session(&self, session_id: Uuid, status: &str) -> Result<(), LedgerError> {
        self.finish_session(session_id, status)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))
    }

    async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ledger_api::LedgerEvent>, LedgerError> {
        let rows = DatabasePool::get_events_by_session(self, session_id)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        rows.into_iter()
            .map(|r| {
                let payload = serde_json::to_value(&r.payload)
                    .map_err(|e| LedgerError::Serialize(e.to_string()))?;
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

    async fn list_sessions(&self) -> Result<Vec<ledger_api::Session>, LedgerError> {
        let rows = DatabasePool::list_sessions(self)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(session_row_to_api).collect())
    }

    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, LedgerError> {
        match self {
            Self::Postgres(p) => ledger::verify_chain(p, from, to)
                .await
                .map_err(|e| LedgerError::Database(e.to_string())),
            Self::Sqlite(p) => ledger::sqlite::verify_chain_sqlite(p, from, to)
                .await
                .map_err(|e| LedgerError::Database(e.to_string())),
        }
    }

    async fn prove_compliance(&self, session_id: Uuid) -> Result<Vec<u8>, LedgerError> {
        let events = DatabasePool::get_events_by_session(self, session_id)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        let bundle = serde_json::json!({
            "session_id": session_id,
            "event_count": events.len(),
            "events": events.iter().map(|e| serde_json::json!({
                "sequence": e.sequence,
                "content_hash": e.content_hash,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_vec(&bundle).map_err(|e| LedgerError::Serialize(e.to_string()))
    }
}

#[async_trait]
impl LedgerAdmin for DatabasePool {
    async fn get_latest(&self) -> Result<Option<(i64, String)>, LedgerError> {
        DatabasePool::get_latest(self)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))
    }

    async fn ensure_genesis(&self) -> Result<ledger_api::AppendResult, LedgerError> {
        let res = DatabasePool::ensure_genesis(self)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        Ok(ledger_api::AppendResult {
            id: res.id,
            sequence: res.sequence,
            previous_hash: res.previous_hash,
            content_hash: res.content_hash,
            created_at: res.created_at,
        })
    }

    async fn stream_events_since(
        &self,
        after_id: i64,
        session_id: Option<Uuid>,
    ) -> Result<Vec<ledger_api::LedgerEvent>, LedgerError> {
        let rows = DatabasePool::stream_events_since(self, after_id, session_id)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        rows.into_iter()
            .map(|r| {
                let payload = serde_json::to_value(&r.payload)
                    .map_err(|e| LedgerError::Serialize(e.to_string()))?;
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

    async fn reap_zombie_sessions(&self, max_age_minutes: i64) -> Result<u64, LedgerError> {
        DatabasePool::reap_zombie_sessions(self, max_age_minutes)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))
    }

    async fn list_sessions_filtered(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ledger_api::Session>, LedgerError> {
        let rows = DatabasePool::list_sessions_filtered(self, status, limit, offset)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(session_row_to_api).collect())
    }
}

/// Convert a host `SessionRow` to an API `Session`.
fn session_row_to_api(r: SessionRow) -> ledger_api::Session {
    ledger_api::Session {
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
    }
}
