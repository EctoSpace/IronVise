//! Chain verification and compliance proofs for one session.

use super::DatabasePool;
use crate::ledger;
use uuid::Uuid;

impl DatabasePool {
    // Chain verification & compliance (inherent wrappers): these provide
    // direct access without importing the LedgerBackend trait.

    /// Verify hash-chain integrity for all events in a session.
    pub async fn verify_chain_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let events = self.get_events_by_session(session_id).await?;
        if events.is_empty() {
            return Ok(true);
        }
        let from = events.first().unwrap().sequence;
        let to = events.last().unwrap().sequence;
        match self {
            Self::Postgres(p) => ledger::verify_chain(p, from, to)
                .await
                .map_err(|e| Box::new(e) as _),
            Self::Sqlite(p) => ledger::sqlite::verify_chain_sqlite(p, from, to)
                .await
                .map_err(|e| Box::new(e) as _),
        }
    }

    /// Signature verification for one session, on either backend: payloads
    /// hash-checked, signatures bound to events, unsigned events accounted for.
    pub async fn verify_session_detailed(
        &self,
        session_id: Uuid,
    ) -> Result<ledger::SessionVerdict, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::postgres::verify_session_detailed(p, session_id).await,
            Self::Sqlite(p) => ledger::sqlite::verify_session_detailed_sqlite(p, session_id).await,
        }
    }

    /// Generate a JSON compliance proof bundle for a session.
    pub async fn prove_compliance_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let events = self.get_events_by_session(session_id).await?;
        Ok(serde_json::json!({
            "session_id": session_id,
            "event_count": events.len(),
            "events": events.iter().map(|e| serde_json::json!({
                "sequence": e.sequence,
                "content_hash": e.content_hash,
            })).collect::<Vec<_>>(),
        }))
    }
}
