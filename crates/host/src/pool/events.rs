//! The ledger itself: appending and reading events, action progress,
//! snapshots, and the event stream.

use super::{DatabasePool, STREAM_BATCH_SIZE};
use crate::ledger;
use crate::schema::{AppendedEvent, EventPayload, LedgerEventRow};
use crate::signing;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use uuid::Uuid;

impl DatabasePool {
    pub async fn get_latest(&self) -> Result<Option<(i64, String)>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::get_latest(p).await,
            Self::Sqlite(p) => ledger::sqlite::get_latest_sqlite(p).await,
        }
    }

    pub async fn get_events_range(
        &self,
        from_sequence: i64,
        to_sequence: i64,
    ) -> Result<Vec<crate::schema::LedgerEventRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::get_events(p, from_sequence, to_sequence).await,
            Self::Sqlite(p) => {
                ledger::sqlite::get_events_sqlite(p, from_sequence, to_sequence).await
            }
        }
    }

    pub async fn mark_action_executing(&self, event_id: i64) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::mark_action_executing(p, event_id).await,
            Self::Sqlite(p) => ledger::sqlite::mark_action_executing_sqlite(p, event_id).await,
        }
    }

    pub async fn mark_action_completed(&self, event_id: i64) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::mark_action_completed(p, event_id).await,
            Self::Sqlite(p) => ledger::sqlite::mark_action_completed_sqlite(p, event_id).await,
        }
    }

    pub async fn mark_action_failed(
        &self,
        event_id: i64,
        error_msg: &str,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::mark_action_failed(p, event_id, error_msg).await,
            Self::Sqlite(p) => {
                ledger::sqlite::mark_action_failed_sqlite(p, event_id, error_msg).await
            }
        }
    }

    pub async fn get_dangling_actions(&self) -> Result<Vec<i64>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::get_dangling_actions(p).await,
            Self::Sqlite(p) => ledger::sqlite::get_dangling_actions_sqlite(p).await,
        }
    }

    pub async fn find_cached_http_get(&self, url: &str) -> Result<Option<String>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::find_cached_http_get(p, url).await,
            Self::Sqlite(p) => ledger::sqlite::find_cached_http_get_sqlite(p, url).await,
        }
    }

    pub async fn store_enclave_attestation(
        &self,
        session_id: Uuid,
        attestation: &crate::enclave::runtime::EnclaveAttestation,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                ledger::store_enclave_attestation(p, session_id, attestation).await
            }
            Self::Sqlite(p) => {
                ledger::sqlite::store_enclave_attestation_sqlite(p, session_id, attestation).await
            }
        }
    }

    pub async fn get_latest_snapshot(
        &self,
    ) -> Result<Option<crate::schema::SnapshotRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => crate::snapshot::get_latest_snapshot(p).await,
            Self::Sqlite(p) => crate::snapshot::get_latest_snapshot_sqlite(p).await,
        }
    }

    pub async fn snapshot_at_sequence(
        &self,
        sequence: i64,
    ) -> Result<crate::schema::SnapshotRow, crate::snapshot::SnapshotError> {
        match self {
            Self::Postgres(p) => crate::snapshot::snapshot_at_sequence(p, sequence).await,
            Self::Sqlite(p) => crate::snapshot::snapshot_at_sequence_sqlite(p, sequence).await,
        }
    }

    pub async fn append_event(
        &self,
        payload: EventPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key: Option<&SigningKey>,
    ) -> Result<AppendedEvent, ledger::AppendError> {
        match self {
            Self::Postgres(p) => {
                ledger::append_event(p, payload, session_id, session_goal, signing_key).await
            }
            Self::Sqlite(p) => {
                ledger::sqlite::append_event_sqlite(
                    p,
                    &payload,
                    session_id,
                    session_goal,
                    signing_key,
                )
                .await
            }
        }
    }

    pub async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::get_events_by_session(p, session_id).await,
            Self::Sqlite(p) => {
                let rows = sqlx::query_as::<_, (i64, i64, String, String, String, chrono::DateTime<Utc>, Option<String>)>(
                    "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
                     FROM agent_events WHERE session_id = ?1 ORDER BY sequence ASC",
                )
                .bind(session_id.to_string())
                .fetch_all(p)
                .await?;

                let mut events = Vec::with_capacity(rows.len());
                for (id, seq, prev, ch, payload_str, ts, _sid) in rows {
                    let payload: EventPayload = match serde_json::from_str(&payload_str) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("Corrupt event payload at id={}: {}", id, e);
                            EventPayload::Observation {
                                content: format!("[corrupt payload: {e}]"),
                            }
                        }
                    };
                    events.push(LedgerEventRow {
                        id,
                        sequence: seq,
                        previous_hash: prev,
                        content_hash: ch,
                        payload,
                        created_at: ts,
                    });
                }
                Ok(events)
            }
        }
    }

    pub async fn ensure_genesis(&self) -> Result<AppendedEvent, ledger::AppendError> {
        match self {
            Self::Postgres(p) => ledger::ensure_genesis(p).await,
            Self::Sqlite(p) => {
                let latest = ledger::sqlite::get_latest_sqlite(p)
                    .await
                    .map_err(ledger::AppendError::Db)?;
                if latest.is_some() {
                    let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
                        "SELECT id, sequence, previous_hash, content_hash, created_at FROM agent_events WHERE sequence = 0",
                    )
                    .fetch_one(p)
                    .await
                    .map_err(ledger::AppendError::Db)?;
                    return Ok(AppendedEvent {
                        id: row.0,
                        sequence: row.1,
                        previous_hash: row.2,
                        content_hash: row.3,
                        created_at: row.4,
                    });
                }
                ledger::sqlite::append_event_sqlite(
                    p,
                    &EventPayload::Genesis {
                        message: "genesis".to_string(),
                        nonce: Some(hex::encode(uuid::Uuid::new_v4().as_bytes())),
                        session_public_key: None, // server-level genesis: no session signing key yet
                    },
                    None,
                    None,
                    None,
                )
                .await
            }
        }
    }

    pub async fn verify_goal_hash(
        &self,
        session_id: Uuid,
        current_goal: &str,
    ) -> Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::verify_goal_hash(p, session_id, current_goal).await,
            Self::Sqlite(p) => {
                let stored: Option<String> =
                    sqlx::query_scalar("SELECT goal_hash FROM agent_sessions WHERE id = ?1")
                        .bind(session_id.to_string())
                        .fetch_optional(p)
                        .await?;
                match stored {
                    None => Ok(false),
                    Some(h) => Ok(crate::hash::goal_hash_matches(&h, current_goal)),
                }
            }
        }
    }

    // Token queries (RBAC).

    pub async fn stream_events_since(
        &self,
        after_id: i64,
        session_id: Option<Uuid>,
    ) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let rows = if let Some(sid) = session_id {
                    sqlx::query_as::<_, (i64, i64, String, String, sqlx::types::Json<EventPayload>, chrono::DateTime<Utc>)>(
                        "SELECT id, sequence, previous_hash, content_hash, payload, created_at
                         FROM agent_events WHERE id > $1 AND session_id = $2 ORDER BY id ASC LIMIT $3",
                    )
                    .bind(after_id)
                    .bind(sid)
                    .bind(STREAM_BATCH_SIZE as i64)
                    .fetch_all(p)
                    .await?
                } else {
                    sqlx::query_as::<
                        _,
                        (
                            i64,
                            i64,
                            String,
                            String,
                            sqlx::types::Json<EventPayload>,
                            chrono::DateTime<Utc>,
                        ),
                    >(
                        "SELECT id, sequence, previous_hash, content_hash, payload, created_at
                         FROM agent_events WHERE id > $1 ORDER BY id ASC LIMIT $2",
                    )
                    .bind(after_id)
                    .bind(STREAM_BATCH_SIZE as i64)
                    .fetch_all(p)
                    .await?
                };
                Ok(rows
                    .into_iter()
                    .map(|(id, seq, prev, ch, payload, ts)| LedgerEventRow {
                        id,
                        sequence: seq,
                        previous_hash: prev,
                        content_hash: ch,
                        payload: payload.0,
                        created_at: ts,
                    })
                    .collect())
            }
            Self::Sqlite(p) => {
                if let Some(sid) = session_id {
                    let rows = sqlx::query_as::<_, (i64, i64, String, String, String, chrono::DateTime<Utc>, Option<String>)>(
                        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
                         FROM agent_events WHERE id > ?1 AND session_id = ?2 ORDER BY id ASC LIMIT ?3",
                    )
                    .bind(after_id)
                    .bind(sid.to_string())
                    .bind(STREAM_BATCH_SIZE as i64)
                    .fetch_all(p)
                    .await?;

                    let mut events = Vec::with_capacity(rows.len());
                    for (id, seq, prev, ch, payload_str, ts, _sid_opt) in rows {
                        let payload: EventPayload = match serde_json::from_str(&payload_str) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!("Corrupt event payload at id={}: {}", id, e);
                                EventPayload::Observation {
                                    content: format!("[corrupt payload: {e}]"),
                                }
                            }
                        };
                        events.push(LedgerEventRow {
                            id,
                            sequence: seq,
                            previous_hash: prev,
                            content_hash: ch,
                            payload,
                            created_at: ts,
                        });
                    }
                    Ok(events)
                } else {
                    let rows = sqlx::query_as::<_, (i64, i64, String, String, String, chrono::DateTime<Utc>, Option<String>)>(
                        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
                         FROM agent_events WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
                    )
                    .bind(after_id)
                    .bind(STREAM_BATCH_SIZE as i64)
                    .fetch_all(p)
                    .await?;

                    let mut events = Vec::with_capacity(rows.len());
                    for (id, seq, prev, ch, payload_str, ts, _sid_opt) in rows {
                        let payload: EventPayload = match serde_json::from_str(&payload_str) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!("Corrupt event payload at id={}: {}", id, e);
                                EventPayload::Observation {
                                    content: format!("[corrupt payload: {e}]"),
                                }
                            }
                        };
                        events.push(LedgerEventRow {
                            id,
                            sequence: seq,
                            previous_hash: prev,
                            content_hash: ch,
                            payload,
                            created_at: ts,
                        });
                    }
                    Ok(events)
                }
            }
        }
    }

    // Zombie session reaper.

    pub async fn load_session_verifying_key(&self, session_id: Uuid) -> Option<VerifyingKey> {
        match self {
            Self::Postgres(p) => signing::load_session_verifying_key(p, session_id).await,
            Self::Sqlite(p) => {
                let pk_hex: Option<String> = sqlx::query_scalar(
                    "SELECT session_public_key FROM agent_sessions WHERE id = ?1",
                )
                .bind(session_id.to_string())
                .fetch_optional(p)
                .await
                .ok()?;

                let pk_hex = pk_hex?;
                let bytes = hex::decode(&pk_hex).ok()?;
                let arr: [u8; 32] = bytes.try_into().ok()?;
                VerifyingKey::from_bytes(&arr).ok()
            }
        }
    }
}
