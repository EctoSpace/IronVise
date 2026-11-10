//! Sessions: creating, listing and finishing them, and the demo reset.

use super::DatabasePool;
use crate::ledger;
use crate::schema::SessionRow;
use ed25519_dalek::SigningKey;
use uuid::Uuid;

impl DatabasePool {
    /// Fetch one session by its primary key, independently of listing pagination.
    pub async fn get_session(&self, session_id: Uuid) -> Result<Option<SessionRow>, sqlx::Error> {
        match self {
            Self::Postgres(pool) => {
                sqlx::query_as::<_, SessionRow>(
                    "SELECT id, goal, goal_hash, status, llm_backend, llm_model, created_at,
                        finished_at, policy_hash, session_public_key, session_did,
                        enclave_attestation_json FROM agent_sessions WHERE id = $1",
                )
                .bind(session_id)
                .fetch_optional(pool)
                .await
            }
            Self::Sqlite(pool) => ledger::sqlite::get_session_sqlite(pool, session_id).await,
        }
    }

    pub async fn get_session_policy_hash(
        &self,
        session_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, Option<String>>(
                "SELECT policy_hash FROM agent_sessions WHERE id = $1",
            )
            .bind(session_id)
            .fetch_optional(p)
            .await
            .map(|row| row.flatten()),
            Self::Sqlite(p) => ledger::sqlite::get_session_policy_hash_sqlite(p, session_id).await,
        }
    }

    /// The goal and lifecycle status of one session, or `None` if it does not
    /// exist.
    ///
    /// A targeted lookup rather than a page of `list_sessions_filtered`: the
    /// SDK's verify-intent endpoint needs to tell "no such session" from "a
    /// session that is no longer accepting work", and a 500-row scan answers
    /// neither question reliably.
    pub async fn session_goal_and_status(
        &self,
        session_id: Uuid,
    ) -> Result<Option<(String, String)>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                sqlx::query_as::<_, (String, String)>(
                    "SELECT goal, status FROM agent_sessions WHERE id = $1",
                )
                .bind(session_id)
                .fetch_optional(p)
                .await
            }
            Self::Sqlite(p) => {
                sqlx::query_as::<_, (String, String)>(
                    "SELECT goal, status FROM agent_sessions WHERE id = ?1",
                )
                .bind(session_id.to_string())
                .fetch_optional(p)
                .await
            }
        }
    }

    pub async fn list_running_session_ids(&self) -> Result<Vec<Uuid>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                sqlx::query_scalar("SELECT id FROM agent_sessions WHERE status = 'running'")
                    .fetch_all(p)
                    .await
            }
            Self::Sqlite(p) => {
                let ids: Vec<String> =
                    sqlx::query_scalar("SELECT id FROM agent_sessions WHERE status = 'running'")
                        .fetch_all(p)
                        .await?;
                ids.into_iter()
                    .map(|s| {
                        s.parse::<Uuid>().map_err(|e| {
                            sqlx::Error::Decode(Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("invalid UUID in agent_sessions.id '{s}': {e}"),
                            )))
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn create_session(
        &self,
        goal: &str,
        llm_backend: &str,
        llm_model: &str,
        policy_hash: Option<&str>,
    ) -> Result<(SessionRow, SigningKey), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                ledger::create_session(p, goal, llm_backend, llm_model, policy_hash).await
            }
            Self::Sqlite(p) => {
                ledger::sqlite::create_session_sqlite(
                    p,
                    goal,
                    llm_backend,
                    llm_model,
                    policy_hash,
                    None,
                )
                .await
            }
        }
    }

    pub async fn create_session_with_did(
        &self,
        goal: &str,
        llm_backend: &str,
        llm_model: &str,
        policy_hash: Option<&str>,
        session_did: Option<&str>,
    ) -> Result<(SessionRow, SigningKey), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                ledger::create_session_with_did(
                    p,
                    goal,
                    llm_backend,
                    llm_model,
                    policy_hash,
                    session_did,
                )
                .await
            }
            Self::Sqlite(p) => {
                ledger::sqlite::create_session_sqlite(
                    p,
                    goal,
                    llm_backend,
                    llm_model,
                    policy_hash,
                    session_did,
                )
                .await
            }
        }
    }

    pub async fn finish_session(&self, session_id: Uuid, status: &str) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::finish_session(p, session_id, status).await,
            // Delegate rather than repeat the UPDATE: a second copy here would
            // miss what finish_session_sqlite records on sealing
            // (sealed_tip_hash, sealed_event_count; F-2).
            Self::Sqlite(p) => ledger::sqlite::finish_session_sqlite(p, session_id, status).await,
        }
    }

    /// Finish a session only while it is still `running`.
    ///
    /// The background cognitive loop must use this. `POST /sessions` always
    /// spawns that loop, and it outlives the request: whatever status it
    /// writes when it ends lands after any `POST /sessions/:id/seal` that
    /// arrived in the meantime, so an unconditional write silently un-seals
    /// the session. An explicit seal still calls [`Self::finish_session`],
    /// which writes whatever it is told - that is the endpoint's job.
    pub async fn finish_session_if_running(
        &self,
        session_id: Uuid,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::finish_session_if_running(p, session_id, status).await,
            Self::Sqlite(p) => {
                ledger::sqlite::finish_session_sqlite_if_running(p, session_id, status).await
            }
        }
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::list_sessions(p).await,
            Self::Sqlite(p) => ledger::sqlite::list_sessions_page_sqlite(p, None, -1, 0).await,
        }
    }

    pub async fn list_sessions_filtered(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SessionRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::list_sessions_filtered(p, status, limit, offset).await,
            Self::Sqlite(p) => {
                ledger::sqlite::list_sessions_page_sqlite(p, status, limit, offset).await
            }
        }
    }

    pub async fn reap_zombie_sessions(&self, max_age_minutes: i64) -> Result<u64, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let result = sqlx::query(
                    "UPDATE agent_sessions SET status = 'failed', finished_at = now()
                     WHERE status = 'running' AND created_at < now() - (interval '1 minute' * $1)",
                )
                .bind(max_age_minutes)
                .execute(p)
                .await?;
                Ok(result.rows_affected())
            }
            Self::Sqlite(p) => {
                let result = sqlx::query(
                    // julianday, not text: created_at is stored as an RFC 3339
                    // `…T…` string (sqlx's chrono encoding) but datetime('now')
                    // renders `… …` with a space, so a text comparison between
                    // the two is not reliable (same root cause as the
                    // api_tokens.expires_at comparison above).
                    "UPDATE agent_sessions SET status = 'failed', finished_at = datetime('now')
                     WHERE status = 'running' AND julianday(created_at) < julianday('now', ?1)",
                )
                .bind(format!("-{max_age_minutes} minutes"))
                .execute(p)
                .await?;
                Ok(result.rows_affected())
            }
        }
    }

    /// Delete **all** agent sessions, events, snapshots, and action-log rows.
    ///
    /// This is intended exclusively for the demo-mode "Reset Test Database"
    /// button - call-sites MUST gate on `config::is_demo_mode()`.
    pub async fn reset_demo_data(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let mut tx = p.begin().await?;
                // The agent_events table has an immutable trigger that blocks
                // DELETE.  Temporarily disable it so the demo reset can clear
                // the ledger, then re-enable it immediately afterwards.
                sqlx::query("ALTER TABLE agent_events DISABLE TRIGGER agent_events_immutable")
                    .execute(&mut *tx)
                    .await?;
                // Order matters: FK-safe (signatures → events → sessions).
                sqlx::query("DELETE FROM agent_action_log")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM agent_event_signatures")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM agent_events")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM agent_snapshots")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM agent_sessions")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("ALTER TABLE agent_events ENABLE TRIGGER agent_events_immutable")
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await
            }
            Self::Sqlite(p) => {
                let mut tx = p.begin().await?;
                // SQLite: drop immutability triggers, delete, then recreate.
                sqlx::query("DROP TRIGGER IF EXISTS agent_events_no_update")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DROP TRIGGER IF EXISTS agent_events_no_delete")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DROP TRIGGER IF EXISTS agent_event_signatures_no_update")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DROP TRIGGER IF EXISTS agent_event_signatures_no_delete")
                    .execute(&mut *tx)
                    .await?;

                sqlx::query("DELETE FROM agent_action_log")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM agent_event_signatures")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM agent_events")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM agent_snapshots")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM agent_sessions")
                    .execute(&mut *tx)
                    .await?;

                // Recreate immutability triggers.
                sqlx::query(
                    "CREATE TRIGGER IF NOT EXISTS agent_events_no_update \
                     BEFORE UPDATE ON agent_events FOR EACH ROW BEGIN \
                     SELECT RAISE(ABORT, 'agent_events is append-only; UPDATE is not allowed.'); END"
                ).execute(&mut *tx).await?;
                sqlx::query(
                    "CREATE TRIGGER IF NOT EXISTS agent_events_no_delete \
                     BEFORE DELETE ON agent_events FOR EACH ROW BEGIN \
                     SELECT RAISE(ABORT, 'agent_events is append-only; DELETE is not allowed.'); END"
                ).execute(&mut *tx).await?;
                sqlx::query(
                    "CREATE TRIGGER IF NOT EXISTS agent_event_signatures_no_update \
                     BEFORE UPDATE ON agent_event_signatures FOR EACH ROW BEGIN \
                     SELECT RAISE(ABORT, 'agent_event_signatures is append-only; UPDATE is not allowed.'); END"
                ).execute(&mut *tx).await?;
                sqlx::query(
                    "CREATE TRIGGER IF NOT EXISTS agent_event_signatures_no_delete \
                     BEFORE DELETE ON agent_event_signatures FOR EACH ROW BEGIN \
                     SELECT RAISE(ABORT, 'agent_event_signatures is append-only; DELETE is not allowed.'); END"
                ).execute(&mut *tx).await?;
                tx.commit().await
            }
        }
    }

    // Signing key lookup.
}
