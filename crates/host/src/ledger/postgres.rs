//! PostgreSQL implementation of `ledger_api::LedgerBackend`.
//!
//! This file contains the original IronVise logic, now exposed both as
//! free functions (keeping existing call-sites working) and as a concrete
//! `PostgresLedger` struct that implements `LedgerBackend`.

use crate::hash::GENESIS_PREVIOUS_HASH;
use crate::schema::{
    AppendedEvent, AuditFinding, EventPayload, FindingSeverity, LedgerEventRow, SessionRow,
};
use crate::signing;
mod adapter;
use chrono::{Timelike as _, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Derives a `did:key:z6Mk…` URI from an Ed25519 verifying key following the
/// W3C DID-key specification (multicodec prefix `0xed01` + base58btc encoding).
///
/// <https://w3c-ccg.github.io/did-method-key/#ed25519-x25519>
fn derive_did_key(verifying_key: &VerifyingKey) -> String {
    // Ed25519 multicodec varint prefix (little-endian): 0xed, 0x01
    let mut encoded = vec![0xed_u8, 0x01_u8];
    encoded.extend_from_slice(verifying_key.as_bytes());
    // `z` is the multibase prefix for base58btc.
    format!("did:key:z{}", bs58::encode(&encoded).into_string())
}

#[derive(FromRow)]
pub(super) struct AgentEventDbRow {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub payload: sqlx::types::Json<EventPayload>,
    pub created_at: chrono::DateTime<Utc>,
    pub session_id: Option<Uuid>,
}

pub(super) fn db_row_to_ledger_event(row: AgentEventDbRow) -> LedgerEventRow {
    LedgerEventRow {
        id: row.id,
        sequence: row.sequence,
        previous_hash: row.previous_hash,
        content_hash: row.content_hash,
        payload: row.payload.0,
        created_at: row.created_at,
    }
}

// Free functions, kept for backward-compat with existing call sites.

pub async fn get_latest(pool: &PgPool) -> Result<Option<(i64, String)>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Does this event's stored payload hash to its stored `content_hash`?
///
/// Extracted so `verify_chain` and `verify_session_detailed` cannot drift
/// apart. Both need the same answer, and the nanosecond fallback below is
/// exactly the sort of hard-won detail that gets reimplemented wrong.
pub(super) fn event_hash_is_consistent(row: &AgentEventDbRow) -> bool {
    let Ok(payload_json) = serde_json::to_string(&row.payload.0) else {
        return false;
    };
    let sid_str = row.session_id.map(|u| u.to_string());
    let ts_str = row.created_at.to_rfc3339();
    // Verify against the canonical v2 scheme first, falling back through
    // the pre-migration v1 layouts (shared multi-scheme verifier in
    // ectoledger_core::hash; constant-time comparisons throughout).
    if crate::hash::verify_content_hash_any_scheme(
        &row.previous_hash,
        row.sequence,
        &payload_json,
        sid_str.as_deref(),
        Some(&ts_str),
        &row.content_hash,
    )
    .is_some()
    {
        return true;
    }

    // Last resort: sub-microsecond nanosecond precision mismatch, for events
    // written while `append_event` called `Utc::now().to_rfc3339()` directly.
    // That call may produce 9 decimal places (e.g. "...970769388+00:00") when
    // the system clock's nanosecond value has a non-zero sub-microsecond
    // component.  PostgreSQL `TIMESTAMPTZ` truncates to microseconds (6
    // decimal places), so reading `created_at` back from the DB and calling
    // `to_rfc3339()` produces "...970769+00:00" - a different string -
    // causing a hash mismatch for exactly those events.  We brute-force the
    // 999 possible sub-microsecond nanosecond offsets (1-999 ns) to recover
    // them.
    let base_ns = row.created_at.nanosecond();
    (1u32..=999).any(|sub_ns| {
        let candidate_ns = base_ns + sub_ns;
        // base_ns is a multiple of 1000 (microseconds from PG),
        // so candidate_ns <= 999_999_999 - always valid.
        let Some(candidate_dt) = row.created_at.with_nanosecond(candidate_ns) else {
            return false;
        };
        let candidate_ts = candidate_dt.to_rfc3339();
        crate::hash::verify_content_hash_any_scheme(
            &row.previous_hash,
            row.sequence,
            &payload_json,
            sid_str.as_deref(),
            Some(&candidate_ts),
            &row.content_hash,
        )
        .is_some()
    })
}

pub async fn verify_chain(
    pool: &PgPool,
    from_sequence: i64,
    to_sequence: i64,
) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events
         WHERE sequence >= $1 AND sequence <= $2
         ORDER BY sequence ASC",
    )
    .bind(from_sequence)
    .bind(to_sequence)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(true);
    }

    let mut prev_content_hash: Option<String> = None;
    for row in rows {
        let expected_prev = prev_content_hash
            .as_deref()
            .unwrap_or(GENESIS_PREVIOUS_HASH);
        if row.previous_hash != expected_prev {
            return Ok(false);
        }
        if !event_hash_is_consistent(&row) {
            return Ok(false);
        }
        prev_content_hash = Some(row.content_hash);
    }
    Ok(true)
}

pub async fn create_session(
    pool: &PgPool,
    goal: &str,
    llm_backend: &str,
    llm_model: &str,
    policy_hash: Option<&str>,
) -> Result<(SessionRow, SigningKey), sqlx::Error> {
    create_session_with_did(pool, goal, llm_backend, llm_model, policy_hash, None).await
}

pub async fn create_session_with_did(
    pool: &PgPool,
    goal: &str,
    llm_backend: &str,
    llm_model: &str,
    policy_hash: Option<&str>,
    session_did: Option<&str>,
) -> Result<(SessionRow, SigningKey), sqlx::Error> {
    let id = Uuid::new_v4();
    let goal_hash = crate::hash::goal_hash(goal);
    let (signing_key, verifying_key) = signing::generate_keypair();
    let session_public_key = Some(signing::public_key_hex(&verifying_key));
    // Auto-derive a W3C did:key URI from the freshly generated Ed25519 keypair
    // unless the caller explicitly supplies one (rare override case).
    let did = session_did
        .map(String::from)
        .unwrap_or_else(|| derive_did_key(&verifying_key));
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO agent_sessions
         (id, goal, goal_hash, status, llm_backend, llm_model, created_at, policy_hash, session_public_key, session_did)
         VALUES ($1, $2, $3, 'running', $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(goal)
    .bind(&goal_hash)
    .bind(llm_backend)
    .bind(llm_model)
    .bind(now)
    .bind(policy_hash)
    .bind(&session_public_key)
    .bind(&did)
    .execute(pool)
    .await?;
    Ok((
        SessionRow {
            id,
            goal: goal.to_string(),
            goal_hash: Some(goal_hash),
            status: "running".to_string(),
            llm_backend: Some(llm_backend.to_string()),
            llm_model: Some(llm_model.to_string()),
            created_at: now,
            finished_at: None,
            policy_hash: policy_hash.map(String::from),
            session_public_key,
            session_did: Some(did.clone()),
            enclave_attestation_json: None,
        },
        signing_key,
    ))
}

pub async fn verify_goal_hash(
    pool: &PgPool,
    session_id: Uuid,
    current_goal: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT goal_hash FROM agent_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;
    let Some((Some(stored_hash),)) = row else {
        return Ok(false);
    };
    Ok(crate::hash::goal_hash_matches(&stored_hash, current_goal))
}

pub async fn finish_session(
    pool: &PgPool,
    session_id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    // F-2: record how long the session was, so a later truncation has
    // something to contradict. Same caveat as the SQLite side - these columns
    // sit in the same database as the events, so this catches carelessness and
    // data loss rather than an attacker who owns the file.
    let tip: Option<(String, i64)> = sqlx::query_as(
        "SELECT content_hash, COUNT(*) OVER () FROM agent_events
         WHERE session_id = $1 ORDER BY sequence DESC LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    sqlx::query(
        "UPDATE agent_sessions
         SET status = $1, finished_at = now(), sealed_tip_hash = $3, sealed_event_count = $4
         WHERE id = $2",
    )
    .bind(status)
    .bind(session_id)
    .bind(tip.as_ref().map(|(h, _)| h.as_str()))
    .bind(tip.as_ref().map(|(_, n)| *n))
    .execute(pool)
    .await?;
    Ok(())
}

/// Same as [`finish_session`], but a no-op when the session is already terminal.
/// Used by the background cognitive loop so it cannot un-seal an HTTP seal.
pub async fn finish_session_if_running(
    pool: &PgPool,
    session_id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    let tip: Option<(String, i64)> = sqlx::query_as(
        "SELECT content_hash, COUNT(*) OVER () FROM agent_events
         WHERE session_id = $1 ORDER BY sequence DESC LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    sqlx::query(
        "UPDATE agent_sessions
         SET status = $1, finished_at = now(), sealed_tip_hash = $3, sealed_event_count = $4
         WHERE id = $2 AND status = 'running'",
    )
    .bind(status)
    .bind(session_id)
    .bind(tip.as_ref().map(|(h, _)| h.as_str()))
    .bind(tip.as_ref().map(|(_, n)| *n))
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist enclave attestation evidence on a session so that certificate
/// generation can embed it even after the agent process exits.
pub async fn store_enclave_attestation(
    pool: &PgPool,
    session_id: Uuid,
    attestation: &crate::enclave::runtime::EnclaveAttestation,
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_string(attestation).map_err(|e| {
        sqlx::Error::Protocol(format!("EnclaveAttestation serialisation failed: {e}"))
    })?;
    sqlx::query("UPDATE agent_sessions SET enclave_attestation_json = $1 WHERE id = $2")
        .bind(&json)
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_sessions(pool: &PgPool) -> Result<Vec<SessionRow>, sqlx::Error> {
    list_sessions_filtered(pool, None, 200, 0).await
}

/// List sessions with optional status filter and pagination.
///
/// - `status` - e.g. `Some("completed")`, `Some("running")`; `None` returns all.
/// - `limit`  - maximum rows to return (capped at 500 by the server layer).
/// - `offset` - number of rows to skip (for page-based navigation).
pub async fn list_sessions_filtered(
    pool: &PgPool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<SessionRow>, sqlx::Error> {
    let rows = match status {
        Some(s) => sqlx::query_as::<_, SessionRow>(
            "SELECT id, goal, goal_hash, status, llm_backend, llm_model, created_at, finished_at, \
                 policy_hash, session_public_key, session_did, enclave_attestation_json \
                 FROM agent_sessions WHERE status = $1 \
                 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(s)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?,
        None => sqlx::query_as::<_, SessionRow>(
            "SELECT id, goal, goal_hash, status, llm_backend, llm_model, created_at, finished_at, \
                 policy_hash, session_public_key, session_did, enclave_attestation_json \
                 FROM agent_sessions ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?,
    };
    Ok(rows)
}

/// Return the `session_did` for a session, if set.
pub async fn get_session_did(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT session_did FROM agent_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(did,)| did))
}

pub async fn append_event(
    pool: &PgPool,
    payload: EventPayload,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    signing_key: Option<&SigningKey>,
) -> Result<AppendedEvent, AppendError> {
    if let (Some(sid), Some(goal)) = (session_id, session_goal) {
        let ok = verify_goal_hash(pool, sid, goal)
            .await
            .map_err(AppendError::Db)?;
        if !ok {
            return Err(AppendError::GoalMismatch);
        }
    }

    if let (Some(sid), EventPayload::Action { name, params }) = (session_id, &payload)
        && name == "complete"
        && let Some(findings_val) = params.get("findings")
        && let Ok(findings) = serde_json::from_value::<Vec<AuditFinding>>(findings_val.clone())
    {
        verify_findings(pool, sid, &findings).await?;
    }

    let payload_json = serde_json::to_string(&payload).map_err(AppendError::Serialize)?;

    let mut tx = pool.begin().await.map_err(AppendError::Db)?;

    // Advisory lock prevents race conditions during genesis (no rows to FOR UPDATE).
    sqlx::query("SELECT pg_advisory_xact_lock(42)")
        .execute(&mut *tx)
        .await
        .map_err(AppendError::Db)?;

    let latest = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    let (sequence, previous_hash) = match latest {
        None => (0_i64, GENESIS_PREVIOUS_HASH.to_string()),
        Some((seq, content_hash)) => (seq + 1, content_hash),
    };

    let now = Utc::now();
    // Truncate to microsecond precision to match what PostgreSQL TIMESTAMPTZ stores.
    // Without this, `now.to_rfc3339()` may produce 9 decimal places when the
    // sub-microsecond nanosecond component is non-zero (e.g. "…970769388+00:00"),
    // whereas reading `created_at` back from the DB always yields 6 decimal places
    // ("…970769+00:00"), causing `verify_chain` to compute a different hash.
    let now_us = now
        .with_nanosecond((now.nanosecond() / 1_000) * 1_000)
        .unwrap_or(now);
    // Canonical v2 scheme: binds previous_hash, sequence, payload, session_id,
    // and the microsecond-truncated creation timestamp.
    let content_hash = crate::hash::compute_content_hash_v2(
        &previous_hash,
        sequence,
        &payload_json,
        session_id.map(|u| u.to_string()).as_deref(),
        &now_us.to_rfc3339(),
    );

    let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
        "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, created_at, session_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, sequence, previous_hash, content_hash, created_at",
    )
    .bind(sequence)
    .bind(&previous_hash)
    .bind(&content_hash)
    .bind(sqlx::types::Json(&payload))
    .bind(now_us)
    .bind(session_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    // Sign and insert the event signature inside the transaction so event+sig
    // are atomic - prevents unsigned events if the sig INSERT fails.
    if let (Some(sk), Some(_sid)) = (signing_key, session_id) {
        let pk_hex = signing::public_key_hex(&sk.verifying_key());
        let sig_hex = signing::sign_content_hash(sk, &row.3);
        sqlx::query(
            "INSERT INTO agent_event_signatures (event_id, content_hash, signature, public_key) VALUES ($1, $2, $3, $4)",
        )
        .bind(row.0)
        .bind(&row.3)
        .bind(&sig_hex)
        .bind(&pk_hex)
        .execute(&mut *tx)
        .await
        .map_err(AppendError::Db)?;
    }

    tx.commit().await.map_err(AppendError::Db)?;

    let appended = AppendedEvent {
        id: row.0,
        sequence: row.1,
        previous_hash: row.2,
        content_hash: row.3,
        created_at: row.4,
    };

    // Wake SSE stream handlers so they fetch the new event immediately.
    crate::server::notify_sse_subscribers();
    // Also issue a PostgreSQL NOTIFY for cross-instance SSE wakeup.
    crate::pg_notify::notify_new_event(pool).await;

    Ok(appended)
}

pub async fn ensure_genesis(pool: &PgPool) -> Result<AppendedEvent, AppendError> {
    let latest = get_latest(pool).await.map_err(AppendError::Db)?;
    if let Some((seq, _)) = latest {
        let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
            "SELECT id, sequence, previous_hash, content_hash, created_at FROM agent_events WHERE sequence = $1",
        )
        .bind(seq)
        .fetch_one(pool)
        .await
        .map_err(AppendError::Db)?;
        return Ok(AppendedEvent {
            id: row.0,
            sequence: row.1,
            previous_hash: row.2,
            content_hash: row.3,
            created_at: row.4,
        });
    }

    let payload = EventPayload::Genesis {
        message: "EctoLedger initialized".to_string(),
        nonce: Some(hex::encode(uuid::Uuid::new_v4().as_bytes())),
        session_public_key: None, // server-level genesis: no session signing key yet
    };
    append_event(pool, payload, None, None, None).await
}

pub async fn get_event_by_id(
    pool: &PgPool,
    event_id: i64,
) -> Result<Option<LedgerEventRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(db_row_to_ledger_event))
}

pub async fn mark_action_executing(pool: &PgPool, event_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO agent_action_log (event_id, status) VALUES ($1, 'executing')")
        .bind(event_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn mark_action_completed(pool: &PgPool, event_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_action_log SET status = 'completed', finished_at = now() WHERE event_id = $1",
    )
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_action_failed(
    pool: &PgPool,
    event_id: i64,
    error_msg: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_action_log SET status = 'failed', finished_at = now(), error_msg = $2 WHERE event_id = $1",
    )
    .bind(event_id)
    .bind(error_msg)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_dangling_actions(pool: &PgPool) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, i64>(
        "SELECT event_id FROM agent_action_log WHERE status IN ('pending', 'executing') ORDER BY started_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_events(
    pool: &PgPool,
    from_sequence: i64,
    to_sequence: i64,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events
         WHERE sequence >= $1 AND sequence <= $2
         ORDER BY sequence ASC",
    )
    .bind(from_sequence)
    .bind(to_sequence)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(db_row_to_ledger_event).collect())
}

pub async fn find_cached_http_get(pool: &PgPool, url: &str) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query_scalar::<_, sqlx::types::Json<crate::schema::EventPayload>>(
        r#"SELECT ae_obs.payload
           FROM agent_events ae_act
           JOIN agent_action_log aal
             ON aal.event_id = ae_act.id AND aal.status = 'completed'
           JOIN agent_events ae_obs
             ON ae_obs.sequence = ae_act.sequence + 1
          WHERE ae_act.payload->>'type' = 'action'
            AND ae_act.payload->>'name' = 'http_get'
            AND ae_act.payload->'params'->>'url' = $1
          ORDER BY ae_act.sequence DESC
          LIMIT 1"#,
    )
    .bind(url)
    .fetch_optional(pool)
    .await?;

    if let Some(payload) = row
        && let crate::schema::EventPayload::Observation { content } = payload.0
    {
        return Ok(Some(content));
    }
    Ok(None)
}

pub async fn get_events_by_session(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events
         WHERE session_id = $1
         ORDER BY sequence ASC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(db_row_to_ledger_event).collect())
}

pub async fn verify_findings(
    pool: &PgPool,
    session_id: Uuid,
    findings: &[AuditFinding],
) -> Result<(), AppendError> {
    if findings.is_empty() {
        return Ok(());
    }
    let events = get_events_by_session(pool, session_id)
        .await
        .map_err(AppendError::Db)?;
    let observation_by_seq: std::collections::HashMap<i64, String> = events
        .into_iter()
        .filter_map(|e| {
            if let EventPayload::Observation { content } = e.payload {
                Some((e.sequence, content))
            } else {
                None
            }
        })
        .collect();

    for f in findings {
        if matches!(
            f.severity,
            FindingSeverity::High | FindingSeverity::Critical
        ) && f.evidence_sequence.is_empty()
        {
            return Err(AppendError::UnverifiedEvidence(format!(
                "finding '{}' (high/critical) has no evidence_sequence",
                f.title
            )));
        }
        for (i, &seq) in f.evidence_sequence.iter().enumerate() {
            let content = observation_by_seq.get(&seq).ok_or_else(|| {
                AppendError::UnverifiedEvidence(format!(
                    "finding '{}' references sequence {} which is not an observation in this session",
                    f.title, seq
                ))
            })?;
            let quote = f.evidence_quotes.get(i).map(String::as_str).unwrap_or("");
            if !quote.is_empty() && !content.contains(quote) {
                return Err(AppendError::UnverifiedEvidence(format!(
                    "finding '{}' evidence_quotes[{}] is not a substring of observation at sequence {}",
                    f.title, i, seq
                )));
            }
        }
    }
    Ok(())
}

// Re-export the shared `AppendError` so existing `ledger::postgres::AppendError`
// paths continue to resolve.
pub use super::AppendError;

/// Verify a session's signatures, reporting a count and the first error.
///
/// Retained for callers that want this shape. It delegates to
/// [`verify_session_detailed`] rather than carrying a second implementation
/// that verifies each signature against the copy of the hash stored beside
/// it - that shape is the F-1 hole (the 0.8.0 changelog), so a
/// weaker verifier kept here as a public function would leave the hole open
/// behind a different name.
pub async fn verify_session_signatures(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<(usize, Option<crate::signing::SigningError>), sqlx::Error> {
    use crate::ledger::SessionVerdict;
    Ok(match verify_session_detailed(pool, session_id).await? {
        SessionVerdict::Verified { signatures, .. } => (signatures, None),
        SessionVerdict::UnauthorisedKey { .. } => {
            (0, Some(crate::signing::SigningError::InvalidKey))
        }
        // Everything else is "the event is not what was signed", which this
        // return shape cannot express in more detail. Callers wanting the
        // distinction should use `verify_session_detailed`.
        _ => (0, Some(crate::signing::SigningError::VerificationFailed)),
    })
}

/// Verify that a session's events are what their signatures say they are.
///
/// The Postgres counterpart of [`super::sqlite::verify_session_detailed_sqlite`],
/// and the same two-step composition - recompute the hash from the payload,
/// then verify the signature over the event's own `content_hash`, never over
/// the copy stored beside the signature. See the 0.8.0 changelog,
/// F-1, for why the copy is not trustworthy.
///
/// [`verify_session_signatures`] is kept for callers that only need a count and
/// a `SigningError`; it does not perform step 1 and should be considered the
/// legacy entry point.
pub async fn verify_session_detailed(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<crate::ledger::SessionVerdict, sqlx::Error> {
    use crate::ledger::SessionVerdict;

    let Some(session) = list_sessions(pool)
        .await?
        .into_iter()
        .find(|s| s.id == session_id)
    else {
        return Ok(SessionVerdict::Verified {
            signatures: 0,
            unsigned: 0,
        });
    };
    // No recorded key is not "nothing to verify": the events are still checked,
    // and the verdict says what is and is not bound (F-4).
    let has_key = session.session_public_key.is_some();

    // Raw rows, not `LedgerEventRow`: step 1 needs previous_hash, session_id
    // and created_at, and needs the payload as the JSON the hash was taken
    // over rather than a re-parsed struct.
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events WHERE session_id = $1 ORDER BY sequence ASC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await?;

    let mut keys = crate::ledger::KeyLifecycle::new(session.session_public_key);

    let mut coverage = crate::ledger::SignatureCoverage::default();
    for row in &rows {
        // Step 1: bind payload → content_hash.
        if !event_hash_is_consistent(row) {
            return Ok(SessionVerdict::PayloadHashMismatch {
                sequence: row.sequence,
            });
        }

        let sig_row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT content_hash, signature, public_key FROM agent_event_signatures \
             WHERE event_id = $1",
        )
        .bind(row.id)
        .fetch_optional(pool)
        .await?;

        let payload_json = serde_json::to_string(&row.payload.0).unwrap_or_default();
        let Some((signed_hash, signature, sig_public_key)) = sig_row else {
            if let Err(verdict) = coverage.unsigned(row.sequence, &payload_json) {
                return Ok(verdict);
            }
            continue;
        };
        if !keys.permits(&sig_public_key) {
            return Ok(SessionVerdict::UnauthorisedKey {
                sequence: row.sequence,
            });
        }
        // Diagnostic only - step 2 would reject this anyway.
        if signed_hash != row.content_hash {
            return Ok(SessionVerdict::AlteredAfterSigning {
                sequence: row.sequence,
            });
        }
        // Step 2: bind content_hash → key.
        if signing::verify_signature(&sig_public_key, &row.content_hash, &signature).is_err() {
            return Ok(SessionVerdict::BadSignature {
                sequence: row.sequence,
            });
        }
        coverage.signed(&payload_json);
        keys.after(&row.payload.0);
    }

    // F-2: sessions sealed by 0.8.0 or later said how long they were. Earlier
    // seals recorded nothing and are skipped - absence of the record is not
    // evidence of truncation.
    let sealed: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT sealed_tip_hash, sealed_event_count FROM agent_sessions WHERE id = $1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;
    if let Some((Some(sealed_tip), Some(sealed_count))) = sealed {
        let found = rows.len() as i64;
        let tip_now = rows.last().map(|r| r.content_hash.as_str()).unwrap_or("");
        if found != sealed_count || tip_now != sealed_tip {
            return Ok(SessionVerdict::TruncatedSinceSealing {
                sealed_events: sealed_count,
                found_events: found,
            });
        }
    }

    Ok(coverage.finish(has_key))
}

/// Newtype wrapping `PgPool` that implements `ledger_api::LedgerBackend`.
pub struct PostgresLedger(pub PgPool);
