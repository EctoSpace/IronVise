//! SQLite-backed implementation of `ledger_api::LedgerBackend`.
//!
//! Use `DATABASE_URL=sqlite://ledger.db` (or `sqlite://:memory:`) to
//! activate this backend.  Good for zero-config local development.
//!
//! Schema is kept in `migrations/sqlite/` and applied at startup.

use crate::hash::GENESIS_PREVIOUS_HASH;
use crate::schema::{AppendedEvent, EventPayload, LedgerEventRow, SessionRow};
use crate::signing;
mod adapter;
use chrono::{Timelike as _, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sqlx::SqlitePool;
use uuid::Uuid;

// Re-import `AppendError` through the module root so the SQLite backend
// does not depend directly on the Postgres module.
use super::AppendError;

// Unlike Postgres (where UUIDs and JSON are native column types), SQLite stores
// both as TEXT.  These `FromRow` structs match the SQLite column types and are
// converted to the domain types in-memory.

/// Row returned by `SELECT … FROM agent_events`.
#[derive(sqlx::FromRow)]
struct SqliteEventRow {
    id: i64,
    sequence: i64,
    previous_hash: String,
    content_hash: String,
    payload: String,
    created_at: chrono::DateTime<Utc>,
    #[allow(dead_code)]
    session_id: Option<String>,
}

/// Row returned by `SELECT … FROM agent_sessions`.
#[derive(sqlx::FromRow)]
struct SqliteSessionRow {
    id: String,
    goal: String,
    goal_hash: Option<String>,
    status: String,
    llm_backend: Option<String>,
    llm_model: Option<String>,
    created_at: chrono::DateTime<Utc>,
    finished_at: Option<chrono::DateTime<Utc>>,
    policy_hash: Option<String>,
    session_public_key: Option<String>,
    session_did: Option<String>,
    enclave_attestation_json: Option<String>,
}

/// Derives a `did:key:z6Mk…` URI from an Ed25519 verifying key following the
/// W3C DID-key specification (multicodec prefix `0xed01` + base58btc encoding).
///
/// <https://w3c-ccg.github.io/did-method-key/#ed25519-x25519>
fn derive_did_key(verifying_key: &VerifyingKey) -> String {
    let mut encoded = vec![0xed_u8, 0x01_u8];
    encoded.extend_from_slice(verifying_key.as_bytes());
    format!("did:key:z{}", bs58::encode(&encoded).into_string())
}

/// Newtype wrapping `SqlitePool` that implements `ledger_api::LedgerBackend`.
pub struct SqliteLedger(pub SqlitePool);

impl SqliteLedger {
    /// Open (or create) a SQLite database at `url` and run migrations.
    ///
    /// Enables WAL journal mode (better concurrent-read performance on all
    /// platforms) and sets a 5-second busy timeout so that transient locks
    /// do not immediately fail - important on Windows where file-lock
    /// contention is more common.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        use sqlx::sqlite::SqliteConnectOptions;
        use std::str::FromStr;

        let opts = SqliteConnectOptions::from_str(url)?
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5))
            .create_if_missing(true);
        #[cfg(feature = "sqlcipher")]
        let opts = crate::sqlcipher::keyed(
            opts,
            crate::sqlcipher::read_sqlcipher_key()
                .map_err(|e| sqlx::Error::Configuration(e.into()))?,
        );

        let pool = SqlitePool::connect_with(opts).await?;
        #[cfg(feature = "sqlcipher")]
        crate::sqlcipher::check_pool(&pool)
            .await
            .map_err(|e| sqlx::Error::Configuration(e.into()))?;
        crate::migrations::migrate_sqlite(&pool)
            .await
            .map_err(|e| sqlx::Error::Configuration(e.into()))?;
        Ok(Self(pool))
    }
}

// These mirror the Postgres free functions in `ledger::postgres` and can be
// called from `main.rs`, `pool.rs`, and command handlers without constructing
// a full `SqliteLedger` wrapper.

pub async fn get_latest_sqlite(pool: &SqlitePool) -> Result<Option<(i64, String)>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Verify hash-chain integrity for a range of sequences (inclusive).
///
/// When `from > 0` the function fetches event `from - 1` to seed the expected
/// `previous_hash` - otherwise verification would incorrectly compare the
/// first row's `previous_hash` against genesis.
pub async fn verify_chain_sqlite(
    pool: &SqlitePool,
    from: i64,
    to: i64,
) -> Result<bool, sqlx::Error> {
    // Wrap both reads in a transaction to guarantee a consistent snapshot;
    // without this, a concurrent writer could cause a false-negative.
    let mut tx = pool.begin().await?;

    let rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            String,
            Option<String>,
            chrono::DateTime<Utc>,
        ),
    >(
        "SELECT sequence, previous_hash, content_hash, payload, session_id, created_at
         FROM agent_events WHERE sequence >= ?1 AND sequence <= ?2 ORDER BY sequence ASC",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&mut *tx)
    .await?;

    if rows.is_empty() {
        return Ok(true);
    }

    // Seed: if verifying from a non-genesis offset, fetch the preceding
    // event's content_hash so we can validate the first row's previous_hash.
    let mut prev: Option<String> = if from > 0 {
        sqlx::query_scalar::<_, String>("SELECT content_hash FROM agent_events WHERE sequence = ?1")
            .bind(from - 1)
            .fetch_optional(&mut *tx)
            .await?
    } else {
        None
    };

    for (seq, prev_hash, ch, payload_str, sid, created_at) in rows {
        let expected_prev = prev.as_deref().unwrap_or(GENESIS_PREVIOUS_HASH);
        if prev_hash != expected_prev {
            return Ok(false);
        }
        let ts_str = created_at.to_rfc3339();
        // Verify against the canonical v2 scheme first, falling back through
        // the pre-migration v1 layouts (shared multi-scheme verifier in
        // ectoledger_core::hash; constant-time comparisons throughout).
        if crate::hash::verify_content_hash_any_scheme(
            &prev_hash,
            seq,
            &payload_str,
            sid.as_deref(),
            Some(&ts_str),
            &ch,
        )
        .is_none()
        {
            return Ok(false);
        }
        prev = Some(ch);
    }
    Ok(true)
}

/// Verify Ed25519 event signatures for all events in a session.
///
/// Returns `true` when every signed event has a valid signature, or when
/// no signatures exist (unsigned sessions are not a verification failure).
///
/// Thin wrapper over [`verify_session_detailed_sqlite`]; use that when the
/// caller can say something useful about *which* check failed.
pub async fn verify_session_signatures_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
) -> Result<bool, sqlx::Error> {
    Ok(verify_session_detailed_sqlite(pool, session_id)
        .await?
        .is_verified())
}

/// Verify that a session's events are what their signatures say they are.
///
/// Two steps, and the composition is the point (the 0.8.0 changelog,
/// F-1):
///
/// 1. Recompute each event's hash from its **payload** via the multi-scheme
///    verifier, binding payload → `content_hash`. Legacy v1 ledgers keep
///    verifying because that verifier already knows their layouts.
/// 2. Verify the signature over the event's own `content_hash`, binding
///    `content_hash` → key.
///
/// Together they bind payload → key, which is the property the README claims.
///
/// What this deliberately does *not* trust is `agent_event_signatures.content_hash`.
/// Verifying a signature against the hash stored beside it proves only that
/// those two fields agree with each other; both belong to anyone who can write
/// to the database, and the event itself never enters the check. The stored
/// copy is compared only so the failure can be named `AlteredAfterSigning`
/// rather than a bare invalid signature.
pub async fn verify_session_detailed_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
) -> Result<crate::ledger::SessionVerdict, sqlx::Error> {
    use crate::ledger::SessionVerdict;

    // Fetch the session's authorised public key so we can cross-check
    // that every signature was produced by an authorised key.
    let session_pk: Option<String> =
        sqlx::query_scalar("SELECT session_public_key FROM agent_sessions WHERE id = ?1")
            .bind(session_id.to_string())
            .fetch_optional(pool)
            .await?
            .flatten();
    // No recorded key is not "nothing to verify": a missing key must not
    // short-circuit to `Verified` before the payload check runs, or clearing
    // one column would let any payload be edited without even recomputing
    // its hash (F-4). The events are still checked; the verdict says what is
    // and is not bound.
    let has_key = session_pk.is_some();

    let mut keys = crate::ledger::KeyLifecycle::new(session_pk);

    // Fetch events in order. `previous_hash`, `created_at` and `session_id` are
    // here because step 1 recomputes the hash from the payload and needs the
    // whole v2 input, not just the payload.
    let event_rows = sqlx::query_as::<
        _,
        (
            i64,
            i64,
            String,
            String,
            String,
            Option<String>,
            chrono::DateTime<Utc>,
        ),
    >(
        "SELECT e.id, e.sequence, e.previous_hash, e.content_hash, e.payload,
                e.session_id, e.created_at
         FROM agent_events e WHERE e.session_id = ?1 ORDER BY e.sequence ASC",
    )
    .bind(session_id.to_string())
    .fetch_all(pool)
    .await?;

    // Map event_id → payload for key lifecycle processing.
    let mut event_payloads: std::collections::HashMap<i64, EventPayload> =
        std::collections::HashMap::new();
    for (eid, _seq, _prev, _ch, payload_str, _sid, _ts) in &event_rows {
        if let Ok(p) = serde_json::from_str::<EventPayload>(payload_str) {
            event_payloads.insert(*eid, p);
        }
    }

    // Fetch all signatures ordered by event sequence.
    let rows = sqlx::query_as::<_, (i64, String, String, String)>(
        "SELECT s.event_id, s.content_hash, s.signature, s.public_key
         FROM agent_event_signatures s
         JOIN agent_events e ON e.id = s.event_id
         WHERE e.session_id = ?1
         ORDER BY e.sequence ASC",
    )
    .bind(session_id.to_string())
    .fetch_all(pool)
    .await?;

    // Process events and signatures together, updating authorised keys as we go.
    let mut sig_idx = 0;
    let mut coverage = crate::ledger::SignatureCoverage::default();
    for (eid, seq, prev_hash, event_content_hash, payload_str, sid, created_at) in &event_rows {
        // Step 1: bind payload → content_hash.
        // Without this, a signature check alone still misses a plain payload
        // edit: nothing else in this function ever looks at the payload, and
        // `verify-session` does not run the chain check (that lives in the
        // `serve`/`audit` startup path, and only over the last 1000 events
        // unless --verify-full). So this has to be here, not assumed elsewhere.
        let ts_str = created_at.to_rfc3339();
        if crate::hash::verify_content_hash_any_scheme(
            prev_hash,
            *seq,
            payload_str,
            sid.as_deref(),
            Some(&ts_str),
            event_content_hash,
        )
        .is_none()
        {
            return Ok(SessionVerdict::PayloadHashMismatch { sequence: *seq });
        }

        // Check if this event has a signature.
        let mut signed = false;
        while sig_idx < rows.len() && rows[sig_idx].0 == *eid {
            let (_, ref signed_hash, ref signature_hex, ref pubkey_hex) = rows[sig_idx];
            sig_idx += 1;

            // Reject if the signing key was revoked or is not authorised.
            if !keys.permits(pubkey_hex) {
                return Ok(SessionVerdict::UnauthorisedKey { sequence: *seq });
            }

            // Diagnostic only. The signature is checked against the event's own
            // hash below either way, so a mismatch here would fail anyway -
            // catching it first just lets us say what actually happened.
            if signed_hash != event_content_hash {
                return Ok(SessionVerdict::AlteredAfterSigning { sequence: *seq });
            }

            let pk_bytes = match hex::decode(pubkey_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => return Ok(SessionVerdict::UnauthorisedKey { sequence: *seq }),
            };
            let arr: [u8; 32] = match pk_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return Ok(SessionVerdict::UnauthorisedKey { sequence: *seq }),
            };
            let vk = match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                Ok(v) => v,
                Err(_) => return Ok(SessionVerdict::UnauthorisedKey { sequence: *seq }),
            };
            // Step 2: bind content_hash → key.
            // The event's hash, never the copy stored beside the signature.
            if !signing::verify_content_hash(&vk, event_content_hash, signature_hex) {
                return Ok(SessionVerdict::BadSignature { sequence: *seq });
            }
            signed = true;
        }
        if signed {
            coverage.signed(payload_str);
        } else if let Err(verdict) = coverage.unsigned(*seq, payload_str) {
            return Ok(verdict);
        }
        if let Some(payload) = event_payloads.get(eid) {
            keys.after(payload);
        }
    }
    // F-2: if this session was sealed by 0.8.0 or later, it said how long it
    // was. Sessions sealed earlier recorded nothing and are skipped rather than
    // failed - absence of the record is not evidence of truncation.
    let sealed: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT sealed_tip_hash, sealed_event_count FROM agent_sessions WHERE id = ?1",
    )
    .bind(session_id.to_string())
    .fetch_optional(pool)
    .await?;
    if let Some((Some(sealed_tip), Some(sealed_count))) = sealed {
        let found = event_rows.len() as i64;
        let tip_now = event_rows.last().map(|r| r.3.as_str()).unwrap_or("");
        if found != sealed_count || tip_now != sealed_tip {
            return Ok(SessionVerdict::TruncatedSinceSealing {
                sealed_events: sealed_count,
                found_events: found,
            });
        }
    }

    Ok(coverage.finish(has_key))
}

pub async fn append_event_sqlite(
    pool: &SqlitePool,
    payload: &EventPayload,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    signing_key: Option<&SigningKey>,
) -> Result<AppendedEvent, AppendError> {
    if let (Some(sid), Some(goal)) = (session_id, session_goal) {
        let stored: Option<(String,)> =
            sqlx::query_as("SELECT goal_hash FROM agent_sessions WHERE id = ?1")
                .bind(sid.to_string())
                .fetch_optional(pool)
                .await
                .map_err(AppendError::Db)?;
        match stored {
            Some((h,)) if crate::hash::goal_hash_matches(&h, goal) => {}
            _ => return Err(AppendError::GoalMismatch),
        }
    }

    if let (Some(sid), EventPayload::Action { name, params }) = (session_id, payload)
        && name == "complete"
        && let Some(findings_val) = params.get("findings")
        && let Ok(findings) =
            serde_json::from_value::<Vec<crate::schema::AuditFinding>>(findings_val.clone())
    {
        verify_findings_sqlite(pool, sid, &findings).await?;
    }

    let payload_json = serde_json::to_string(payload).map_err(AppendError::Serialize)?;

    let mut tx = pool.begin().await.map_err(AppendError::Db)?;

    // Upgrade from DEFERRED to IMMEDIATE so the write lock is acquired *before*
    // we read the latest sequence.  Without this, two concurrent callers can
    // both read the same `latest` inside their DEFERRED transactions and then
    // one INSERT will fail with UNIQUE-constraint on `sequence`.  IMMEDIATE
    // serialises writers at BEGIN time - the SQLite equivalent of Postgres'
    // `pg_advisory_xact_lock(42)`.  Works on macOS, Windows, and Linux.
    sqlx::query("END; BEGIN IMMEDIATE")
        .execute(&mut *tx)
        .await
        .map_err(AppendError::Db)?;

    let latest = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    let (sequence, previous_hash) = match latest {
        None => (0_i64, GENESIS_PREVIOUS_HASH.to_string()),
        Some((seq, ch)) => (seq + 1, ch),
    };

    let sid_str = session_id.map(|u| u.to_string());
    let now = Utc::now();
    // Truncate to microsecond precision so the timestamp that is hashed is
    // exactly what a verifier reading the row back will reproduce - matching
    // the Postgres backend, whose TIMESTAMPTZ stores at most microseconds.
    let now_us = now
        .with_nanosecond((now.nanosecond() / 1_000) * 1_000)
        .unwrap_or(now);
    // Canonical v2 scheme: binds previous_hash, sequence, payload, session_id,
    // and the microsecond-truncated creation timestamp.
    let content_hash = crate::hash::compute_content_hash_v2(
        &previous_hash,
        sequence,
        &payload_json,
        sid_str.as_deref(),
        &now_us.to_rfc3339(),
    );

    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, created_at, session_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         RETURNING id",
    )
    .bind(sequence)
    .bind(&previous_hash)
    .bind(&content_hash)
    .bind(&payload_json)
    .bind(now_us)
    .bind(&sid_str)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    // Insert signature inside the SAME transaction so event + signature are
    // committed atomically, matching the PostgreSQL backend's behaviour.
    if let (Some(sk), Some(_sid)) = (signing_key, session_id) {
        let pk_hex = signing::public_key_hex(&sk.verifying_key());
        let sig_hex = signing::sign_content_hash(sk, &content_hash);
        sqlx::query(
            "INSERT INTO agent_event_signatures (event_id, content_hash, signature, public_key) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(id)
        .bind(&content_hash)
        .bind(&sig_hex)
        .bind(&pk_hex)
        .execute(&mut *tx)
        .await
        .map_err(AppendError::Db)?;
    }

    tx.commit().await.map_err(AppendError::Db)?;

    let appended = AppendedEvent {
        id,
        sequence,
        previous_hash,
        content_hash,
        created_at: now_us,
    };

    crate::server::notify_sse_subscribers();

    Ok(appended)
}

pub async fn create_session_sqlite(
    pool: &SqlitePool,
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
    // Auto-derive a W3C did:key URI from the Ed25519 keypair unless the
    // caller explicitly supplies one - matches the Postgres backend.
    let did = session_did
        .map(String::from)
        .unwrap_or_else(|| derive_did_key(&verifying_key));
    let now = Utc::now();
    let id_str = id.to_string();

    sqlx::query(
        "INSERT INTO agent_sessions
         (id, goal, goal_hash, status, llm_backend, llm_model, created_at, policy_hash, session_public_key, session_did)
         VALUES (?1, ?2, ?3, 'running', ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&id_str)
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
            session_did: Some(did),
            enclave_attestation_json: None,
        },
        signing_key,
    ))
}

/// Mark a session as finished with the given status.
///
/// Returns `sqlx::Error::RowNotFound` if no session with the given id exists,
/// preventing silent no-ops when the caller passes a stale or invalid UUID.
pub async fn finish_session_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    finish_session_sqlite_inner(pool, session_id, status, false).await
}

/// Same as [`finish_session_sqlite`], but a no-op when the session is already
/// terminal. The cognitive loop uses this so a later `failed` cannot un-seal
/// an HTTP `POST …/seal`.
pub async fn finish_session_sqlite_if_running(
    pool: &SqlitePool,
    session_id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    finish_session_sqlite_inner(pool, session_id, status, true).await
}

async fn finish_session_sqlite_inner(
    pool: &SqlitePool,
    session_id: Uuid,
    status: &str,
    only_if_running: bool,
) -> Result<(), sqlx::Error> {
    // F-2: record how long the session was, so a later truncation has something
    // to contradict. Same database as the events, so this stops carelessness
    // rather than an attacker - see the migration comment and
    // the 0.8.0 changelog.
    let tip: Option<(String, i64)> = sqlx::query_as(
        "SELECT content_hash, COUNT(*) OVER () FROM agent_events
         WHERE session_id = ?1 ORDER BY sequence DESC LIMIT 1",
    )
    .bind(session_id.to_string())
    .fetch_optional(pool)
    .await?;

    let sql = if only_if_running {
        "UPDATE agent_sessions
         SET status = ?1, finished_at = ?2, sealed_tip_hash = ?4, sealed_event_count = ?5
         WHERE id = ?3 AND status = 'running'"
    } else {
        "UPDATE agent_sessions
         SET status = ?1, finished_at = ?2, sealed_tip_hash = ?4, sealed_event_count = ?5
         WHERE id = ?3"
    };
    let result = sqlx::query(sql)
        .bind(status)
        .bind(Utc::now())
        .bind(session_id.to_string())
        .bind(tip.as_ref().map(|(h, _)| h.as_str()))
        .bind(tip.as_ref().map(|(_, n)| *n))
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 && !only_if_running {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// Retrieve all events for a session, ordered by sequence.
///
/// Returns an error if any stored payload cannot be deserialised, rather than
/// silently fabricating a synthetic `Observation` - an immutable audit ledger
/// must never misrepresent its own data.
pub async fn get_events_by_session_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, SqliteEventRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events WHERE session_id = ?1 ORDER BY sequence ASC",
    )
    .bind(session_id.to_string())
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let payload: EventPayload = serde_json::from_str(&row.payload).map_err(|e| {
                sqlx::Error::Decode(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("corrupt event payload at id={}: {}", row.id, e),
                )))
            })?;
            Ok(LedgerEventRow {
                id: row.id,
                sequence: row.sequence,
                previous_hash: row.previous_hash,
                content_hash: row.content_hash,
                payload,
                created_at: row.created_at,
            })
        })
        .collect()
}

/// List all sessions (for CLI display / reporting).
///
/// Returns a hard error if any stored `id` cannot be parsed as a UUID rather
/// than silently dropping the row - callers should be aware of corrupt data.
pub async fn list_sessions_sqlite(pool: &SqlitePool) -> Result<Vec<SessionRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, SqliteSessionRow>(
        "SELECT id, goal, goal_hash, status, llm_backend, llm_model,
                created_at, finished_at, policy_hash, session_public_key, session_did,
                enclave_attestation_json
         FROM agent_sessions ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let id: Uuid = row.id.parse().map_err(|e| {
                sqlx::Error::Decode(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid UUID in agent_sessions.id '{}': {}", row.id, e),
                )))
            })?;
            Ok(SessionRow {
                id,
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
                enclave_attestation_json: row.enclave_attestation_json,
            })
        })
        .collect()
}

/// Fetch every session column by primary key without listing pagination.
pub async fn get_session_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
) -> Result<Option<SessionRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, SqliteSessionRow>(
        "SELECT id, goal, goal_hash, status, llm_backend, llm_model,
                created_at, finished_at, policy_hash, session_public_key, session_did,
                enclave_attestation_json FROM agent_sessions WHERE id = ?1",
    )
    .bind(session_id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| SessionRow {
        id: session_id,
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
        enclave_attestation_json: row.enclave_attestation_json,
    }))
}

/// Sessions for the API and the GUI: optional status filter and paging, every
/// column. Rows whose `id` is not a UUID are skipped with a warning rather than
/// failing the whole page, since this feeds a list a person is looking at.
///
/// Selects every column itself, rather than leaving it to a caller's own
/// query: a partial column list here would silently hide a session's key
/// (and whether it has finished) from anything reading it through the pool
/// on SQLite, including the GUI.
pub async fn list_sessions_page_sqlite(
    pool: &SqlitePool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<SessionRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, SqliteSessionRow>(
        "SELECT id, goal, goal_hash, status, llm_backend, llm_model,
                created_at, finished_at, policy_hash, session_public_key, session_did,
                enclave_attestation_json
         FROM agent_sessions
         WHERE (?1 IS NULL OR status = ?1)
         ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
    )
    .bind(status)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| match row.id.parse::<Uuid>() {
            Ok(id) => Some(SessionRow {
                id,
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
                enclave_attestation_json: row.enclave_attestation_json,
            }),
            Err(e) => {
                tracing::warn!("Skipping session with unparseable UUID '{}': {}", row.id, e);
                None
            }
        })
        .collect())
}

/// Load events in the inclusive sequence range `[from_sequence, to_sequence]`.
pub async fn get_events_sqlite(
    pool: &SqlitePool,
    from_sequence: i64,
    to_sequence: i64,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, SqliteEventRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events
         WHERE sequence >= ?1 AND sequence <= ?2
         ORDER BY sequence ASC",
    )
    .bind(from_sequence)
    .bind(to_sequence)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let payload: EventPayload = serde_json::from_str(&row.payload).map_err(|e| {
                sqlx::Error::Decode(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("corrupt event payload at id={}: {}", row.id, e),
                )))
            })?;
            Ok(LedgerEventRow {
                id: row.id,
                sequence: row.sequence,
                previous_hash: row.previous_hash,
                content_hash: row.content_hash,
                payload,
                created_at: row.created_at,
            })
        })
        .collect()
}

pub async fn mark_action_executing_sqlite(
    pool: &SqlitePool,
    event_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO agent_action_log (event_id, status) VALUES (?1, 'executing')")
        .bind(event_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn mark_action_completed_sqlite(
    pool: &SqlitePool,
    event_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_action_log SET status = 'completed', finished_at = ?1 WHERE event_id = ?2",
    )
    .bind(Utc::now())
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_action_failed_sqlite(
    pool: &SqlitePool,
    event_id: i64,
    error_msg: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_action_log
         SET status = 'failed', finished_at = ?1, error_msg = ?2
         WHERE event_id = ?3",
    )
    .bind(Utc::now())
    .bind(error_msg)
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_dangling_actions_sqlite(pool: &SqlitePool) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT event_id FROM agent_action_log
         WHERE status IN ('pending', 'executing')
         ORDER BY started_at ASC",
    )
    .fetch_all(pool)
    .await
}

/// Look up a cached `http_get` observation for `url` (same shape as Postgres).
pub async fn find_cached_http_get_sqlite(
    pool: &SqlitePool,
    url: &str,
) -> Result<Option<String>, sqlx::Error> {
    let payload_json: Option<String> = sqlx::query_scalar(
        r#"SELECT ae_obs.payload
           FROM agent_events ae_act
           JOIN agent_action_log aal
             ON aal.event_id = ae_act.id AND aal.status = 'completed'
           JOIN agent_events ae_obs
             ON ae_obs.sequence = ae_act.sequence + 1
          WHERE json_extract(ae_act.payload, '$.type') = 'action'
            AND json_extract(ae_act.payload, '$.name') = 'http_get'
            AND json_extract(ae_act.payload, '$.params.url') = ?1
          ORDER BY ae_act.sequence DESC
          LIMIT 1"#,
    )
    .bind(url)
    .fetch_optional(pool)
    .await?;

    if let Some(raw) = payload_json {
        let payload: EventPayload = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("corrupt cached http_get observation: {e}"),
            )))
        })?;
        if let EventPayload::Observation { content } = payload {
            return Ok(Some(content));
        }
    }
    Ok(None)
}

pub async fn store_enclave_attestation_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
    attestation: &crate::enclave::runtime::EnclaveAttestation,
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_string(attestation).map_err(|e| {
        sqlx::Error::Protocol(format!("EnclaveAttestation serialisation failed: {e}"))
    })?;
    sqlx::query("UPDATE agent_sessions SET enclave_attestation_json = ?1 WHERE id = ?2")
        .bind(&json)
        .bind(session_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_session_policy_hash_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<String>>("SELECT policy_hash FROM agent_sessions WHERE id = ?1")
        .bind(session_id.to_string())
        .fetch_optional(pool)
        .await
        .map(|row| row.flatten())
}

pub async fn verify_findings_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
    findings: &[crate::schema::AuditFinding],
) -> Result<(), AppendError> {
    use crate::schema::FindingSeverity;

    if findings.is_empty() {
        return Ok(());
    }
    let events = get_events_by_session_sqlite(pool, session_id)
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

#[cfg(test)]
mod chain_verification_tests;
