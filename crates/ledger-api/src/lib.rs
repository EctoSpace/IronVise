//! # ledger-api
//!
//! Minimal, backend-agnostic trait surface for the IronVise cryptographic ledger.
//!
//! Consumers (agents, servers, tests) depend on *this* crate rather than directly on
//! any concrete backend.  The host crate ships two implementations behind the
//! `LedgerBackend` trait:
//!
//! - `ledger::postgres::PostgresLedger`  - production Postgres
//! - `ledger::sqlite::SqliteLedger`      - zero-config local SQLite
//!
//! ## Example
//! ```rust,ignore
//! use std::sync::Arc;
//! use ledger_api::{LedgerBackend, NewSession};
//!
//! async fn run(ledger: Arc<dyn LedgerBackend>) {
//!     let (session, _key) = ledger
//!         .create_session(NewSession { goal: "audit example.com".into(), ..Default::default() })
//!         .await
//!         .unwrap();
//!     println!("Session {} created", session.id);
//! }
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Errors that can occur when interacting with the ledger backend.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("session goal hash mismatch - possible prompt-injection redirect")]
    GoalMismatch,
    #[error("unverified evidence: {0}")]
    UnverifiedEvidence(String),
    #[error("chain integrity failure at sequence {0}")]
    ChainBroken(i64),
    #[error("backend not supported")]
    Unsupported,
}

/// Raw payload stored in an event.  Passed through as JSON so the trait stays
/// independent from the concrete `EventPayload` enum defined in the host crate.
pub type RawPayload = serde_json::Value;

/// A single ledger event row as returned from any backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEvent {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub payload: RawPayload,
    pub created_at: DateTime<Utc>,
}

/// Session record returned from any backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub goal: String,
    pub goal_hash: Option<String>,
    pub status: String,
    pub llm_backend: Option<String>,
    pub llm_model: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub policy_hash: Option<String>,
    pub session_public_key: Option<String>,
    /// W3C Decentralized Identifier associated with this agent session (phase 1: stored as-is).
    pub session_did: Option<String>,
}

/// Parameters for creating a new session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewSession {
    pub goal: String,
    pub llm_backend: String,
    pub llm_model: String,
    pub policy_hash: Option<String>,
    /// Optional DID to associate with this session.
    pub session_did: Option<String>,
}

/// Result of a successful event append.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendResult {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

/// Minimal, cursor-style backend interface for the IronVise cryptographic ledger.
///
/// All methods are async and return `Result<_, LedgerError>`.  Implementations
/// are expected to be `Send + Sync` so they can be wrapped in `Arc<dyn LedgerBackend>`.
///
/// Phase-1 surface covers the operations required for event appending, session
/// lifecycle, chain verification, and compliance sealing.  Further operations
/// (batch queries, metric snapshots, cross-ledger seals) may be added as new
/// methods with default no-op implementations to preserve backward compatibility.
#[async_trait]
pub trait LedgerBackend: Send + Sync {
    /// Append an arbitrary JSON payload to the chain.
    ///
    /// When `session_id` and `session_goal` are both provided the backend MUST
    /// verify that `session_goal` matches the stored `goal_hash` before writing.
    /// `signing_key_bytes` is the raw 32-byte seed of the session Ed25519 key; when
    /// present the backend signs the `content_hash` and stores the signature.
    async fn append_event(
        &self,
        payload: RawPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key_bytes: Option<&[u8]>,
    ) -> Result<AppendResult, LedgerError>;

    /// Create a new session record.  Returns the session row and the raw 32-byte
    /// Ed25519 signing-key seed so callers can sign subsequent events.
    async fn create_session(&self, params: NewSession) -> Result<(Session, Vec<u8>), LedgerError>;

    /// Seal (finish) a session with the given status string (`"completed"`, `"failed"`, etc.).
    async fn seal_session(&self, session_id: Uuid, status: &str) -> Result<(), LedgerError>;

    /// Return all events belonging to `session_id` in ascending sequence order.
    async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<LedgerEvent>, LedgerError>;

    /// Return all sessions, newest first.
    async fn list_sessions(&self) -> Result<Vec<Session>, LedgerError>;

    /// Verify the hash-chain between two sequence numbers (inclusive).
    /// Returns `true` if every link is intact.
    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, LedgerError>;

    /// Generate a compliance proof bundle (implementation-defined bytes - may be
    /// a Merkle proof, a signed JSON, a ZK receipt, or a simple digest).
    async fn prove_compliance(&self, session_id: Uuid) -> Result<Vec<u8>, LedgerError>;
}

/// Extended administrative interface for ledger backends.
///
/// Covers operational methods beyond the core read/write/integrity surface:
/// event streaming, session maintenance, and initialization.
///
/// Separated from [`LedgerBackend`] so that minimal consumers (agents, tests)
/// need only the core trait, while the server and CLI can require the full
/// administrative surface.
#[async_trait]
pub trait LedgerAdmin: LedgerBackend {
    /// Return the latest event's `(sequence, content_hash)`.
    /// Returns `None` if the chain is empty.
    async fn get_latest(&self) -> Result<Option<(i64, String)>, LedgerError>;

    /// Ensure the genesis event exists, creating it if the chain is empty.
    /// Idempotent - returns the genesis event's metadata on every call.
    async fn ensure_genesis(&self) -> Result<AppendResult, LedgerError>;

    /// Return events with `id > after_id`, optionally filtered to a session.
    /// Results are ordered by `id ASC` and capped at an implementation-defined
    /// batch size (typically 100).  Used for SSE streaming.
    async fn stream_events_since(
        &self,
        after_id: i64,
        session_id: Option<Uuid>,
    ) -> Result<Vec<LedgerEvent>, LedgerError>;

    /// Mark sessions that have been `"running"` for longer than `max_age_minutes`
    /// as `"failed"`.  Returns the number of sessions reaped.
    async fn reap_zombie_sessions(&self, max_age_minutes: i64) -> Result<u64, LedgerError>;

    /// List sessions with optional status filter, pagination via `limit`/`offset`.
    /// Returns sessions in reverse chronological order.
    async fn list_sessions_filtered(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Session>, LedgerError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // These types are the wire contract shared by the host, the Tauri GUI, and
    // the Python and TypeScript SDKs. Renaming a field or changing how an
    // absent one is handled breaks those consumers silently - nothing here
    // fails to compile when the JSON shape shifts. Pin the shape instead.

    fn sample_event() -> LedgerEvent {
        LedgerEvent {
            id: 42,
            sequence: 7,
            previous_hash: "a".repeat(64),
            content_hash: "b".repeat(64),
            payload: serde_json::json!({"kind": "observation", "data": "x"}),
            created_at: DateTime::parse_from_rfc3339("2026-08-08T12:00:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
        }
    }

    fn sample_session() -> Session {
        Session {
            id: Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("valid uuid"),
            goal: "audit example.com".into(),
            goal_hash: Some("c".repeat(64)),
            status: "running".into(),
            llm_backend: Some("ollama".into()),
            llm_model: Some("qwen2.5:0.5b".into()),
            created_at: DateTime::parse_from_rfc3339("2026-08-08T12:00:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            finished_at: None,
            policy_hash: Some("d".repeat(64)),
            session_public_key: Some("e".repeat(64)),
            session_did: Some("did:key:z6Mk".into()),
        }
    }

    #[test]
    fn ledger_event_survives_a_json_round_trip() {
        let original = sample_event();
        let decoded: LedgerEvent =
            serde_json::from_str(&serde_json::to_string(&original).expect("serialize"))
                .expect("deserialize");

        assert_eq!(decoded.id, original.id);
        assert_eq!(decoded.sequence, original.sequence);
        assert_eq!(decoded.previous_hash, original.previous_hash);
        assert_eq!(decoded.content_hash, original.content_hash);
        assert_eq!(decoded.payload, original.payload);
        assert_eq!(decoded.created_at, original.created_at);
    }

    #[test]
    fn session_survives_a_json_round_trip() {
        let original = sample_session();
        let decoded: Session =
            serde_json::from_str(&serde_json::to_string(&original).expect("serialize"))
                .expect("deserialize");

        assert_eq!(decoded.id, original.id);
        assert_eq!(decoded.goal, original.goal);
        assert_eq!(decoded.goal_hash, original.goal_hash);
        assert_eq!(decoded.status, original.status);
        assert_eq!(decoded.finished_at, None);
        assert_eq!(decoded.session_did, original.session_did);
    }

    #[test]
    fn append_result_survives_a_json_round_trip() {
        let original = AppendResult {
            id: 1,
            sequence: 0,
            previous_hash: "0".repeat(64),
            content_hash: "f".repeat(64),
            created_at: Utc::now(),
        };
        let decoded: AppendResult =
            serde_json::from_str(&serde_json::to_string(&original).expect("serialize"))
                .expect("deserialize");
        assert_eq!(decoded.sequence, original.sequence);
        assert_eq!(decoded.content_hash, original.content_hash);
    }

    #[test]
    fn ledger_event_uses_the_documented_snake_case_field_names() {
        let value = serde_json::to_value(sample_event()).expect("serialize");
        let object = value.as_object().expect("event serializes to an object");

        let expected = [
            "id",
            "sequence",
            "previous_hash",
            "content_hash",
            "payload",
            "created_at",
        ];
        for key in expected {
            assert!(
                object.contains_key(key),
                "LedgerEvent lost the {key:?} field"
            );
        }
        assert_eq!(
            object.len(),
            expected.len(),
            "LedgerEvent gained an undocumented field: {:?}",
            object.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn session_uses_the_documented_snake_case_field_names() {
        let value = serde_json::to_value(sample_session()).expect("serialize");
        let object = value.as_object().expect("session serializes to an object");

        let expected = [
            "id",
            "goal",
            "goal_hash",
            "status",
            "llm_backend",
            "llm_model",
            "created_at",
            "finished_at",
            "policy_hash",
            "session_public_key",
            "session_did",
        ];
        for key in expected {
            assert!(object.contains_key(key), "Session lost the {key:?} field");
        }
        assert_eq!(
            object.len(),
            expected.len(),
            "Session gained an undocumented field: {:?}",
            object.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn absent_optional_fields_decode_as_none() {
        // SDKs and older servers omit optionals rather than sending null. If
        // serde ever starts demanding them, every such client breaks.
        let json = r#"{
            "id": "11111111-2222-3333-4444-555555555555",
            "goal": "audit example.com",
            "status": "running",
            "created_at": "2026-08-08T12:00:00Z"
        }"#;
        let session: Session = serde_json::from_str(json).expect("optionals may be omitted");
        assert_eq!(session.goal_hash, None);
        assert_eq!(session.llm_backend, None);
        assert_eq!(session.finished_at, None);
        assert_eq!(session.session_did, None);
    }

    #[test]
    fn explicit_nulls_decode_as_none() {
        let json = r#"{
            "id": "11111111-2222-3333-4444-555555555555",
            "goal": "g",
            "goal_hash": null,
            "status": "running",
            "llm_backend": null,
            "llm_model": null,
            "created_at": "2026-08-08T12:00:00Z",
            "finished_at": null,
            "policy_hash": null,
            "session_public_key": null,
            "session_did": null
        }"#;
        let session: Session = serde_json::from_str(json).expect("nulls decode as None");
        assert_eq!(session.policy_hash, None);
        assert_eq!(session.session_public_key, None);
    }

    #[test]
    fn new_session_default_is_empty_rather_than_panicking() {
        // The doc example on this crate relies on `..Default::default()`.
        let params = NewSession {
            goal: "audit example.com".into(),
            ..Default::default()
        };
        assert_eq!(params.goal, "audit example.com");
        assert!(params.llm_backend.is_empty());
        assert!(params.llm_model.is_empty());
        assert_eq!(params.policy_hash, None);
        assert_eq!(params.session_did, None);
    }

    #[test]
    fn arbitrary_json_payloads_round_trip_intact() {
        // `payload` is deliberately untyped so backends stay independent of the
        // host's EventPayload enum. Nested structure must survive unchanged.
        let payload = serde_json::json!({
            "nested": {"array": [1, 2, {"deep": true}], "unicode": "überprüft ✅"},
            "null_value": null,
            "big": 9_007_199_254_740_993_i64,
        });
        let mut event = sample_event();
        event.payload = payload.clone();

        let decoded: LedgerEvent =
            serde_json::from_str(&serde_json::to_string(&event).expect("serialize"))
                .expect("deserialize");
        assert_eq!(decoded.payload, payload);
    }

    /// Both traits are documented as usable behind `Arc<dyn _>`. That only holds
    /// while they stay object-safe; adding a generic method would silently break
    /// every consumer. This function fails to compile if that happens.
    #[allow(dead_code)]
    fn assert_traits_are_object_safe(backend: &dyn LedgerBackend, admin: &dyn LedgerAdmin) {
        let _: &dyn LedgerBackend = backend;
        let _: &dyn LedgerAdmin = admin;
    }

    #[test]
    fn error_messages_are_actionable() {
        assert_eq!(
            LedgerError::Database("connection refused".into()).to_string(),
            "database error: connection refused"
        );
        assert_eq!(
            LedgerError::ChainBroken(17).to_string(),
            "chain integrity failure at sequence 17"
        );
        assert_eq!(
            LedgerError::Unsupported.to_string(),
            "backend not supported"
        );
    }

    #[test]
    fn goal_mismatch_names_the_attack_it_detects() {
        // This message is what an operator sees when the guard catches a
        // prompt-injection redirect; it must stay explicit about the cause.
        let message = LedgerError::GoalMismatch.to_string();
        assert!(message.contains("goal hash mismatch"), "got: {message}");
        assert!(message.contains("prompt-injection"), "got: {message}");
    }

    #[test]
    fn serialize_and_unverified_evidence_errors_include_their_cause() {
        assert_eq!(
            LedgerError::Serialize("missing field `goal`".into()).to_string(),
            "serialization error: missing field `goal`"
        );
        assert_eq!(
            LedgerError::UnverifiedEvidence("no issuer signature".into()).to_string(),
            "unverified evidence: no issuer signature"
        );
    }

    #[test]
    fn append_result_uses_the_documented_snake_case_field_names() {
        let value = serde_json::to_value(AppendResult {
            id: 1,
            sequence: 0,
            previous_hash: "0".repeat(64),
            content_hash: "f".repeat(64),
            created_at: Utc::now(),
        })
        .expect("serialize");
        let object = value
            .as_object()
            .expect("append result serializes to an object");

        let expected = [
            "id",
            "sequence",
            "previous_hash",
            "content_hash",
            "created_at",
        ];
        for key in expected {
            assert!(
                object.contains_key(key),
                "AppendResult lost the {key:?} field"
            );
        }
        assert_eq!(
            object.len(),
            expected.len(),
            "AppendResult gained an undocumented field: {:?}",
            object.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn new_session_round_trips_through_json_with_documented_field_names() {
        let original = NewSession {
            goal: "audit example.com".into(),
            llm_backend: "ollama".into(),
            llm_model: "qwen2.5:0.5b".into(),
            policy_hash: Some("d".repeat(64)),
            session_did: Some("did:key:z6Mk".into()),
        };
        let value = serde_json::to_value(&original).expect("serialize");
        let object = value
            .as_object()
            .expect("new session serializes to an object");

        let expected = [
            "goal",
            "llm_backend",
            "llm_model",
            "policy_hash",
            "session_did",
        ];
        for key in expected {
            assert!(
                object.contains_key(key),
                "NewSession lost the {key:?} field"
            );
        }
        assert_eq!(
            object.len(),
            expected.len(),
            "NewSession gained an undocumented field: {:?}",
            object.keys().collect::<Vec<_>>()
        );

        let decoded: NewSession = serde_json::from_value(value).expect("deserialize");
        assert_eq!(decoded.goal, original.goal);
        assert_eq!(decoded.llm_backend, original.llm_backend);
        assert_eq!(decoded.llm_model, original.llm_model);
        assert_eq!(decoded.policy_hash, original.policy_hash);
        assert_eq!(decoded.session_did, original.session_did);
    }

    #[test]
    fn session_round_trip_preserves_a_present_finished_at() {
        let mut original = sample_session();
        original.status = "completed".into();
        original.finished_at = Some(
            DateTime::parse_from_rfc3339("2026-08-08T13:30:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
        );

        let decoded: Session =
            serde_json::from_str(&serde_json::to_string(&original).expect("serialize"))
                .expect("deserialize");
        assert_eq!(decoded.finished_at, original.finished_at);
        assert_eq!(decoded.status, "completed");
    }

    #[test]
    fn session_deserializes_with_unknown_fields_present_for_forward_compatibility() {
        // A newer SDK or server may add fields this build does not know about yet;
        // deserialization must ignore them rather than fail.
        let json = r#"{
            "id": "11111111-2222-3333-4444-555555555555",
            "goal": "g",
            "status": "running",
            "created_at": "2026-08-08T12:00:00Z",
            "from_the_future": "surprise"
        }"#;
        let session: Session =
            serde_json::from_str(json).expect("unknown fields should be ignored");
        assert_eq!(session.goal, "g");
    }

    #[test]
    fn ledger_event_deserialize_fails_when_a_required_field_is_missing() {
        // Guards against accidentally making a required field optional without
        // also updating every SDK that relies on it always being present.
        let json = r#"{
            "id": 1,
            "sequence": 0,
            "previous_hash": "0",
            "payload": {},
            "created_at": "2026-08-08T12:00:00Z"
        }"#;
        assert!(serde_json::from_str::<LedgerEvent>(json).is_err());
    }
}
