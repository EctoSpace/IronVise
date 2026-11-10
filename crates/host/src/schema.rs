use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Completed,
    Failed,
    Aborted,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Running => "running",
            SessionStatus::Completed => "completed",
            SessionStatus::Failed => "failed",
            SessionStatus::Aborted => "aborted",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditFinding {
    pub severity: FindingSeverity,
    pub title: String,
    pub evidence: String,
    pub recommendation: String,
    /// Ledger sequence numbers that support this finding. Required for high/critical.
    #[serde(default)]
    pub evidence_sequence: Vec<i64>,
    /// Exact substrings from those observations that support the evidence.
    #[serde(default)]
    pub evidence_quotes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, FromRow)]
pub struct SessionRow {
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
    pub session_did: Option<String>,
    /// JSON-serialised `EnclaveAttestation` captured during the session, if any.
    pub enclave_attestation_json: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    Genesis {
        message: String,
        /// Random hex nonce ensuring each ledger's genesis event is unique.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        /// Hex-encoded Ed25519 verifying key of the session that owns this ledger.
        /// Binds the genesis event to a specific signing key so it cannot be replayed
        /// into a different session with a different key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_public_key: Option<String>,
    },
    /// The user's original prompt / audit goal.
    PromptInput {
        content: String,
    },
    Thought {
        content: String,
    },
    /// Schema validation error (e.g. missing justification).
    SchemaError {
        message: String,
        attempt: u32,
        max_attempts: u32,
    },
    /// Circuit breaker tripped: too many consecutive errors of the same kind.
    CircuitBreaker {
        reason: String,
        consecutive_failures: u32,
    },
    Action {
        name: String,
        params: serde_json::Value,
    },
    Observation {
        content: String,
    },
    /// Human-in-the-loop: approval requested for an action.
    ApprovalRequired {
        gate_id: String,
        action_name: String,
        action_params_summary: String,
    },
    /// Human-in-the-loop: decision recorded.
    ApprovalDecision {
        gate_id: String,
        approved: bool,
        reason: Option<String>,
    },
    /// Multi-agent: cross-ledger seal committing all sub-agent ledger tips.
    CrossLedgerSeal {
        seal_hash: String,
        session_ids: Vec<Uuid>,
        session_tip_hashes: Vec<String>,
    },
    /// OpenTimestamps anchor: the ledger tip was submitted to the Bitcoin timechain.
    Anchor {
        ledger_tip_hash: String,
        ots_proof_hex: String,
        /// Filled once the OTS stamp is confirmed in a Bitcoin block.
        bitcoin_block_height: Option<u64>,
    },
    /// Automatic signing-key rotation: a new Ed25519 keypair has been generated.
    /// All events after this one are signed with `new_public_key`.
    /// Verifiers should use this event to determine which public key covers each
    /// segment of the audit trail (events before this rotation vs. after).
    KeyRotation {
        /// Hex-encoded Ed25519 public key that will be used from this point onward.
        new_public_key: String,
        /// Monotonically increasing rotation counter (1 = first rotation, 2 = second, …).
        rotation_index: u64,
    },
    /// Explicit revocation of an Ed25519 signing key.
    /// Once recorded, verifiers MUST reject any event signed by the revoked
    /// key that has a sequence number greater than this event's sequence.
    KeyRevocation {
        /// Hex-encoded Ed25519 public key being revoked.
        revoked_public_key: String,
        /// Human-readable reason for revocation (e.g. "key compromise", "rotation").
        reason: String,
    },
    /// W3C Verifiable Credential JWT issued when the session completes.
    /// The JWT is signed with the session Ed25519 key (EdDSA) and encodes goal,
    /// policy hash, DID, session ID, and completion timestamp.
    VerifiableCredential {
        /// The full JWT string: `header.payload.signature` (or `header.payload.` when unsigned).
        vc_jwt: String,
    },
    /// Direct LLM chat message (no agent loop). Logged so the observer can
    /// display user↔LLM interactions in real-time.
    ChatMessage {
        role: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        backend: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
    },

    // ── Control decisions ────────────────────────────────────────────────────
    //
    // GuardDenial and TripwireRejection are typed events rather than
    // `Thought { content: "Guard denied: …" }` prose, because enumerating
    // refusals by pattern-matching a string prefix is not an audit trail
    // anyone can rely on. EU AI Act Article 12(2)(a) asks for records of
    // "events relevant for identifying situations that may result in the
    // system presenting a risk" - a refused action is the clearest such
    // event a guarded system produces, so it gets a type.
    //
    // Both variants are appended BEFORE the action could execute, so they record
    // something that did not happen. See docs/compliance/eu-ai-act-article12.md.
    /// The semantic guard refused a proposed action.
    GuardDenial {
        /// Name of the refused action, when the intent parsed far enough to have one.
        #[serde(skip_serializing_if = "Option::is_none")]
        action: Option<String>,
        /// Reason reported by the guard.
        reason: String,
        /// `true` when the decision prevented execution, `false` when the action
        /// was only flagged and allowed to proceed. Recorded explicitly because a
        /// log line saying "denied" is not by itself evidence that nothing ran.
        enforced: bool,
    },
    /// A tripwire, policy rule, or prompt scan rejected a proposed action.
    TripwireRejection {
        /// Name of the rejected action; `None` for prompt-level scans, which run
        /// before any action exists.
        #[serde(skip_serializing_if = "Option::is_none")]
        action: Option<String>,
        /// Reason reported by the rejecting check.
        reason: String,
        /// Where in the pipeline the rejection happened: `prompt_scan`,
        /// `validation`, or `policy`.
        stage: String,
        /// `true` when the decision prevented execution. See `GuardDenial::enforced`.
        enforced: bool,
    },
    /// What a tool returned, by hash: evidence of exactly which data the agent
    /// received. Recorded after the call; the data itself is never stored.
    DataReceipt {
        /// The tool as the client names it (`Read`, `mcp:files/read_text_file`).
        tool: String,
        /// What was read, when the call names it: a path, a URL, a query.
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        /// The client's id for the call (`tool_use_id`, the JSON-RPC id), which
        /// links the receipt to the decision recorded before the call.
        #[serde(skip_serializing_if = "Option::is_none")]
        call_id: Option<String>,
        /// SHA-256 of the whole response as canonical JSON (keys sorted, compact).
        response_sha256: String,
        /// SHA-256 of each text the agent received (file contents, command
        /// output, page text, MCP text blocks): what a holder of the data can
        /// check with `sha256sum`.
        text_sha256: Vec<String>,
        /// Total UTF-8 bytes of those texts.
        text_bytes: u64,
    },
}

#[derive(Clone, Debug)]
pub struct LedgerEventRow {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub payload: EventPayload,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AppendedEvent {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SnapshotRow {
    pub id: Uuid,
    pub sequence: i64,
    pub state_hash: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RestoredState {
    pub snapshot_sequence: i64,
    pub snapshot_payload: serde_json::Value,
    pub replayed_events: Vec<LedgerEventRow>,
}

// ── Drift gate ────────────────────────────────────────────────────────────────
//
// The `EventPayload` enum, `docs/reference/schema.md`, and the GUI's webhook filter list
// drifted apart once already, and the failure was silent in both directions:
// the docs described a webhook default that was right while the GUI offered ten
// filter names of which seven did not exist, so a webhook configured through the
// UI matched nothing and forwarded no events to the SIEM. Nothing failed; the
// SIEM was just quiet.
//
// These tests derive the authoritative lists from the Rust source and fail when
// either the documentation or the GUI diverges.

#[cfg(test)]
mod drift;
