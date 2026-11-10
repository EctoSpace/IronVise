// ledger - module root.
//
// Sub-backends:
//   ledger::postgres - PostgreSQL (production default)
//   ledger::sqlite   - SQLite (zero-config local dev)
//
// All existing call-sites continue to work via the wildcard re-export of `postgres`.

pub mod postgres;
pub mod sqlite;

// `AppendError` is shared by the Postgres and SQLite backends. Defining it at
// the module root avoids cross-module coupling (sqlite depending on postgres
// or vice versa); both backends import it via `use super::AppendError;`.

/// Error type returned when appending an event to the ledger fails.
#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("session goal mismatch (possible redirect)")]
    GoalMismatch,
    #[error("unverified evidence: {0}")]
    UnverifiedEvidence(String),
}

/// Why a session failed verification, or that it passed.
///
/// A bare `false` was not enough. "Signature invalid" and "this event was
/// altered after it was signed" are the same outcome to a boolean and very
/// different facts to whoever is holding the ledger, and naming which event
/// gave way is the difference between a verdict and an accusation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionVerdict {
    /// Every signed event verified, and every unsigned one is of a kind some
    /// legitimate path writes unsigned (see [`UNSIGNED_BY_DESIGN`]).
    /// `unsigned` counts those, so a reader sees what the signatures do not
    /// cover instead of "all N signatures verified" over N+1 events.
    Verified { signatures: usize, unsigned: usize },
    /// The session records no public key and no event carries a signature.
    /// Every hash was checked and is consistent, but nothing binds these events
    /// to anyone: whoever holds the database could have written all of them.
    /// Not a pass: reporting this as `Verified { signatures: 0, unsigned: 0 }`
    /// would let clearing the key column's value turn an entire unsigned
    /// session into a clean "all signatures verified" result.
    Unsigned { events: usize },
    /// An event of a kind that is always signed when the server writes it has
    /// no signature. It was added after the fact, or its signature removed.
    MissingSignature { sequence: i64, kind: String },
    /// The session records a key, yet none of its events carries a signature.
    /// Every server path signs the first event it writes to a keyed session,
    /// so the signatures were removed, or the data predates per-event signing.
    NoSignatures { events: usize },
    /// The stored payload does not hash to the event's own `content_hash`
    /// under any accepted scheme. The event has been edited.
    PayloadHashMismatch { sequence: i64 },
    /// The signature is over a hash the event no longer has: valid in itself,
    /// but detached from the data. This is what a re-chained tamper looks
    /// like - see the 0.8.0 changelog, F-1.
    AlteredAfterSigning { sequence: i64 },
    /// The signature does not verify against the event's `content_hash`.
    BadSignature { sequence: i64 },
    /// Signed with a key that is not authorised for this session, or with one
    /// that a key-revocation event has withdrawn.
    UnauthorisedKey { sequence: i64 },
    /// The session was sealed with a different tip or length than it has now -
    /// events have been removed from the end (F-2). Only detectable for
    /// sessions sealed by 0.8.0 or later; earlier seals recorded nothing.
    TruncatedSinceSealing {
        sealed_events: i64,
        found_events: i64,
    },
}

impl SessionVerdict {
    pub fn is_verified(&self) -> bool {
        matches!(self, SessionVerdict::Verified { .. })
    }

    /// A stable machine name for the verdict, for APIs and the desktop app.
    /// The `Display` text is prose and free to improve; this is not.
    pub fn kind(&self) -> &'static str {
        match self {
            SessionVerdict::Verified { .. } => "verified",
            SessionVerdict::Unsigned { .. } => "unsigned",
            SessionVerdict::MissingSignature { .. } => "missing-signature",
            SessionVerdict::NoSignatures { .. } => "no-signatures",
            SessionVerdict::PayloadHashMismatch { .. } => "payload-hash-mismatch",
            SessionVerdict::AlteredAfterSigning { .. } => "altered-after-signing",
            SessionVerdict::BadSignature { .. } => "bad-signature",
            SessionVerdict::UnauthorisedKey { .. } => "unauthorised-key",
            SessionVerdict::TruncatedSinceSealing { .. } => "truncated-since-sealing",
        }
    }
}

/// Event kinds a client may append through `POST /api/sessions/{id}/events`.
/// The server has no key to sign them with, so they are stored unsigned: a
/// signature would attest to the server receiving a claim, not to it being
/// true. Anything else submitted there is refused, because it would be
/// indistinguishable in the chain from something the server did.
pub const CLIENT_ASSERTABLE_KINDS: [&str; 4] =
    ["observation", "thought", "prompt_input", "chat_message"];

/// Kinds the server itself writes without a signature, because the path that
/// writes them does not hold the session key: the orchestrator's cross-ledger
/// seal, and anchors, which are appended after the session (and its key) has
/// ended.
///
/// `approval_decision` is deliberately absent. Ledgers from earlier releases
/// hold an unsigned copy of every decision beside the signed one the loop
/// writes, so an unsigned approval passes only when the same session also
/// holds a signed decision for the same gate. A forged approval has no
/// signed twin.
pub const SERVER_UNSIGNED_KINDS: [&str; 2] = ["cross_ledger_seal", "anchor"];

/// Whether an unsigned event of this kind can have been written legitimately.
/// Every other kind is signed on every path that writes it, so an unsigned one
/// was added, or had its signature removed, after the fact: verification must
/// not skip unsigned events of any kind, or deleting signature rows would
/// undo the F-1 fix (the 0.8.0 changelog, F-4).
pub fn unsigned_by_design(kind: &str) -> bool {
    CLIENT_ASSERTABLE_KINDS.contains(&kind) || SERVER_UNSIGNED_KINDS.contains(&kind)
}

/// Which keys may sign the next event of a session.
///
/// An event is judged by the keys in force *before* it. A `KeyRotation` takes
/// effect only once its own signature has been checked, so it cannot authorise
/// the key that signed it: that is how an attacker with database access could
/// append a rotation to their own key and then any events they liked.
pub(crate) struct KeyLifecycle {
    authorised: std::collections::HashSet<String>,
    revoked: std::collections::HashSet<String>,
}

impl KeyLifecycle {
    pub(crate) fn new(session_public_key: Option<String>) -> Self {
        Self {
            authorised: session_public_key.into_iter().collect(),
            revoked: Default::default(),
        }
    }

    pub(crate) fn permits(&self, public_key: &str) -> bool {
        self.authorised.contains(public_key) && !self.revoked.contains(public_key)
    }

    /// Apply a verified event's effect on the key set.
    pub(crate) fn after(&mut self, payload: &crate::schema::EventPayload) {
        match payload {
            crate::schema::EventPayload::KeyRotation { new_public_key, .. } => {
                self.authorised.insert(new_public_key.clone());
            }
            crate::schema::EventPayload::KeyRevocation {
                revoked_public_key, ..
            } => {
                self.revoked.insert(revoked_public_key.clone());
                self.authorised.remove(revoked_public_key);
            }
            _ => {}
        }
    }
}

/// Per-session signature bookkeeping shared by both backends, so the rules
/// about unsigned events cannot drift apart between them.
#[derive(Default)]
pub(crate) struct SignatureCoverage {
    signed: usize,
    unsigned: usize,
    events: usize,
    /// Gates with a signed `approval_decision` in this session.
    signed_gates: std::collections::HashSet<String>,
    /// Unsigned `approval_decision`s, `(sequence, gate_id)`, checked at the end
    /// against `signed_gates`.
    unsigned_approvals: Vec<(i64, String)>,
}

impl SignatureCoverage {
    /// Record an event that carried a signature which verified.
    pub(crate) fn signed(&mut self, payload_json: &str) {
        self.events += 1;
        self.signed += 1;
        if let Some(gate) = approval_gate(payload_json) {
            self.signed_gates.insert(gate);
        }
    }

    /// Record an event with no signature. Fails at once if its kind is never
    /// legitimately unsigned.
    pub(crate) fn unsigned(
        &mut self,
        sequence: i64,
        payload_json: &str,
    ) -> Result<(), SessionVerdict> {
        self.events += 1;
        let kind = payload_kind(payload_json);
        if let Some(gate) = approval_gate(payload_json) {
            self.unsigned += 1;
            self.unsigned_approvals.push((sequence, gate));
            return Ok(());
        }
        let kind = kind.as_str();
        if !unsigned_by_design(kind) {
            return Err(SessionVerdict::MissingSignature {
                sequence,
                kind: kind.to_string(),
            });
        }
        self.unsigned += 1;
        Ok(())
    }

    /// The verdict once every event has been seen and nothing else failed.
    ///
    /// A session that records a key and has events, none of them signed, fails:
    /// every server path signs the first event it writes to a keyed session
    /// (the prompt, the hook's first action, the orchestrator's genesis), so
    /// "no signatures at all" means they were removed, or the data predates
    /// per-event signing, and either way nothing here is authenticated.
    pub(crate) fn finish(self, has_key: bool) -> SessionVerdict {
        if let Some((sequence, _)) = self
            .unsigned_approvals
            .iter()
            .find(|(_, gate)| !self.signed_gates.contains(gate))
        {
            return SessionVerdict::MissingSignature {
                sequence: *sequence,
                kind: "approval_decision".into(),
            };
        }
        if self.events > 0 && self.signed == 0 {
            return if has_key {
                SessionVerdict::NoSignatures {
                    events: self.events,
                }
            } else {
                SessionVerdict::Unsigned {
                    events: self.events,
                }
            };
        }
        SessionVerdict::Verified {
            signatures: self.signed,
            unsigned: self.unsigned,
        }
    }
}

/// The gate of an `approval_decision` payload, or `None` for anything else.
fn approval_gate(payload_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload_json).ok()?;
    if v.get("type")?.as_str()? != "approval_decision" {
        return None;
    }
    Some(v.get("gate_id")?.as_str()?.to_string())
}

/// The `type` tag of a stored payload, or "" when it cannot be read (which
/// `unsigned_by_design` treats as a kind that must be signed).
pub(crate) fn payload_kind(payload_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(payload_json)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
        .unwrap_or_default()
}

impl std::fmt::Display for SessionVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionVerdict::Verified {
                signatures,
                unsigned: 0,
            } => {
                write!(f, "all {signatures} event signatures verified")
            }
            SessionVerdict::Verified {
                signatures,
                unsigned,
            } => write!(
                f,
                "all {signatures} event signatures verified; {unsigned} further event(s) \
                 unsigned by design (client-asserted, seals, anchors, pre-0.8 approval \
                 copies) and covered by hashes only"
            ),
            SessionVerdict::Unsigned { events } => write!(
                f,
                "no public key and no signatures: the {events} event(s) hash consistently, \
                 but nothing binds them to anyone - whoever holds the database could have \
                 written them"
            ),
            SessionVerdict::NoSignatures { events } => write!(
                f,
                "the session records a signing key but none of its {events} event(s) is \
                 signed - the signatures were removed, or the session predates per-event \
                 signing"
            ),
            SessionVerdict::MissingSignature { sequence, kind } => write!(
                f,
                "event {sequence}: a `{kind}` event with no signature, though the server \
                 always signs that kind - it was added, or its signature removed, after \
                 the fact"
            ),
            SessionVerdict::PayloadHashMismatch { sequence } => write!(
                f,
                "event {sequence}: stored payload does not hash to its content_hash \
                 - the event has been edited"
            ),
            SessionVerdict::AlteredAfterSigning { sequence } => write!(
                f,
                "event {sequence}: the signature covers a hash this event no longer \
                 has - it was altered after signing"
            ),
            SessionVerdict::BadSignature { sequence } => {
                write!(f, "event {sequence}: signature does not verify")
            }
            SessionVerdict::UnauthorisedKey { sequence } => write!(
                f,
                "event {sequence}: signed with a key that is not authorised for \
                 this session (or was revoked)"
            ),
            SessionVerdict::TruncatedSinceSealing {
                sealed_events,
                found_events,
            } => write!(
                f,
                "session was sealed with {sealed_events} events but has {found_events} \
                 - events have been removed since sealing"
            ),
        }
    }
}

// Re-export the Postgres free-functions so all `crate::ledger::foo` call-sites
// continue to compile without changes.
pub use postgres::{
    PostgresLedger, append_event, create_session, create_session_with_did, ensure_genesis,
    find_cached_http_get, finish_session, finish_session_if_running, get_dangling_actions,
    get_event_by_id, get_events, get_events_by_session, get_latest, get_session_did, list_sessions,
    list_sessions_filtered, mark_action_completed, mark_action_executing, mark_action_failed,
    store_enclave_attestation, verify_chain, verify_findings, verify_goal_hash,
    verify_session_signatures,
};

// Expose the trait-based backend for DI consumers.
pub use ledger_api::{LedgerAdmin, LedgerBackend};

#[cfg(test)]
mod verdict_tests;
