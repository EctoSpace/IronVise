use sha2::{Digest, Sha256};

pub const GENESIS_PREVIOUS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute a hex-encoded hash of `input`.
///
/// When the `hash-blake3` feature is enabled, uses BLAKE3 (256-bit);
/// otherwise falls back to SHA-256.  Both produce 64-char hex strings.
#[inline]
pub fn sha256_hex(input: &[u8]) -> String {
    #[cfg(feature = "hash-blake3")]
    {
        let hash = blake3::hash(input);
        hash.to_hex().to_string()
    }
    #[cfg(not(feature = "hash-blake3"))]
    {
        let hash = Sha256::digest(input);
        hex::encode(hash)
    }
}

/// Compute a hex-encoded SHA-256 hash (always SHA-256, independent of
/// `hash-blake3`).  Used during chain verification to attempt legacy
/// fallback when the current hash algorithm doesn't match.
#[inline]
pub fn sha256_hex_legacy(input: &[u8]) -> String {
    let hash = Sha256::digest(input);
    hex::encode(hash)
}

/// A session goal's `goal_hash`: always SHA-256, whatever the chain hash is.
/// It names the goal to relying parties, and every verifier (`verify-cert`,
/// the browser page, the SDKs) recomputes it as SHA-256 (docs/reference/elc-spec.md).
/// Must stay SHA-256 under `hash-blake3` too: following the chain hash there
/// instead would make every certificate such a build exports fail its
/// goal-hash check against those verifiers.
pub fn goal_hash(goal: &str) -> String {
    sha256_hex_legacy(goal.as_bytes())
}

/// Whether `stored` is `goal`'s hash: SHA-256, or, in a `hash-blake3` build,
/// the BLAKE3 hash recorded by sessions that predate [`goal_hash`] always
/// being SHA-256, so those older sessions keep verifying.
pub fn goal_hash_matches(stored: &str, goal: &str) -> bool {
    if stored == goal_hash(goal) {
        return true;
    }
    #[cfg(feature = "hash-blake3")]
    if stored == sha256_hex(goal.as_bytes()) {
        return true;
    }
    false
}

/// SHA-256(len(a) || a || len(b) || b) - used by the attestation layer to
/// commit to a prompt/response pair without exposing either value directly.
///
/// Each input is prefixed with its 8-byte big-endian length to prevent
/// boundary-manipulation collisions (e.g. shifting bytes between `a` and `b`).
#[inline]
pub fn sha256_pair(a: &[u8], b: &[u8]) -> String {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update((a.len() as u64).to_be_bytes());
    hasher.update(a);
    hasher.update((b.len() as u64).to_be_bytes());
    hasher.update(b);
    hex::encode(hasher.finalize())
}

/// Content-hash scheme identifiers, newest first.
///
/// The ledger's on-disk `content_hash` column has gone through several input
/// layouts. Verification must accept all of them so pre-migration ledgers
/// still verify; **writes must only ever use the newest scheme** ([`HashScheme::V2`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashScheme {
    /// Canonical scheme (v0.8.0+): version-tagged input that always binds the
    /// creation timestamp and the session id (empty string when the event has
    /// no session). See [`content_hash_input_v2`].
    V2,
    /// Pre-0.8 input with both session_id and created_at appended.
    V1SessionTimestamp,
    /// Pre-0.8 input with session_id but no timestamp (and the
    /// Postgres hot path before canonicalization).
    V1SessionOnly,
    /// Pre-0.8 input with created_at but no session_id (SQLite era).
    V1TimestampOnly,
    /// Original input: previous_hash, sequence, and payload only.
    V1Legacy,
}

/// Version tag prepended to canonical (v2) hash inputs. Provides domain
/// separation: no v2 input can collide with any v1 input because v1 inputs
/// always start with a hex-encoded previous hash, never with this tag.
pub const HASH_SCHEME_V2_TAG: &[u8] = b"ELv2\x00";

/// Canonical (v2) content-hash input.
///
/// Layout (fields joined by single null bytes, after the version tag):
///
/// ```text
/// "ELv2\0" previous_hash \0 sequence \0 payload_json \0 session_id \0 created_at
/// ```
///
/// - `session_id` is the empty string when the event has no session.
/// - `created_at` MUST be the RFC 3339 rendering of the event's stored
///   timestamp, truncated to microseconds before formatting (both database
///   backends store at most microsecond precision, so this is what a verifier
///   reading the row back will reproduce).
///
/// Every field is always present, so the layout is unambiguous - unlike the
/// v1 layouts, where optional trailing fields made `(sid=None, ts=Some(x))`
/// and `(sid=Some(x), ts=None)` indistinguishable. The separator relies on
/// no field holding a raw NUL byte, which holds for what the ledger stores:
/// `payload_json` is serialized JSON, which writes a NUL as `\u0000`, and
/// `session_id` is a UUID.
pub fn content_hash_input_v2(
    previous_hash: &str,
    sequence: i64,
    payload_json: &str,
    session_id: Option<&str>,
    created_at: &str,
) -> Vec<u8> {
    let seq_str = sequence.to_string();
    let sid = session_id.unwrap_or("");
    let mut out = Vec::with_capacity(
        HASH_SCHEME_V2_TAG.len()
            + previous_hash.len()
            + seq_str.len()
            + payload_json.len()
            + sid.len()
            + created_at.len()
            + 4,
    );
    out.extend_from_slice(HASH_SCHEME_V2_TAG);
    out.extend_from_slice(previous_hash.as_bytes());
    out.push(0x00);
    out.extend_from_slice(seq_str.as_bytes());
    out.push(0x00);
    out.extend_from_slice(payload_json.as_bytes());
    out.push(0x00);
    out.extend_from_slice(sid.as_bytes());
    out.push(0x00);
    out.extend_from_slice(created_at.as_bytes());
    out
}

/// Compute the canonical (v2) content hash. This is the ONLY function write
/// paths may use; the v1 variants exist solely so old ledgers keep verifying.
pub fn compute_content_hash_v2(
    previous_hash: &str,
    sequence: i64,
    payload_json: &str,
    session_id: Option<&str>,
    created_at: &str,
) -> String {
    sha256_hex(&content_hash_input_v2(
        previous_hash,
        sequence,
        payload_json,
        session_id,
        created_at,
    ))
}

/// Verify a stored content hash against every supported scheme, newest first.
///
/// Returns the scheme that matched, or `None` when the stored hash matches no
/// scheme (i.e. the event is tampered or corrupted). All comparisons are
/// constant-time. When the `hash-blake3` feature is enabled, each scheme is
/// additionally checked against its SHA-256 digest so ledgers written before
/// a BLAKE3 migration keep verifying.
pub fn verify_content_hash_any_scheme(
    previous_hash: &str,
    sequence: i64,
    payload_json: &str,
    session_id: Option<&str>,
    created_at: Option<&str>,
    stored_hash: &str,
) -> Option<HashScheme> {
    use subtle::ConstantTimeEq;

    let matches_input = |input: &[u8]| -> bool {
        let current: bool = stored_hash
            .as_bytes()
            .ct_eq(sha256_hex(input).as_bytes())
            .into();
        if current {
            return true;
        }
        // Pre-BLAKE3-migration fallback: only meaningful when the current
        // algorithm is not already SHA-256.
        #[cfg(feature = "hash-blake3")]
        {
            let legacy: bool = stored_hash
                .as_bytes()
                .ct_eq(sha256_hex_legacy(input).as_bytes())
                .into();
            if legacy {
                return true;
            }
        }
        false
    };

    if let Some(ts) = created_at {
        // v2 canonical.
        let v2 = content_hash_input_v2(previous_hash, sequence, payload_json, session_id, ts);
        if matches_input(&v2) {
            return Some(HashScheme::V2);
        }
        // v1: session + timestamp.
        if session_id.is_some() {
            let v1_both =
                content_hash_input(previous_hash, sequence, payload_json, session_id, Some(ts));
            if matches_input(&v1_both) {
                return Some(HashScheme::V1SessionTimestamp);
            }
        }
        // v1: timestamp only.
        let v1_ts = content_hash_input(previous_hash, sequence, payload_json, None, Some(ts));
        if matches_input(&v1_ts) {
            return Some(HashScheme::V1TimestampOnly);
        }
    }
    // v1: session only.
    if session_id.is_some() {
        let v1_sid = content_hash_input(previous_hash, sequence, payload_json, session_id, None);
        if matches_input(&v1_sid) {
            return Some(HashScheme::V1SessionOnly);
        }
    }
    // v1 legacy: neither bound.
    let v1_legacy = content_hash_input(previous_hash, sequence, payload_json, None, None);
    if matches_input(&v1_legacy) {
        return Some(HashScheme::V1Legacy);
    }
    None
}

/// Pre-0.8 (v1) content-hash input. Retained ONLY so that
/// [`verify_content_hash_any_scheme`] can verify ledgers written before the
/// canonical v2 scheme; do not use for new writes.
pub fn content_hash_input(
    previous_hash: &str,
    sequence: i64,
    payload_json: &str,
    session_id: Option<&str>,
    created_at: Option<&str>,
) -> Vec<u8> {
    // Use null-byte delimiters between fields to prevent boundary-manipulation
    // collisions (e.g. sequence=1,payload="23{}" vs sequence=12,payload="3{}").
    let seq_str = sequence.to_string();
    let sid_len = session_id.map_or(0, |s| 1 + s.len());
    let ts_len = created_at.map_or(0, |t| 1 + t.len());
    let mut out = Vec::with_capacity(
        previous_hash.len() + 1 + seq_str.len() + 1 + payload_json.len() + sid_len + ts_len,
    );
    out.extend_from_slice(previous_hash.as_bytes());
    out.push(0x00);
    out.extend_from_slice(seq_str.as_bytes());
    out.push(0x00);
    out.extend_from_slice(payload_json.as_bytes());
    // When a session_id is provided, append it with a null-byte delimiter so
    // the event is cryptographically bound to this session - preventing
    // cross-session replay attacks.
    if let Some(sid) = session_id {
        out.push(0x00);
        out.extend_from_slice(sid.as_bytes());
    }
    // When a timestamp is provided, append it with a null-byte delimiter so
    // the event is cryptographically bound to its creation time - preventing
    // timestamp manipulation after the fact.
    if let Some(ts) = created_at {
        out.push(0x00);
        out.extend_from_slice(ts.as_bytes());
    }
    out
}

/// Pre-0.8 (v1) content hash. Retained ONLY for verification of pre-migration
/// ledgers via [`verify_content_hash_any_scheme`]; write paths must use
/// [`compute_content_hash_v2`].
pub fn compute_content_hash(
    previous_hash: &str,
    sequence: i64,
    payload_json: &str,
    session_id: Option<&str>,
    created_at: Option<&str>,
) -> String {
    let input = content_hash_input(
        previous_hash,
        sequence,
        payload_json,
        session_id,
        created_at,
    );
    sha256_hex(&input)
}

#[cfg(test)]
mod tests;
