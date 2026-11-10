//! Check a ledger against a certificate cut from it earlier.
//!
//! Two tampers cannot be caught from the database alone, by any verifier:
//! removing events from the end while rewriting the seal columns beside them,
//! and rewriting a whole session and signing it with a key of one's own. Both
//! contradict a certificate exported before the tamper, which commits to the
//! session's key, its event hashes in order, and its tip. This compares the
//! two. It does no I/O: callers pass what they read from the ledger.
//!
//! The certificate is only as good as its own verification. Callers should run
//! [`crate::verify::verify`] with a signature required first (and an expected
//! key when they have one), or a forger can bring a certificate that agrees
//! with their forged ledger.

use crate::EctoLedgerCertificate;
use serde::Serialize;

/// What the ledger shows now, for the certificate's session.
pub struct LedgerView<'a> {
    pub session_id: &'a str,
    /// `agent_sessions.session_public_key`, as recorded now.
    pub session_public_key: Option<&'a str>,
    /// `(sequence, content_hash)` of every event in the session, in order.
    pub events: &'a [(i64, String)],
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Comparison {
    /// Contradictions. Any one of them means the ledger changed after the
    /// certificate was cut, or the certificate is about something else.
    pub problems: Vec<String>,
    /// Events after the certificate's tip. Not a contradiction (anchors, for
    /// one, are appended after a session ends), but not covered by it either.
    pub events_after_certificate: usize,
}

impl Comparison {
    pub fn agrees(&self) -> bool {
        self.problems.is_empty()
    }
}

pub fn compare(cert: &EctoLedgerCertificate, ledger: &LedgerView<'_>) -> Comparison {
    let mut problems = Vec::new();

    if cert.session_id.to_string() != ledger.session_id {
        problems.push(format!(
            "the certificate is for session {}, not {}",
            cert.session_id, ledger.session_id
        ));
        return Comparison {
            problems,
            events_after_certificate: 0,
        };
    }

    match (&cert.session_public_key, ledger.session_public_key) {
        (Some(c), Some(l)) if !c.trim().eq_ignore_ascii_case(l.trim()) => problems.push(format!(
            "the session's key is now {}…, but the certificate was signed under {}…: \
             the session was re-keyed after the certificate was cut",
            short(l),
            short(c)
        )),
        (Some(c), None) => problems.push(format!(
            "the session no longer records a key; the certificate names {}…",
            short(c)
        )),
        _ => {}
    }

    let by_seq: std::collections::HashMap<i64, &str> = ledger
        .events
        .iter()
        .map(|(s, h)| (*s, h.as_str()))
        .collect();
    let mut first_missing = None;
    let mut first_changed = None;
    for e in &cert.events {
        match by_seq.get(&e.sequence) {
            None => {
                first_missing.get_or_insert(e.sequence);
            }
            Some(h) if !h.eq_ignore_ascii_case(&e.content_hash) => {
                first_changed.get_or_insert(e.sequence);
            }
            _ => {}
        }
    }
    let missing = cert
        .events
        .iter()
        .filter(|e| !by_seq.contains_key(&e.sequence))
        .count();
    if let Some(seq) = first_changed {
        problems.push(format!(
            "event {seq} no longer has the hash the certificate recorded: it was \
             rewritten after the certificate was cut"
        ));
    }
    if let Some(seq) = first_missing {
        problems.push(format!(
            "{missing} event(s) the certificate covers are gone from the ledger, from \
             sequence {seq}: removed after the certificate was cut"
        ));
    }

    let tip = cert.events.last().map(|e| e.sequence).unwrap_or(i64::MIN);
    let events_after_certificate = ledger.events.iter().filter(|(s, _)| *s > tip).count();

    Comparison {
        problems,
        events_after_certificate,
    }
}

fn short(s: &str) -> &str {
    crate::verify::prefix(s, 16)
}

#[cfg(test)]
mod tests;
