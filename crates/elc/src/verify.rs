//! The certificate verifier: six checks, one verdict, no I/O.
//!
//! Every entry point calls [`verify`]: the standalone `verify-cert` binary,
//! `ironvise verify-certificate`, and the browser verifier. They differ only
//! in how they print the [`Report`].
//!
//! ## Two modes, because they answer different questions
//!
//! The default is **inspection**: it reports what is inside the file and whether
//! the file is internally consistent. An unsigned certificate passes, because an
//! unsigned certificate is a real artifact that people hold and a verifier that
//! refuses to look at one is not useful.
//!
//! What inspection does *not* establish is who issued it. The hash chain, the
//! Merkle root and the goal hash are all computed from the file's own contents,
//! so a forger who builds a certificate from scratch passes every one of them.
//! Only the signature ties the document to a key, and only an expected key ties
//! that key to anyone. The verdict says which of those was established, and
//! `Requirements::signature` refuses to pass a certificate whose issuer is
//! unknown.

mod checks;
use checks::*;

use crate::{EctoLedgerCertificate, canonical_json_for_signing, legacy_json_for_signing};
use ectoledger_core::merkle;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// What the caller requires before calling a certificate verified.
#[derive(Clone, Debug, Default)]
pub struct Requirements {
    /// A signature must be present and verify.
    pub signature: bool,
    /// The signature must be by this key (hex), given out of band. Implies `signature`.
    pub expected_key: Option<String>,
    /// The OTS stamp must carry a Bitcoin attestation.
    pub anchor: bool,
    /// A detached `.ots` file for this certificate's tip, kept beside it: how
    /// an upgraded stamp is presented. Upgrading the embedded stamp in place
    /// would change `ots_proof_hex`, which the signature covers.
    pub ots_file: Option<Vec<u8>>,
    /// The certificate must be countersigned by this issuer key (hex), given
    /// out of band. Satisfies a required signature on its own.
    pub issuer: Option<String>,
}

impl Requirements {
    /// `expected_key` implies `signature`: knowing which key to expect is the
    /// whole point, so requiring a signature is implied by having an opinion
    /// about whose it is.
    pub fn normalised(mut self) -> Self {
        if let Some(k) = self.expected_key.take() {
            let k = k.trim().to_lowercase();
            if !k.is_empty() {
                self.signature = true;
                self.expected_key = Some(k);
            }
        }
        self.issuer = self
            .issuer
            .map(|k| k.trim().to_lowercase())
            .filter(|k| !k.is_empty());
        self
    }

    fn strict(&self) -> bool {
        self.signature || self.anchor || self.issuer.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The check ran and passed.
    Pass,
    /// Not a failure, but something a reader should know (unsigned, no stamp).
    Warn,
    /// The check failed. The certificate is invalid.
    Fail,
}

/// One check's outcome, printable as a single line plus optional notes.
#[derive(Clone, Debug, Serialize)]
pub struct Check {
    /// Stable machine name: `signature`, `hash_chain`, `merkle`, `goal_hash`,
    /// `ots`, `anchor_required`, `enclave`, `zk_proof`, `issuer`.
    pub id: &'static str,
    pub status: Status,
    /// The emphasised part of the line.
    pub title: String,
    /// The rest of the line, already including its leading separator.
    pub detail: String,
    /// Further lines, printed indented under this one.
    pub notes: Vec<String>,
}

impl Check {
    fn new(
        id: &'static str,
        status: Status,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Check {
            id,
            status,
            title: title.into(),
            detail: detail.into(),
            notes: Vec::new(),
        }
    }

    fn with_notes(mut self, notes: Vec<String>) -> Self {
        self.notes = notes;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// Every requirement passed and a signature verified.
    Valid {
        /// The key that verified, lowercase hex: the session key, or the
        /// issuer's when only the issuer signed.
        signer: String,
        /// Whether that key was the one the caller expected.
        expected: bool,
        /// The issuer's countersignature, when there is one and it verified.
        issuer: Option<IssuerVerdict>,
    },
    /// Every requirement passed, but nothing identifies the issuer.
    ConsistentUnsigned,
    /// At least one check failed.
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuerVerdict {
    /// The issuer key that verified, lowercase hex.
    pub key: String,
    /// Whether it was the issuer the caller required.
    pub expected: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub session_id: String,
    pub event_count: u64,
    pub started_at: String,
    pub goal: String,
    /// `strict` when a signature or anchor was required, else `inspection`.
    pub mode: &'static str,
    pub checks: Vec<Check>,
    /// Whether the OTS stamp carries a Bitcoin attestation.
    pub anchored: bool,
    pub verdict: Verdict,
}

impl Report {
    pub fn is_valid(&self) -> bool {
        !matches!(self.verdict, Verdict::Invalid)
    }

    /// The final line, without colour.
    pub fn verdict_line(&self) -> String {
        match &self.verdict {
            Verdict::Invalid => "CERTIFICATE INVALID - one or more checks failed.".to_string(),
            Verdict::Valid {
                signer,
                expected,
                issuer: Some(issuer),
            } => {
                let who = |key: &str, required: bool, what: &str| {
                    let the = if required { "the expected " } else { "" };
                    format!("{the}{what}{}…", prefix(key, 16))
                };
                let signed = if *signer == issuer.key {
                    format!("signed by {}", who(&issuer.key, issuer.expected, "issuer "))
                } else {
                    format!(
                        "signed by {}, countersigned by {}",
                        who(signer, *expected, "key "),
                        who(&issuer.key, issuer.expected, "issuer ")
                    )
                };
                let hint = if *expected || issuer.expected {
                    ""
                } else {
                    " (no key here is known to be anyone's: pass --issuer to check)"
                };
                format!(
                    "CERTIFICATE VALID  - session {}, {signed}{hint}",
                    self.session_id
                )
            }
            Verdict::Valid {
                signer, expected, ..
            } => {
                let short = prefix(signer, 16);
                if *expected {
                    format!(
                        "CERTIFICATE VALID  - session {}, signed by the expected key {short}…",
                        self.session_id
                    )
                } else {
                    format!(
                        "CERTIFICATE VALID  - session {}, signed by {short}… \
                         (that key is not known to be anyone's: pass --expected-key to check)",
                        self.session_id
                    )
                }
            }
            Verdict::ConsistentUnsigned => format!(
                "CERTIFICATE INTERNALLY CONSISTENT - session {}, but unsigned: nothing in it \
                 identifies who issued it, and every check above is computed from the file's own \
                 contents. Use --strict to require a signature.",
                self.session_id
            ),
        }
    }

    /// The whole report as terminal text. `color` adds ANSI colours around the
    /// emphasised parts; `include_verdict` appends the final line.
    pub fn render(&self, color: bool, include_verdict: bool) -> String {
        let mut out = self.render_checks(color);
        if include_verdict {
            out.push('\n');
            out.push_str(&self.render_verdict(color));
            out.push('\n');
        }
        out
    }

    /// The header and one line (plus notes) per check.
    pub fn render_checks(&self, color: bool) -> String {
        let (green, red, yellow, reset) = palette(color);
        let mut out = String::new();
        out.push_str("\nVerifying IronVise Audit Certificate\n");
        out.push_str(&format!("  Session : {}\n", self.session_id));
        out.push_str(&format!("  Events  : {}\n", self.event_count));
        out.push_str(&format!("  Started : {}\n", self.started_at));
        out.push_str(&format!(
            "  Mode    : {}\n\n",
            if self.mode == "strict" {
                "strict - the requirements below must be met"
            } else {
                "inspection - reports contents and internal consistency"
            }
        ));
        for c in &self.checks {
            let (col, sym) = match c.status {
                Status::Pass => (green, "✓"),
                Status::Warn => (yellow, "⚠"),
                Status::Fail => (red, "✗"),
            };
            out.push_str(&format!("{col}{sym}  {}{reset}{}\n", c.title, c.detail));
            for n in &c.notes {
                out.push_str(&format!("     {n}\n"));
            }
        }
        out
    }

    /// The verdict line, with only its leading "CERTIFICATE …" phrase coloured.
    pub fn render_verdict(&self, color: bool) -> String {
        let (green, red, yellow, reset) = palette(color);
        let col = match self.verdict {
            Verdict::Valid { .. } => green,
            Verdict::ConsistentUnsigned => yellow,
            Verdict::Invalid => red,
        };
        let line = self.verdict_line();
        let split = line.find(" - ").unwrap_or(line.len());
        format!("{col}{}{reset}{}", &line[..split], &line[split..])
    }
}

fn palette(color: bool) -> (&'static str, &'static str, &'static str, &'static str) {
    if color {
        ("\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[0m")
    } else {
        ("", "", "", "")
    }
}

/// Run every check against a parsed certificate.
pub fn verify(cert: &EctoLedgerCertificate, req: &Requirements) -> Report {
    let req = req.clone().normalised();
    let mut checks = Vec::new();
    let mut all_ok = true;

    let (issuer_check, issuer, issuer_ok) = check_issuer(cert, &req);
    let (sig_check, verified_key, sig_ok) = check_signature(cert, &req, issuer.is_some());
    checks.push(sig_check);
    checks.extend(issuer_check);
    all_ok &= sig_ok && issuer_ok;

    let chain = check_hash_chain(cert);
    all_ok &= chain.status != Status::Fail;
    checks.push(chain);

    let merkle = check_merkle_proofs(cert);
    all_ok &= merkle.status != Status::Fail;
    checks.push(merkle);

    let goal = check_goal_hash(cert);
    all_ok &= goal.status != Status::Fail;
    checks.push(goal);

    let (ots, anchored) = check_ots(cert, &req);
    let ots_failed = ots.status == Status::Fail;
    all_ok &= !ots_failed;
    checks.push(ots);
    if req.anchor && !anchored {
        checks.push(Check::new(
            "anchor_required",
            Status::Fail,
            "Anchor required",
            " - an anchor was required and the stamp carries no Bitcoin attestation",
        ));
        all_ok = false;
    }

    // Informational; never fatal.
    checks.push(check_enclave_attestation(cert));
    if let Some(zk) = check_zk_proof(cert) {
        checks.push(zk);
    }

    let verdict = if !all_ok {
        Verdict::Invalid
    } else {
        match (verified_key, issuer) {
            (Some(signer), issuer) => Verdict::Valid {
                signer,
                expected: req.expected_key.is_some(),
                issuer,
            },
            (None, Some(issuer)) => Verdict::Valid {
                signer: issuer.key.clone(),
                expected: issuer.expected,
                issuer: Some(issuer),
            },
            (None, None) => Verdict::ConsistentUnsigned,
        }
    };

    Report {
        session_id: cert.session_id.to_string(),
        event_count: cert.event_count,
        started_at: cert.started_at.clone(),
        goal: cert.goal.clone(),
        mode: if req.strict() { "strict" } else { "inspection" },
        checks,
        anchored,
        verdict,
    }
}

/// The first `n` characters of `s`: certificate fields are untrusted text, so
/// never slice them by byte.
pub(crate) fn prefix(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

#[cfg(test)]
mod tests;
