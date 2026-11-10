// Host-side policy module.
//
// All pure evaluation types and the PolicyEngine are defined in `ectoledger_core::policy`
// and re-exported here so that existing `use crate::policy::*` imports resolve unchanged.
//
// This module adds the TOML file-loading layer (`PolicyLoadError`, `load_policy_engine`)
// which requires std file I/O and is therefore kept out of the no-I/O-dependency core crate.

pub use ectoledger_core::policy::*;

use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid regex in policy: {0}")]
    InvalidRegex(String),
    #[error("policy integrity check failed: expected hash {expected}, got {actual}")]
    IntegrityCheckFailed { expected: String, actual: String },
}

/// Parse an `AuditPolicy` from a TOML file and wrap it in a `PolicyEngine`.
///
/// The `PolicyEngine` itself lives in `ectoledger_core` (no file I/O).
/// This free function is the host-side entry point for loading policies from disk.
pub fn load_policy_engine(path: &Path) -> Result<PolicyEngine, PolicyLoadError> {
    load_policy_engine_with_integrity(path, None)
}

/// Parse an `AuditPolicy` from a TOML file, optionally verifying its SHA-256
/// hash against `expected_hash` before trusting the content.
///
/// When `expected_hash` is `Some`, the raw file content is hashed and compared
/// to the expected value. A mismatch indicates policy file tampering and the
/// function returns `PolicyLoadError::IntegrityCheckFailed`.
///
/// Returns the `PolicyEngine` and the computed SHA-256 hash of the file (hex).
pub fn load_policy_engine_with_integrity(
    path: &Path,
    expected_hash: Option<&str>,
) -> Result<PolicyEngine, PolicyLoadError> {
    let s = std::fs::read_to_string(path).map_err(PolicyLoadError::Io)?;

    // Compute the SHA-256 hash of the raw policy file for integrity verification.
    let actual_hash = hex::encode(Sha256::digest(s.as_bytes()));

    if let Some(expected) = expected_hash
        && !constant_time_eq(expected.as_bytes(), actual_hash.as_bytes())
    {
        return Err(PolicyLoadError::IntegrityCheckFailed {
            expected: expected.to_string(),
            actual: actual_hash,
        });
    }

    let policy: AuditPolicy = toml::from_str(&s).map_err(PolicyLoadError::Toml)?;
    PolicyEngine::new(policy).map_err(|e| PolicyLoadError::InvalidRegex(e.0))
}

/// A policy from its text, for one that has no file of its own (a built-in
/// pack) or is read fresh for each run. `origin` is reported as its path.
pub fn loaded_policy_from_text(
    text: &str,
    origin: std::path::PathBuf,
) -> Result<LoadedPolicy, PolicyLoadError> {
    let hash = hex::encode(Sha256::digest(text.as_bytes()));
    let policy: AuditPolicy = toml::from_str(text).map_err(PolicyLoadError::Toml)?;
    let engine = PolicyEngine::new(policy).map_err(|e| PolicyLoadError::InvalidRegex(e.0))?;
    Ok(LoadedPolicy {
        engine,
        hash,
        path: origin,
    })
}

/// A policy loaded from disk, with the identity an auditor needs to say *which*
/// policy produced a decision.
pub struct LoadedPolicy {
    pub engine: PolicyEngine,
    /// SHA-256 of the file's bytes, hex. Reported in verdicts so a decision can
    /// be tied to the exact rules that produced it.
    pub hash: String,
    pub path: std::path::PathBuf,
}

static SERVER_POLICY: std::sync::OnceLock<Result<Option<std::sync::Arc<LoadedPolicy>>, String>> =
    std::sync::OnceLock::new();

/// Load the server-wide policy named by `ECTO_POLICY_PATH`, once.
///
/// Before this existed the Observer had no policy at all: the cognitive loop
/// took one from `--policy` on the command line, and every HTTP surface - the
/// Claude Code hook, the SDK's `verify-intent`, the REST run endpoint - built
/// its evaluation context with `policy: None`. They shared the evaluator and
/// not its configuration, so "the same pipeline the loop uses" described the
/// code and not the checks.
///
/// Unset means no policy, which is the historical behaviour and is reported as
/// a skipped layer rather than passed off as a full evaluation. Set but
/// unloadable is a **startup failure**: a policy that silently does not load is
/// the same defect as a guard that silently does not run.
pub fn server_policy() -> Result<Option<std::sync::Arc<LoadedPolicy>>, String> {
    SERVER_POLICY
        .get_or_init(|| {
            let Some(raw) = std::env::var("ECTO_POLICY_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
            else {
                return Ok(None);
            };
            let path = std::path::PathBuf::from(raw);
            let hash = compute_policy_hash(&path)
                .map_err(|e| format!("ECTO_POLICY_PATH {}: {e}", path.display()))?;
            let engine = load_policy_engine(&path)
                .map_err(|e| format!("ECTO_POLICY_PATH {}: {e}", path.display()))?;
            if !engine.policy().has_enforceable_rules() {
                return Err(format!(
                    "ECTO_POLICY_PATH {}: the policy has no rules to check actions against",
                    path.display()
                ));
            }
            Ok(Some(std::sync::Arc::new(LoadedPolicy {
                engine,
                hash,
                path,
            })))
        })
        .clone()
}

/// Startup check: fail the process rather than serve with a policy that did not
/// load. Mirrors [`crate::config::ensure_guard_config`].
pub fn ensure_server_policy() -> Result<(), String> {
    match server_policy()? {
        Some(p) => {
            tracing::info!(
                "policy = {} (sha256 {}…)",
                p.path.display(),
                &p.hash[..16.min(p.hash.len())]
            );
            Ok(())
        }
        None => {
            tracing::info!(
                "policy = none (ECTO_POLICY_PATH unset); declarative policy rules are not evaluated"
            );
            Ok(())
        }
    }
}

/// Compute the SHA-256 hash of a policy file without loading it as a
/// `PolicyEngine`. Useful for storing the expected hash at deployment time.
pub fn compute_policy_hash(path: &Path) -> Result<String, std::io::Error> {
    let s = std::fs::read_to_string(path)?;
    Ok(hex::encode(Sha256::digest(s.as_bytes())))
}

/// Constant-time byte comparison (prevents timing side-channels on hash checks).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_policy_engine_reads_a_minimal_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "max_steps = 3\n").unwrap();
        let engine = load_policy_engine(&path).expect("load");
        assert_eq!(engine.max_steps(), Some(3));
    }

    #[test]
    fn integrity_mismatch_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "max_steps = 3\n").unwrap();
        let err = match load_policy_engine_with_integrity(&path, Some("deadbeef")) {
            Err(e) => e,
            Ok(_) => panic!("expected integrity failure"),
        };
        assert!(matches!(err, PolicyLoadError::IntegrityCheckFailed { .. }));
    }

    #[test]
    fn integrity_match_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let body = "max_steps = 3\n";
        std::fs::write(&path, body).unwrap();
        let expected = compute_policy_hash(&path).unwrap();
        let engine = load_policy_engine_with_integrity(&path, Some(&expected)).expect("load");
        assert_eq!(engine.max_steps(), Some(3));
        assert_eq!(expected, compute_policy_hash(&path).unwrap());
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let err = match load_policy_engine(std::path::Path::new("/no/such/policy.toml")) {
            Err(e) => e,
            Ok(_) => panic!("expected missing file"),
        };
        assert!(matches!(err, PolicyLoadError::Io(_)));
    }

    #[test]
    fn invalid_toml_is_a_toml_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "[[[not toml").unwrap();
        let err = match load_policy_engine(&path) {
            Err(e) => e,
            Ok(_) => panic!("expected toml error"),
        };
        assert!(matches!(err, PolicyLoadError::Toml(_)));
    }
}
