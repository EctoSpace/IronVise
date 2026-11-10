use crate::cloud_creds::CloudCredentialSet;
use crate::intent::ValidatedIntent;
use crate::output::{format_sandbox_output, trim_to_max};
use crate::policy::PolicyEngine;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

mod command;
mod file;
mod http;
mod programs;
#[cfg(test)]
mod read_file_toctou_tests;
#[cfg(all(test, unix))]
mod sandbox_fail_closed_tests;
#[cfg(test)]
mod tests;

use command::*;
use file::*;
use http::*;
use programs::*;
pub use programs::{host_os_for_prompt, programs_for_prompt};

/// Test-only switch that makes [`apply_child_sandbox_for_exec`] behave as if
/// the OS sandbox could not be applied.
///
/// **Why a seam exists at all:** a real sandbox failure cannot be induced
/// portably - Landlock/Seatbelt/Job Objects fail only on unsupported kernels
/// or hardened hosts - so the fail-closed branch would otherwise be untestable
/// and silently rot. This is the smallest honest seam: it fakes only the
/// *result* of `apply_child_sandbox`, leaving the pre_exec hook, the
/// permissive-flag decision, and the spawn path exactly as they run in
/// production. The static is compiled out entirely in non-test builds, and it
/// is read post-`fork()` (the value is inherited by the child as ordinary
/// copied memory; a relaxed atomic load is async-signal-safe).
#[cfg(all(test, unix))]
static FORCE_SANDBOX_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Serializes every test that spawns a child process through this module.
///
/// Both `FORCE_SANDBOX_FAILURE` and the `AGENT_ALLOWED_PROGRAMS` /
/// `ECTO_SANDBOX_PERMISSIVE` environment variables are process-global, so a
/// test that arms them would otherwise corrupt any spawn running concurrently
/// on another test thread. Every test calling `run_command_with_context` holds
/// this lock.
#[cfg(test)]
static EXEC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Applies the child sandbox for a pending `exec()`. Production behaviour is
/// exactly [`crate::sandbox::apply_child_sandbox`]; see
/// [`FORCE_SANDBOX_FAILURE`] for the test-only failure seam.
#[cfg(unix)]
fn apply_child_sandbox_for_exec(
    workspace: &std::path::Path,
) -> Result<(), crate::sandbox::SandboxError> {
    #[cfg(test)]
    if FORCE_SANDBOX_FAILURE.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(crate::sandbox::SandboxError::Unsupported(
            "forced failure (test seam)".to_string(),
        ));
    }
    crate::sandbox::apply_child_sandbox(workspace)
}

pub async fn execute(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    execute_with_policy(validated, None, None).await
}

/// Execute with optional cloud credentials and policy engine for allowlist and env injection.
pub async fn execute_with_policy(
    validated: ValidatedIntent,
    creds: Option<Arc<CloudCredentialSet>>,
    policy: Option<&PolicyEngine>,
) -> Result<String, ExecuteError> {
    let action = validated.action();
    match action {
        "run_command" => run_command_with_context(validated, creds.as_deref(), policy).await,
        "read_file" => read_file(validated).await,
        "http_get" => http_get(validated).await,
        "complete" => complete_audit(validated),
        // Evaluated for external agents through the hook, which then run the
        // write themselves. The audit loop is read-only by design and has no
        // write path; refuse by name rather than as "unknown".
        "write_file" => Err(ExecuteError::UnknownAction(
            "write_file (the audit loop does not write files; this action is evaluated \
             for agents behind the Claude Code hook)"
                .to_string(),
        )),
        _ => Err(ExecuteError::UnknownAction(action.to_string())),
    }
}

fn complete_audit(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let params = validated.params();
    if let Some(findings_val) = params.get("findings") {
        match serde_json::from_value::<Vec<crate::schema::AuditFinding>>(findings_val.clone()) {
            Ok(findings) => {
                let summary = findings
                    .iter()
                    .map(|f| format!("[{:?}] {}", f.severity, f.title))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Ok(format!(
                    "Audit complete. {} finding(s): {}",
                    findings.len(),
                    if summary.is_empty() {
                        "none".to_string()
                    } else {
                        summary
                    }
                ));
            }
            Err(e) => {
                tracing::warn!(
                    "complete action findings did not conform to AuditFinding schema: {}",
                    e
                );
            }
        }
    }
    Ok("Audit complete.".to_string())
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("unknown action: {0}")]
    UnknownAction(String),
    #[error("missing param: {0}")]
    MissingParam(&'static str),
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("program not allowed: {0}")]
    ProgramNotAllowed(String),
    #[error("plugin integrity check failed: {0}")]
    PluginIntegrityFailed(String),
    #[error("sandbox required but unavailable: {0}")]
    SandboxUnavailable(String),
    #[error("timeout")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}
