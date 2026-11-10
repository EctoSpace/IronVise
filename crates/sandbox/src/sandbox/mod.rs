use crate::output::format_sandbox_output;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox io: {0}")]
    Io(#[from] std::io::Error),
    /// The sandbox is not available on this platform.
    /// Callers that tolerate advisory-only sandboxing may log and continue;
    /// callers that require hard isolation should propagate this error.
    #[error("sandbox unsupported: {0}")]
    Unsupported(String),
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    #[error("landlock: {0}")]
    Landlock(#[from] landlock::RulesetError),
    #[cfg(target_os = "windows")]
    #[error("windows job object: {0}")]
    Windows(#[from] windows::core::Error),
}

mod docker;
mod firecracker;
#[cfg(all(target_os = "linux", feature = "sandbox"))]
mod linux;
#[cfg(any(test, target_os = "macos"))]
mod macos;
mod seccomp;
#[cfg(test)]
mod tests;
#[cfg(target_os = "windows")]
mod win32;

pub use docker::*;
pub use firecracker::*;
#[cfg(all(target_os = "linux", feature = "sandbox"))]
use linux::*;
#[cfg(any(test, target_os = "macos"))]
use macos::*;
pub use seccomp::*;
#[cfg(target_os = "windows")]
use win32::*;

/// Applies the strongest available child-process sandbox for the current platform.
///
/// - Linux (with `sandbox` feature): Landlock + rlimits
/// - macOS: Apple Seatbelt (sandbox_init) profile restricting filesystem writes
///   to the workspace and denying network + process-exec access.
/// - Windows: Job Object with `KILL_ON_JOB_CLOSE` and full UI restrictions
/// - All other platforms: no-op (sandbox is best-effort)
pub fn apply_child_sandbox(workspace: &Path) -> Result<(), SandboxError> {
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        apply_landlock(workspace)?;
        apply_rlimits();
    }
    #[cfg(target_os = "macos")]
    {
        apply_seatbelt(workspace)?;
    }
    #[cfg(target_os = "windows")]
    {
        let _ = workspace;
        apply_windows_job_object()?;
    }
    #[cfg(not(any(
        all(target_os = "linux", feature = "sandbox"),
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let _ = workspace;
        tracing::info!(
            "No OS-level sandbox available on this platform; \
             relying on advisory tripwires for isolation."
        );
    }
    #[allow(unreachable_code)]
    Ok(())
}
