//! Regression tests for the fail-closed sandbox contract.
//!
//! The security property under test: when the OS sandbox cannot be applied,
//! the action is **aborted**, not executed unsandboxed. The documented opt-out
//! (`ECTO_SANDBOX_PERMISSIVE=true`) is pinned by the mirror case so neither
//! branch can regress silently.

use super::*;
use crate::intent::{ProposedIntent, ValidatedIntent};
use std::sync::MutexGuard;
use std::sync::atomic::Ordering;

/// Holds the shared exec lock, forces sandbox failure, and restores both on
/// drop (including on panic, so one failing assertion cannot poison the
/// rest). Same serialization pattern as `tests/adversarial_guards.rs`.
struct ForcedSandboxFailure {
    _guard: MutexGuard<'static, ()>,
}

impl ForcedSandboxFailure {
    fn with_permissive(permissive: bool) -> Self {
        let guard = EXEC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var(
                "ECTO_SANDBOX_PERMISSIVE",
                if permissive { "true" } else { "false" },
            );
            // `touch` is not in the default allowlist; add it so the child
            // has an observable side effect (file creation) that proves
            // whether it ran.
            std::env::set_var("AGENT_ALLOWED_PROGRAMS", "touch");
        }
        FORCE_SANDBOX_FAILURE.store(true, Ordering::Relaxed);
        ForcedSandboxFailure { _guard: guard }
    }
}

impl Drop for ForcedSandboxFailure {
    fn drop(&mut self) {
        FORCE_SANDBOX_FAILURE.store(false, Ordering::Relaxed);
        unsafe {
            std::env::remove_var("ECTO_SANDBOX_PERMISSIVE");
            std::env::remove_var("AGENT_ALLOWED_PROGRAMS");
        }
    }
}

fn touch_intent(marker: &std::path::Path) -> ValidatedIntent {
    ValidatedIntent::from_proposed(ProposedIntent {
        action: "run_command".to_string(),
        params: serde_json::json!({ "command": format!("touch {}", marker.display()) }),
        justification: "sandbox fail-closed regression test".to_string(),
        reasoning: String::new(),
    })
}

/// Fail-closed (default): when the sandbox cannot be applied, the command
/// must NOT run - no error swallowed, no side effect on disk.
#[test]
fn sandbox_failure_aborts_command_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("child-ran.marker");
    let _forced = ForcedSandboxFailure::with_permissive(false);

    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_command_with_context(touch_intent(&marker), None, None));

    assert!(
        result.is_err(),
        "sandbox failure must abort the action, got Ok: {result:?}"
    );
    assert!(
        !marker.exists(),
        "command executed despite sandbox failure - fail-closed contract broken \
         (marker file {} was created)",
        marker.display()
    );
}

/// Documented opt-in: with `ECTO_SANDBOX_PERMISSIVE=true` the same action
/// is allowed to proceed unsandboxed, so both branches of the flag are
/// pinned by tests.
#[test]
fn sandbox_failure_proceeds_when_permissive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("child-ran.marker");
    let _forced = ForcedSandboxFailure::with_permissive(true);

    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_command_with_context(touch_intent(&marker), None, None));

    assert!(
        result.is_ok(),
        "permissive mode must allow the action to proceed, got: {result:?}"
    );
    assert!(
        marker.exists(),
        "permissive mode should have executed the command (marker file {} missing)",
        marker.display()
    );
}
