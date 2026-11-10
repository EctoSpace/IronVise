//! Process start-up, before the arguments are read and after the ledger is
//! open.

use super::BoxError;
#[cfg(any(all(target_os = "linux", feature = "sandbox"), windows))]
use ectoledger::sandbox;
use tokio_util::sync::CancellationToken;

/// The environment, logging, the server policy and, on Windows, the process
/// sandbox, before anything else runs.
pub fn prepare() -> Result<(), BoxError> {
    // .env first: the filter reads RUST_LOG, and .env.example sets it there.
    dotenvy::dotenv().ok();
    ectoledger::logfmt::init_from_env();

    // A policy path that does not load stops the process here. Continuing would
    // serve with the policy layer silently switched off, which is the failure
    // mode this check exists to prevent.
    ectoledger::policy::ensure_server_policy()?;

    // Windows: apply Job Object sandbox to the current process.
    // All child processes inherit KILL_ON_JOB_CLOSE + UI restrictions.
    // This is done at startup (not per-child) because Windows lacks Unix pre_exec.
    #[cfg(target_os = "windows")]
    {
        let ws = std::env::current_dir().unwrap_or_default();
        if let Err(e) = sandbox::apply_child_sandbox(&ws) {
            tracing::error!("Windows Job Object sandbox could not be applied: {}", e);
            return Err("Aborting: Windows Job Object sandbox could not be applied.".into());
        }
    }
    Ok(())
}

/// Installs the Linux seccomp filter, once the database is up.
pub fn confine() -> Result<(), BoxError> {
    // The Linux seccomp filter is installed here (after DB setup) rather than
    // at process start, because embedded PostgreSQL (pg_embed) spawns child
    // processes via fork()+exec() that inherit the filter via PR_SET_NO_NEW_PRIVS.
    // PostgreSQL requires System V IPC (shmget, semget, etc.) which are NOT in
    // the allowlist.  Deferring the filter until after DB setup avoids this.
    //
    // The filter is per-thread: it covers this thread and every thread and
    // child started after it (the CLI agent loop, the guard worker,
    // run_command children, SQLite connection threads opened later), not the
    // runtime's worker threads, which already exist. `serve` handlers run on
    // those; their commands are still confined by Landlock in pre_exec.
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        if let Err(e) = sandbox::apply_main_process_seccomp() {
            tracing::error!("Linux seccomp filter failed to apply: {e}");
            return Err(sandbox::main_process_seccomp_failure(&e).into());
        }
    }
    Ok(())
}

/// A token cancelled by Ctrl-C, so a running command can shut down cleanly.
pub fn cancel_on_ctrl_c() -> CancellationToken {
    let cancel = CancellationToken::new();
    {
        let shutdown_cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("SIGINT received - initiating graceful shutdown");
                shutdown_cancel.cancel();
            }
        });
    }
    cancel
}
