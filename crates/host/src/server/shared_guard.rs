//! The guard worker the Claude Code hook and the SDK's `verify-intent` share.
//!
//! The cognitive loop spawns a guard worker per session; these two surfaces
//! have no session loop to own one. The server keeps a single worker for them:
//! started on first use when the guard is required, serialised by a lock (a
//! worker answers one request at a time), and replaced after it fails, since a
//! worker that died answers nothing again.

use tokio::sync::{Mutex, MutexGuard};

use crate::guard::GuardExecutor;
use crate::guard_process::GuardProcess;

#[derive(Default)]
pub(crate) struct SharedGuard(Mutex<Option<GuardProcess>>);

/// The worker for one evaluation, held under the lock until dropped.
pub(crate) struct GuardSlot<'a>(Option<MutexGuard<'a, Option<GuardProcess>>>);

impl SharedGuard {
    /// When the guard is required, the worker (started if there is none).
    /// When it cannot be started the slot is empty, and the evaluator denies
    /// at `guard_unavailable` rather than allowing unchecked.
    pub(crate) async fn acquire(&self, required: bool) -> GuardSlot<'_> {
        if !required {
            return GuardSlot(None);
        }
        let mut worker = self.0.lock().await;
        if worker.is_none() {
            let started = crate::config::ensure_guard_config()
                .and_then(|()| GuardProcess::spawn().map_err(|e| e.to_string()));
            match started {
                Ok(g) => *worker = Some(g),
                Err(e) => tracing::error!("the hook and SDK guard could not start: {e}"),
            }
        }
        GuardSlot(Some(worker))
    }
}

impl GuardSlot<'_> {
    pub(crate) fn executor(&mut self) -> Option<&mut dyn GuardExecutor> {
        self.0
            .as_mut()?
            .as_mut()
            .map(|g| g as &mut dyn GuardExecutor)
    }

    pub(crate) fn running(&self) -> bool {
        self.0.as_ref().is_some_and(|w| w.is_some())
    }

    /// Drop a worker that failed, so the next evaluation starts a new one.
    pub(crate) fn discard(&mut self) {
        if let Some(worker) = self.0.as_mut() {
            worker.take();
        }
    }
}
