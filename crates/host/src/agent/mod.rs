//! The cognitive loop: each step perceives the session, asks the model for one
//! action, checks it (policy, approval gate, tripwire, guard), runs it in the
//! strongest isolation configured and records what came back. Every decision
//! is an event in the session's signed ledger.

mod approval;
mod checks;
mod execute;
mod loop_detection;
mod observation;
mod preflight;
mod propose;
mod record;
#[cfg(test)]
mod tests;

use crate::cloud_creds::CloudCredentialSet;
use crate::compensation::CompensationPlanner;
use crate::config;
use crate::ledger::AppendError;
use crate::policy::PolicyEngine;
use crate::pool::DatabasePool;
use crate::schema::RestoredState;
use crate::tripwire::Tripwire;
use crate::wakeup::{self, WakeUpError};
use ed25519_dalek::SigningKey;
use reqwest::Client;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// What to do when a *configured* isolation tier (Firecracker or Docker) fails.
///
/// Configuring a tier is a statement that the action requires isolation, so the
/// default is to abort rather than silently run the action on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TierFailureAction {
    /// Abort the action: isolation was required and could not be provided.
    Abort,
    /// Run on the host executor anyway - only when the operator explicitly
    /// opted in via `ECTO_SANDBOX_PERMISSIVE`.
    FallBackToHost,
}

/// Fail-closed policy for isolation-tier failures. Extracted so both branches
/// are directly testable without a database or a running agent loop.
pub(crate) fn tier_failure_action(permissive: bool) -> TierFailureAction {
    if permissive {
        TierFailureAction::FallBackToHost
    } else {
        TierFailureAction::Abort
    }
}

pub struct AgentLoopConfig<'a> {
    pub llm: Box<dyn crate::llm::LlmBackend>,
    pub tripwire: &'a Tripwire,
    pub max_steps: Option<u32>,
    pub session_id: Option<Uuid>,
    pub session_goal: String,
    pub guard: Option<Box<dyn crate::guard::GuardExecutor>>,
    pub policy: Option<&'a PolicyEngine>,
    pub session_signing_key: Option<Arc<SigningKey>>,
    pub metrics: Option<std::sync::Arc<crate::metrics::Metrics>>,
    /// Optional channel to the async webhook egress worker. When set, flagged and aborted
    /// observations are forwarded in the background without blocking the cognitive loop.
    pub egress_tx: Option<tokio::sync::mpsc::Sender<crate::webhook::EgressEvent>>,
    /// Ephemeral cloud credentials injected only into matching child processes.
    pub cloud_creds: Option<Arc<CloudCredentialSet>>,
    /// When true, approval gate decisions are prompted interactively on stdin instead of
    /// waiting for the REST API (Mode A). When false, the shared ApprovalState is polled.
    pub interactive: bool,
    /// Shared approval state from the Observer server, enabling REST-driven gate decisions.
    pub approval_state: Option<Arc<crate::approvals::ApprovalState>>,
    /// Optional Firecracker microVM configuration.  When present and the Firecracker binary,
    /// kernel, and rootfs are available, `run_command` intents are executed inside an
    /// ephemeral KVM microVM instead of as host child processes.  Requires Linux and the
    /// `sandbox-firecracker` Cargo feature. Failure aborts unless permissive mode is enabled.
    pub firecracker_config: Option<crate::sandbox::FirecrackerConfig>,
    /// Optional Docker/Podman container sandbox configuration.  When present, `run_command`
    /// intents are executed inside an ephemeral, network-isolated container.  This works on
    /// Linux, macOS, and Windows wherever Docker Desktop or Podman is running.
    /// Priority: Firecracker (if configured) > Docker > host executor.
    pub docker_config: Option<crate::sandbox::DockerConfig>,
    /// If set, the session signing key is rotated every N steps.  A `KeyRotation` event
    /// is appended to the ledger each time the key changes, preserving a complete
    /// cryptographic audit trail.  `None` (the default) disables automatic rotation.
    pub key_rotation_interval_steps: Option<u32>,
    /// Optional compensating-action planner loaded from `.ectoledger/rollback_rules.toml`.
    /// When set, tripwire rejections are matched against rollback rules and a compensating
    /// `ProposedIntent` is proposed as a `Thought` event for the next iteration.
    pub compensation: Option<CompensationPlanner>,
    /// Optional enclave runtime for confidential inference. When set, LLM prompts
    /// are routed through the enclave's `execute()` method, and the resulting
    /// attestation is stored for embedding in the `.elc` certificate.
    ///
    /// **Nothing in this repository sets it.** All four construction sites pass
    /// `None`, and `enclave::router::select_enclave` - which picks a tier - has
    /// no callers. The enclave runtimes themselves are real and tested
    /// (`tests/enclave_apple_boot.rs` boots a unikernel on Apple Hypervisor and
    /// round-trips through its encrypted channel); what is missing is the wiring
    /// from configuration to this field. Treat the field as the seam that work
    /// will land on, not as a live path.
    pub enclave: Option<Box<dyn crate::enclave::runtime::EnclaveRuntime>>,
    /// Attestation evidence collected during enclave execution.
    /// Populated automatically after the first enclave-wrapped LLM call.
    pub enclave_attestation: Option<crate::enclave::runtime::EnclaveAttestation>,
    /// Optional cancellation token for cooperative shutdown.  When cancelled, the
    /// cognitive loop breaks gracefully at the next iteration boundary instead of
    /// relying on external future-drop from `tokio::select!`.
    pub cancel: Option<CancellationToken>,
}

pub async fn run_cognitive_loop(
    db: &DatabasePool,
    _client: &Client,
    config: AgentLoopConfig<'_>,
) -> Result<(), AgentError> {
    // Zombie sessions and half-run actions are recovered once at server start
    // (commands/serve.rs): recovering them here would fail every other session
    // that is running.
    let mut run = CognitiveLoop::new(db, config);
    run.preflight().await?;
    for step in 1..=run.limits.max_steps {
        run.check_cancelled()?;
        if run.step(step).await? == Step::Done {
            return Ok(());
        }
    }
    run.check_cancelled()
}

/// One session's run: its configuration and the failures it has counted.
struct CognitiveLoop<'a> {
    pool: &'a DatabasePool,
    config: AgentLoopConfig<'a>,
    limits: Limits,
    strikes: Strikes,
}

/// How many steps a session may take, and how many failures in a row end it.
struct Limits {
    max_steps: u32,
    llm_errors: u32,
    guard_denials: u32,
    justification_failures: u32,
}

/// Failures in a row, each reset by the next success of its kind.
#[derive(Default)]
struct Strikes {
    llm_errors: u32,
    guard_denials: u32,
    justification_failures: u32,
}

/// Whether the session goes on to another step.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Next,
    Done,
}

impl<'a> CognitiveLoop<'a> {
    fn new(pool: &'a DatabasePool, config: AgentLoopConfig<'a>) -> Self {
        let limits = Limits {
            max_steps: config
                .max_steps
                .or_else(|| config.policy.and_then(|p| p.max_steps()))
                .unwrap_or_else(config::max_steps),
            llm_errors: config::llm_error_limit(),
            guard_denials: config::guard_denial_limit(),
            justification_failures: config::justification_failure_limit(),
        };
        Self {
            pool,
            config,
            limits,
            strikes: Strikes::default(),
        }
    }

    /// Stops between steps once the caller has cancelled the session, so it
    /// can mark the session itself.
    fn check_cancelled(&self) -> Result<(), AgentError> {
        match &self.config.cancel {
            Some(cancel) if cancel.is_cancelled() => {
                tracing::info!(
                    "CancellationToken triggered - breaking cognitive loop cooperatively."
                );
                Err(AgentError::Cancelled)
            }
            _ => Ok(()),
        }
    }

    async fn step(&mut self, step: u32) -> Result<Step, AgentError> {
        let state = perceive(self.pool, self.config.session_id).await?;
        if loop_detection::detect_loop(&state.replayed_events) {
            return self.complete_after_loop().await;
        }
        let Some(intent) = self.propose(&state).await? else {
            return Ok(Step::Next);
        };
        if !self.policy_allows(&intent, step).await? {
            return Ok(Step::Next);
        }
        let Some(validated) = self.validate(&intent).await? else {
            return Ok(Step::Next);
        };
        if !self.guard_allows(&intent).await? || self.replay_cached_http_get(&validated).await? {
            return Ok(Step::Next);
        }
        let is_complete = validated.action() == "complete";
        let Some(output) = self.execute(validated).await? else {
            return Ok(Step::Next);
        };
        self.record_output(&output).await?;
        self.rotate_key(step).await;
        self.snapshot(step).await?;
        if is_complete {
            self.issue_credential().await;
            return Ok(Step::Done);
        }
        Ok(Step::Next)
    }
}

/// What the agent sees: this session's events only.
///
/// Another session's goal and observations must never reach this session's
/// prompt, and loop detection must count only this session's actions, or a
/// session repeating an earlier task stops at step one with "Loop detected".
/// Without a session id (no caller passes none) the whole-ledger view is kept.
async fn perceive(
    pool: &DatabasePool,
    session_id: Option<Uuid>,
) -> Result<RestoredState, AgentError> {
    if let Some(sid) = session_id {
        let events = pool
            .get_events_by_session(sid)
            .await
            .map_err(|e| AgentError::WakeUp(WakeUpError::Db(e)))?;
        return Ok(RestoredState {
            snapshot_sequence: 0,
            snapshot_payload: serde_json::Value::Null,
            replayed_events: events,
        });
    }
    match wakeup::restore_state(pool, false).await {
        Ok(s) => Ok(s),
        Err(WakeUpError::NoSnapshot) => wakeup::restore_state_from_genesis(pool)
            .await
            .map_err(AgentError::WakeUp),
        Err(e) => Err(AgentError::WakeUp(e)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("wakeup: {0}")]
    WakeUp(#[from] WakeUpError),
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("append: {0}")]
    Append(#[from] AppendError),
    #[error("circuit breaker: too many consecutive LLM errors")]
    CircuitBreaker,
    #[error("guard abort: too many consecutive denials")]
    GuardAbort,
    #[error("token budget exceeded: AGENT_TOKEN_BUDGET_MAX reached")]
    TokenBudgetExceeded,
    /// Policy observation rule triggered an abort.
    #[error("policy abort: {0}")]
    PolicyAbort(String),
    /// Prompt-level tripwire scan detected a dangerous pattern in the user goal.
    #[error("tripwire abort: {0}")]
    TripwireAbort(String),
    /// Generic I/O error (used by orchestrator to wrap errors).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The CancellationToken was triggered - the loop exited cooperatively.
    #[error("cancelled: cooperative shutdown via CancellationToken")]
    Cancelled,
}
