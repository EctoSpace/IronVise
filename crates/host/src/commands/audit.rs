//! `ironvise audit` - run a security audit with the cognitive loop.
//!
//! Uses a supervision tree built on `CancellationToken` for cooperative
//! shutdown between the Axum observer server and the agent cognitive loop.
//!
//! `audit` accepts any `DatabasePool`. Multi-agent orchestration
//! (`orchestrate`, `diff-audit`, `red-team`) still requires PostgreSQL.

use crate::agent::{self, AgentError, AgentLoopConfig};
use crate::config;
use crate::guard::GuardExecutor;
use crate::guard_process::GuardProcess;
use crate::ledger::AppendError;
use crate::policy::PolicyEngine;
use crate::pool::{self, DatabasePool};
use crate::sandbox;
use crate::schema::EventPayload;
use crate::server;
use crate::tripwire::Tripwire;
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type AuditResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Arguments for the `audit` subcommand, extracted from the CLI parser.
pub struct AuditArgs {
    pub prompt: String,
    pub policy: Option<PathBuf>,
    pub no_guard: bool,
    pub no_guard_confirmed: bool,
    pub interactive: bool,
    /// Read key-encryption password from this file descriptor (Unix only).
    pub key_password_fd: Option<i32>,
}

/// How the supervised audit ended, as far as cleanup is concerned.
struct AuditEnding {
    aborted: bool,
    session_finished: bool,
}

/// Run a full security audit: start the Observer dashboard, spawn the guard,
/// and execute the cognitive loop with proper supervision.
///
/// # Supervision model
///
/// Both the Axum HTTP server and the cognitive loop are `tokio::spawn`-ed.
/// A shared `CancellationToken` coordinates shutdown:
///
/// - **Ctrl-C** → token cancelled → both tasks observe and shut down cooperatively
/// - **Server crash** → token cancelled → cognitive loop stops, session marked "failed"
/// - **Cognitive loop error** → token cancelled → server shuts down gracefully
/// - **Cognitive loop panic** → `JoinHandle` returns `Err` → token cancelled, session "panicked"
pub async fn run(
    pool: pool::DatabasePool,
    metrics: Arc<crate::metrics::Metrics>,
    args: AuditArgs,
) -> AuditResult<()> {
    let AuditArgs {
        prompt,
        policy,
        no_guard,
        no_guard_confirmed,
        interactive,
        key_password_fd,
    } = args;

    // Before the model or the ledger is touched: a guard that is required but
    // not configured, or whose worker is missing, must fail here, or it would
    // fail after the session was created, leaving it `running` with only its
    // genesis event.
    let guard = start_guard(no_guard, no_guard_confirmed)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            crate::config::llm_timeout_secs(),
        ))
        .build()?;
    let llm_backend = crate::llm::backend_from_env(&client)?;
    llm_backend.ensure_ready(&client).await?;

    let (policy_engine, policy_hash) = match policy.as_deref() {
        Some(path) => {
            let (engine, hash) = load_enforceable_policy(path)?;
            (Some(engine), Some(hash))
        }
        None => (None, None),
    };

    // Must run before session creation to avoid TOCTOU with recovered sessions.
    recover_previous_runs(&pool).await;

    let (session, session_signing_key) = pool
        .create_session(
            &prompt,
            llm_backend.backend_name(),
            llm_backend.model_name(),
            policy_hash.as_deref(),
        )
        .await?;
    metrics.inc_sessions_created();
    let session_id = session.id;
    // On stdout whatever RUST_LOG says: `verify-session`, `report` and the
    // dashboard all start from this id, and nothing else prints it.
    println!("Session {session_id} started.");

    persist_signing_key(session_id, &session_signing_key, key_password_fd);
    let session_signing_key = Arc::new(session_signing_key);

    let goal_thought = match &policy_hash {
        Some(hash) => format!("Audit goal: {prompt}. Policy hash: {hash}"),
        None => format!("Audit goal: {prompt}"),
    };
    pool.append_event(
        EventPayload::Thought {
            content: goal_thought,
        },
        Some(session_id),
        Some(prompt.as_str()),
        Some(session_signing_key.as_ref()),
    )
    .await?;
    metrics.inc_events_appended();

    tracing::info!(
        "LLM ready ({} / {}). Starting cognitive loop.",
        llm_backend.backend_name(),
        llm_backend.model_name()
    );

    let cloud_creds = crate::cloud_creds::load_cloud_creds().map(Arc::new);
    if let Some(ref creds) = cloud_creds {
        tracing::info!(
            "Cloud credentials loaded: {} (provider: {})",
            creds.name,
            creds.provider
        );
    }

    let approval_state = Arc::new(crate::approvals::ApprovalState::for_pool(&pool));
    let cancel = CancellationToken::new();
    let server_handle = start_observer_server(
        pool.clone(),
        metrics.clone(),
        Arc::clone(&approval_state),
        cancel.clone(),
    )
    .await?;
    let mut server_handle = std::pin::pin!(server_handle);

    let tripwire = Tripwire::from_operator_config();
    let (egress_sender, egress_handle) =
        crate::webhook::spawn_egress_worker(config::webhook_config(), pool.clone());
    // Keep a sender here so the channel closes below even if the cognitive
    // loop future is cancelled mid-flight while holding its own copy.
    let egress_tx_cleanup = egress_sender.clone();

    let agent_config = AgentLoopConfig {
        llm: llm_backend,
        tripwire: &tripwire,
        max_steps: config::max_steps_configured(),
        session_id: Some(session_id),
        session_goal: prompt.clone(),
        guard,
        policy: policy_engine.as_ref(),
        session_signing_key: Some(session_signing_key),
        metrics: Some(metrics),
        egress_tx: Some(egress_sender),
        cloud_creds,
        interactive,
        approval_state: Some(approval_state),
        firecracker_config: sandbox::FirecrackerConfig::from_env_opt(),
        docker_config: sandbox::DockerConfig::from_env_opt(),
        key_rotation_interval_steps: config::key_rotation_interval_steps(),
        compensation: Some(crate::compensation::CompensationPlanner::load()),
        enclave: None,
        enclave_attestation: None,
        cancel: Some(cancel.clone()),
    };

    let agent_pool = pool.clone();
    let ending = tokio::select! {
        result = agent::run_cognitive_loop(&agent_pool, &client, agent_config) => {
            let outcome = conclude_session(&pool, session_id, result).await;
            cancel.cancel();
            outcome?;
            AuditEnding { aborted: false, session_finished: false }
        }
        result = &mut server_handle => {
            match result {
                Ok(()) => tracing::error!("Observer server exited unexpectedly during audit."),
                Err(e) => tracing::error!("Observer server panicked during audit: {}", e),
            }
            mark_session(&pool, session_id, "failed").await;
            cancel.cancel();
            AuditEnding { aborted: true, session_finished: true }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received; cancelling tasks…");
            cancel.cancel();
            AuditEnding { aborted: true, session_finished: false }
        }
    };

    drop(egress_tx_cleanup);
    if let Err(e) = egress_handle.await {
        tracing::error!("Webhook egress worker panicked: {e}");
    }
    if ending.aborted {
        snapshot_after_abort(&pool, session_id, ending.session_finished).await?;
    }
    println!(
        "Session {session_id} finished. Next:\n  \
         ironvise verify-session {session_id}\n  \
         ironvise report {session_id} --format certificate --output audit.elc"
    );
    Ok(())
}

/// The guard worker, or `None` only when both `--no-guard` flags were given.
fn start_guard(
    no_guard: bool,
    no_guard_confirmed: bool,
) -> AuditResult<Option<Box<dyn GuardExecutor>>> {
    match (no_guard, no_guard_confirmed) {
        (true, false) => Err(
            "⚠️  WARNING: You specified --no-guard. The Guard provides a separate process \
             and model to validate actions.\n   Running without the Guard reduces security. \
             If you really want to proceed, run with:\n   \
             cargo run -- audit \"<your goal>\" --no-guard --no-guard-confirmed"
                .into(),
        ),
        (true, true) => {
            tracing::warn!("Running without Guard (--no-guard --no-guard-confirmed).");
            Ok(None)
        }
        (false, _) => {
            config::ensure_guard_config().map_err(|e| format!("Configuration error: {e}"))?;
            let worker =
                GuardProcess::spawn().map_err(|e| format!("Guard process failed to start: {e}"))?;
            Ok(Some(Box::new(worker)))
        }
    }
}

/// Load a policy file and its hash, refusing one with nothing to enforce.
///
/// The session records this policy's hash as the one it ran under; a file with
/// no rules (the ISO 42001 controls mapping) would make that a claim about
/// checks that never ran.
fn load_enforceable_policy(path: &Path) -> Result<(PolicyEngine, String), std::io::Error> {
    let content = std::fs::read(path).inspect_err(|e| {
        tracing::error!("Failed to read policy file: {}", e);
    })?;
    let hash = crate::policy::policy_hash_bytes(&content);
    let engine = crate::policy::load_policy_engine(path).map_err(|e| {
        tracing::error!("Failed to load policy: {}", e);
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
    if !engine.policy().has_enforceable_rules() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} has no rules to check actions against, so it cannot govern an audit",
                path.display()
            ),
        ));
    }
    Ok((engine, hash))
}

/// Clean up sessions and actions a previous server run left half-done.
async fn recover_previous_runs(pool: &DatabasePool) {
    if let Err(e) = crate::wakeup::recover_zombie_sessions(pool).await {
        tracing::warn!("audit startup: failed to recover zombie sessions: {e}");
    }
    if let Err(e) = crate::wakeup::recover_incomplete_actions(pool).await {
        tracing::warn!("audit startup: failed to recover incomplete actions: {e}");
    }
}

/// Save the session key under a password, so a crash does not invalidate the
/// audit trail. Without a password the key lives only in memory.
fn persist_signing_key(session_id: Uuid, key: &SigningKey, key_password_fd: Option<i32>) {
    let password = match key_password_fd {
        Some(fd) => crate::signing::read_password_from_fd(fd),
        None => crate::signing::prompt_or_env_password(
            "Set a password to protect this session's signing key (leave blank to skip): ",
        ),
    };
    let Some(password) = password else { return };
    if let Err(e) =
        crate::signing::save_session_key(&config::session_key_dir(), session_id, key, &password)
    {
        tracing::warn!(
            "Could not persist signing key: {}. Key will be lost on crash.",
            e
        );
    }
}

/// Bind the Observer dashboard and wait until its task is serving.
async fn start_observer_server(
    pool: DatabasePool,
    metrics: Arc<crate::metrics::Metrics>,
    approval_state: Arc<crate::approvals::ApprovalState>,
    cancel: CancellationToken,
) -> AuditResult<JoinHandle<()>> {
    let bind_host = config::bind_host();
    let bind_port = config::bind_port();
    let listener = TcpListener::bind(format!("{bind_host}:{bind_port}")).await?;
    let display_host = if bind_host == "0.0.0.0" {
        "localhost"
    } else {
        bind_host.as_str()
    };
    tracing::info!("Observer dashboard: http://{}:{}", display_host, bind_port);

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let server_cancel = cancel.clone();
    let mut handle = tokio::spawn(async move {
        let _ = ready_tx.send(());
        let (router, _task_tracker) = server::router_with_approval_state(
            pool,
            metrics,
            approval_state,
            server_cancel.clone(),
            None,
        );
        let server = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(server_cancel.cancelled_owned());
        if let Err(e) = server.await {
            tracing::error!("Observer server terminated with error: {}", e);
        }
    });

    tokio::select! {
        _ = ready_rx => Ok(handle),
        result = &mut handle => {
            cancel.cancel();
            match result {
                Ok(()) => Err("Observer server exited immediately - cannot proceed with audit.".into()),
                Err(e) => Err(format!("Observer server task panicked: {e}").into()),
            }
        }
    }
}

/// Record how the cognitive loop ended and seal the session with the matching
/// status. Returns the error the CLI should report, if any.
async fn conclude_session(
    pool: &DatabasePool,
    session_id: Uuid,
    result: Result<(), AgentError>,
) -> AuditResult<()> {
    match result {
        Ok(()) => {
            mark_session(pool, session_id, "completed").await;
            tracing::info!("Cognitive loop finished.");
            Ok(())
        }
        Err(AgentError::Append(AppendError::GoalMismatch)) => {
            record_thought(
                pool,
                session_id,
                "Security: session goal mismatch (possible redirect); aborting.".to_string(),
            )
            .await;
            mark_session(pool, session_id, "aborted").await;
            Err("Session aborted: goal mismatch.".into())
        }
        Err(AgentError::Append(AppendError::UnverifiedEvidence(msg))) => {
            record_thought(
                pool,
                session_id,
                format!("Findings verification failed: {msg}; commit rejected."),
            )
            .await;
            mark_session(pool, session_id, "failed").await;
            Err(format!("Session failed: {msg}").into())
        }
        Err(AgentError::TripwireAbort(reason)) => {
            mark_session(pool, session_id, "aborted").await;
            Err(format!("Session aborted (tripwire): {reason}").into())
        }
        Err(AgentError::Cancelled) => {
            mark_session(pool, session_id, "aborted").await;
            Ok(())
        }
        Err(other) => {
            mark_session(pool, session_id, "failed").await;
            Err(other.into())
        }
    }
}

async fn record_thought(pool: &DatabasePool, session_id: Uuid, content: String) {
    if let Err(e) = pool
        .append_event(
            EventPayload::Thought { content },
            Some(session_id),
            None,
            None,
        )
        .await
    {
        tracing::warn!("Failed to append thought to session {}: {}", session_id, e);
    }
}

async fn mark_session(pool: &DatabasePool, session_id: Uuid, status: &str) {
    if let Err(e) = pool.finish_session(session_id, status).await {
        tracing::warn!("Failed to mark session {} as {}: {}", session_id, status, e);
    }
}

async fn snapshot_after_abort(
    pool: &DatabasePool,
    session_id: Uuid,
    session_finished: bool,
) -> AuditResult<()> {
    if let Some((seq, _)) = pool.get_latest().await?
        && let Err(e) = pool.snapshot_at_sequence(seq).await
    {
        tracing::warn!("Failed to snapshot on abort: {}", e);
    }
    if !session_finished {
        mark_session(pool, session_id, "aborted").await;
    }
    tracing::info!("Shutdown signal received; session aborted.");
    Ok(())
}
