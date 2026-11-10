use crate::agent;
use crate::approvals::{ApprovalDecisionRequest, ApprovalState, PendingApproval};
use crate::config;
use crate::guard::GuardExecutor;
use crate::guard_process::GuardProcess;
use crate::ledger;
use crate::llm;
use crate::pool::DatabasePool;
use crate::schema::{EventPayload, SessionRow};
use crate::tripwire;
use axum::Router;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Html;
use axum::response::sse::{Event, Sse};
use axum::routing::{delete, get, post, put};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::metrics::Metrics;

// Handlers are grouped by the API surface they serve. This module keeps only
// the shared state, the index page, and the router assembly, so route
// registration and middleware order stay readable in one place.

mod approvals_api;
mod auth;
mod chat;
mod exports;
mod hook;
mod observability;
mod policies;
mod redact;
mod sdk;
mod session_keys;
mod sessions;
mod settings;
mod shared_guard;
mod stream;
mod tokens;
mod webhooks_api;

/// The Claude Code `matcher` covering exactly the tools the hook evaluates.
pub fn hook_matcher() -> String {
    format!("{}|mcp__.*", hook::MAPPED_TOOLS.join("|"))
}

/// The Antigravity CLI tools the hook evaluates, one matcher each.
pub fn antigravity_hook_tools() -> &'static [&'static str] {
    hook::ANTIGRAVITY_TOOLS
}

// Handlers are referenced unqualified by the router below, so each group is
// glob-imported rather than listed name by name.
use approvals_api::*;
use auth::*;
use chat::*;
use exports::*;
use observability::*;
use policies::*;
use redact::*;
use sdk::*;
use sessions::*;
use settings::*;
use stream::*;
use tokens::*;
use webhooks_api::*;

pub use auth::Role;
pub use stream::notify_sse_subscribers;

const INDEX_HTML: &str = include_str!("../index.html");

#[derive(Clone)]
pub struct AppState {
    pub pool: DatabasePool,
    pub metrics: Arc<Metrics>,
    pub approval_state: Arc<ApprovalState>,
    /// Broadcast sender - cloned into SSE handlers for event-driven wakeup.
    pub sse_tx: broadcast::Sender<()>,
    /// Sender end of the single shared webhook egress worker.
    /// Cloned into each agent session instead of spawning a separate worker
    /// per session (which would exhaust the DB connection pool under load).
    pub egress_tx: mpsc::Sender<crate::webhook::EgressEvent>,
    /// Shared HTTP client - reused across all handlers to avoid per-session
    /// TLS/DNS/connection-pool exhaustion under concurrent load.
    pub http_client: reqwest::Client,
    /// Tracks all spawned cognitive-loop tasks so shutdown can await them.
    pub task_tracker: TaskTracker,
    /// Server-wide cancellation token - cancelled on shutdown to signal all
    /// REST-spawned cognitive loops to exit cooperatively.
    pub cancel: CancellationToken,
    /// Optional LLM backend factory - when set, handlers use this instead of
    /// `backend_from_env()`.  Used by integration tests to inject a stub
    /// without requiring mock.rs in production code.
    pub llm_factory: Option<Arc<dyn Fn() -> Box<dyn llm::LlmBackend> + Send + Sync>>,
    /// The server-wide declarative policy from `ECTO_POLICY_PATH`, when one is
    /// configured. `None` means no policy layer runs, which every surface
    /// reports as a skipped layer rather than passing off as an evaluation.
    ///
    /// Loaded once by [`crate::policy::server_policy`]; `main.rs` calls
    /// [`crate::policy::ensure_server_policy`] first, so a path that does not
    /// load fails startup instead of silently disabling the layer here.
    pub policy: Option<Arc<crate::policy::LoadedPolicy>>,
    /// The guard worker the hook and the SDK's verify-intent share, started on
    /// first use when the guard is required.
    pub(crate) guard: Arc<shared_guard::SharedGuard>,
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}
/// Build a router and return both the `Router` and the shared `ApprovalState` Arc so callers
/// (e.g. the `audit` command) can wire it into the `AgentLoopConfig`.
///
/// Reads the trusted-proxy list for rate limiting from `ECTO_TRUSTED_PROXIES`
/// (see [`config::trusted_proxies`]). Use
/// [`router_with_approval_state_and_trusted_proxies`] to supply it directly
/// instead - tests do, since env vars are process-global and would otherwise
/// race across tests run on different threads of the same binary.
pub fn router_with_approval_state(
    pool: DatabasePool,
    metrics: Arc<crate::metrics::Metrics>,
    approval_state: Arc<ApprovalState>,
    cancel: CancellationToken,
    llm_factory: Option<Arc<dyn Fn() -> Box<dyn llm::LlmBackend> + Send + Sync>>,
) -> (Router, TaskTracker) {
    router_with_approval_state_and_trusted_proxies(
        pool,
        metrics,
        approval_state,
        cancel,
        llm_factory,
        config::trusted_proxies(),
    )
}

/// Same as [`router_with_approval_state`], taking the trusted-proxy list
/// (raw `ECTO_TRUSTED_PROXIES`-style entries, IPs or CIDRs) explicitly rather
/// than reading it from the environment.
pub fn router_with_approval_state_and_trusted_proxies(
    pool: DatabasePool,
    metrics: Arc<crate::metrics::Metrics>,
    approval_state: Arc<ApprovalState>,
    cancel: CancellationToken,
    llm_factory: Option<Arc<dyn Fn() -> Box<dyn llm::LlmBackend> + Send + Sync>>,
    trusted_proxies: Vec<String>,
) -> (Router, TaskTracker) {
    let task_tracker = TaskTracker::new();
    let (tx, _) = broadcast::channel::<()>(64);
    // Spin up exactly one egress worker for the lifetime of this router.  All
    // agent sessions share this single worker rather than each spawning their
    // own, preventing DB connection pool exhaustion under concurrent load.
    //
    // The egress worker runs on PostgreSQL and SQLite (DB-backed webhook rows).
    let (etx, _handle) =
        crate::webhook::spawn_egress_worker(config::webhook_config(), pool.clone());
    let egress_tx = etx;

    // Forget replay-protection ids past their retention (pool::REPLAY_RETENTION_DAYS).
    {
        let pool = pool.clone();
        tokio::spawn(async move {
            match pool.purge_consumed_requests().await {
                Ok(0) => {}
                Ok(n) => tracing::info!("purged {n} expired replay-protection ids"),
                Err(e) => tracing::warn!("purging replay-protection ids failed: {e}"),
            }
        });
    }

    // A session that is still "running" after 60 minutes almost certainly hit an
    // unrecoverable panic or lost its DB connection.  Mark it "failed" so the
    // GUI never shows a permanently-spinning session.
    {
        let reaper_pool = pool.clone();
        tokio::spawn(async move {
            let interval = tokio::time::Duration::from_secs(5 * 60);
            loop {
                tokio::time::sleep(interval).await;
                let fut = std::panic::AssertUnwindSafe(reaper_pool.reap_zombie_sessions(60));
                match futures_util::FutureExt::catch_unwind(fut).await {
                    Ok(Ok(n)) if n > 0 => {
                        tracing::warn!(
                            count = n,
                            "zombie-session-reaper: marked {n} stale session(s) as failed"
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::error!("zombie-session-reaper: query failed: {e}");
                    }
                    Err(e) => {
                        tracing::error!(
                            "zombie-session-reaper: panicked: {:?} - will retry next interval",
                            e
                        );
                    }
                    _ => {}
                }
            }
        });
    }

    // Store the SSE sender in the global so `notify_sse_subscribers()` can
    // wake SSE handlers from the ledger layer without threading state through.
    let _ = SSE_WAKEUP.set(tx.clone());
    // On PostgreSQL every append also sends NOTIFY; listening for it wakes
    // this instance's SSE clients when another instance appends.
    if let DatabasePool::Postgres(pg) = &pool {
        crate::pg_notify::spawn_pg_listener(pg, cancel.clone(), notify_sse_subscribers);
    }
    let state = Arc::new(AppState {
        pool,
        metrics,
        approval_state,
        sse_tx: tx,
        egress_tx,
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                crate::config::llm_timeout_secs(),
            ))
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "reqwest Client::builder() failed ({e}); falling back to default client"
                );
                reqwest::Client::new()
            }),
        task_tracker: task_tracker.clone(),
        cancel,
        llm_factory,
        policy: crate::policy::server_policy().unwrap_or_else(|e| {
            // Unreachable in the server binary, which calls
            // `ensure_server_policy()` before building the router. Reached only
            // by an embedder that skipped it; loud, and still no policy.
            tracing::error!("policy did not load, continuing without one: {e}");
            None
        }),
        guard: Arc::default(),
    });

    // Rate-limit key: the socket peer, unless that peer is a configured
    // trusted proxy, in which case the client IP it reports via
    // X-Forwarded-For/X-Real-Ip/Forwarded is used instead. Unlike
    // `tower_governor`'s `SmartIpKeyExtractor`, an untrusted caller cannot
    // evade its own limit by sending a fresh spoofed header per request -
    // see `auth::TrustedProxyKeyExtractor`.
    let rate_limit_key_extractor =
        auth::TrustedProxyKeyExtractor::new(auth::parse_trusted_proxies(&trusted_proxies));

    // Global API rate limit: configurable via API_RATE_LIMIT_PER_SECOND and
    // API_RATE_LIMIT_BURST env vars (defaults: 60 req/s, burst 120).
    let api_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(rate_limit_key_extractor.clone())
            .per_second(crate::config::api_rate_limit_per_second())
            .burst_size(crate::config::api_rate_limit_burst())
            .finish()
            .expect("GovernorConfigBuilder with valid per_second/burst_size must succeed"),
    );

    // Stricter rate limit for the SSE stream endpoint.  Override via
    // SSE_RATE_LIMIT_PER_SECOND / SSE_RATE_LIMIT_BURST env vars.
    let sse_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(rate_limit_key_extractor.clone())
            .per_second(crate::config::sse_rate_limit_per_second())
            .burst_size(crate::config::sse_rate_limit_burst())
            .finish()
            .expect("GovernorConfigBuilder with valid per_second/burst_size must succeed"),
    );

    // Per-IP limit on session *creation* only (POST).  Defaults to 2 req/s with
    // burst of 5 to prevent an authenticated caller from spinning up hundreds of
    // concurrent sessions and exhausting LLM quota / DB connections.  Override
    // via SESSION_RATE_LIMIT_PER_SECOND / SESSION_RATE_LIMIT_BURST env vars
    // (set both to high values in integration-test environments).
    let session_create_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(rate_limit_key_extractor)
            .per_second(crate::config::session_rate_limit_per_second())
            .burst_size(crate::config::session_rate_limit_burst())
            .finish()
            .expect("GovernorConfigBuilder with valid per_second/burst_size must succeed"),
    );

    let stream_router = Router::new()
        .route("/api/stream", get(stream_events))
        .route_layer(GovernorLayer::new(sse_governor_conf));

    // The hook is called once per Claude Code tool call, often several in
    // parallel, so it takes the general API limit, not this one: a 429 makes
    // the hook fail closed and blocks a legitimate call.
    let session_create_router = Router::new()
        .route("/api/sessions", post(create_session))
        .route("/api/chat", post(chat))
        .route("/api/chat/stream", post(chat_stream))
        .route_layer(GovernorLayer::new(session_create_conf));

    let built_router = Router::new()
        .route("/api/sessions", get(list_sessions))
        .merge(session_create_router)
        .route("/api/hook/tool-call", post(hook::tool_call))
        .route("/api/hook/tool-result", post(hook::tool_result))
        .route("/api/sessions/{id}", get(get_session_by_id))
        .route("/api/sessions/{id}/seal", post(seal_session_handler))
        .route("/api/sessions/{id}/events", post(append_event_handler))
        .route("/api/sessions/{id}/verify", get(verify_chain_handler))
        .route(
            "/api/sessions/{id}/verify-intent",
            post(verify_intent_handler),
        )
        .route(
            "/api/sessions/{id}/compliance",
            get(prove_compliance_handler),
        )
        .route("/api/events", get(get_events_json))
        .route("/api/policies", get(list_policies))
        .route(
            "/api/policies/{name}",
            get(get_policy_content)
                .put(save_policy)
                .delete(delete_policy),
        )
        .route("/api/certificates/{session_id}", get(get_certificate))
        .route("/api/reports/{session_id}", get(get_report))
        .route(
            "/api/approvals/{session_id}/pending",
            get(get_pending_approval),
        )
        .route("/api/approvals/{session_id}", post(post_approval_decision))
        .route("/metrics", get(metrics_handler))
        .route("/api/metrics", get(metrics_json_handler))
        .route("/api/metrics/security", get(security_metrics))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/admin/reset-demo", post(reset_demo_data))
        .route(
            "/api/tripwire",
            get(get_tripwire_config).put(put_tripwire_config),
        )
        .route("/api/tripwire/check", post(check_tripwire))
        .route("/api/sessions/{id}/vc", get(get_session_vc))
        .route("/api/sessions/{id}/vc/verify", get(verify_session_vc))
        .route("/api/tokens", get(list_tokens).post(create_token))
        .route("/api/tokens/{hash}", delete(delete_token))
        .route("/api/webhooks", get(list_webhooks).post(create_webhook))
        .route(
            "/api/webhooks/{id}",
            delete(delete_webhook).put(toggle_webhook),
        )
        // The Python SDK uses slightly different endpoint paths.  These aliases
        // ensure both the TS and Python SDKs work against the same backend.
        .route(
            "/api/config/tripwire",
            get(get_tripwire_config).put(put_tripwire_config),
        )
        .route("/api/webhooks/{id}/toggle", put(toggle_webhook))
        .route(
            "/api/sessions/{session_id}/events/stream",
            get(stream_events_by_session),
        )
        .route("/api/sessions/{session_id}/chat", post(session_chat))
        .route(
            "/api/sessions/{session_id}/chat/stream",
            post(session_chat_stream),
        )
        .merge(stream_router)
        .route_layer(GovernorLayer::new(api_governor_conf))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        // Public routes - merged AFTER the auth route_layer so they are
        // accessible without a Bearer token (the index page is static HTML).
        .route("/", get(index))
        .route("/api/status", get(get_status))
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576)) // 1 MiB
        // CORS: explicit origin allowlist. The server binds to 127.0.0.1 by
        // default (see config::bind_host); the allowed origins are the Tauri
        // webview (tauri://localhost) and the local Vite dev server, plus any
        // operator-configured extras via ECTO_CORS_ALLOWED_ORIGINS.
        // Bearer-token auth on the routes above applies regardless of origin.
        .layer(cors_layer())
        .with_state(state);

    (built_router, task_tracker)
}

/// CORS layer with an explicit origin allowlist: the Tauri webview origins,
/// the local Vite dev server, and any extra origins from
/// `ECTO_CORS_ALLOWED_ORIGINS` (comma-separated).
fn cors_layer() -> CorsLayer {
    use axum::http::{HeaderValue, Method, header};
    let mut origins: Vec<HeaderValue> = [
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
        "http://localhost:1420",
        "http://127.0.0.1:1420",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect();
    for extra in crate::config::cors_extra_origins() {
        match extra.parse::<HeaderValue>() {
            Ok(hv) => origins.push(hv),
            Err(_) => tracing::warn!(
                "ECTO_CORS_ALLOWED_ORIGINS entry '{}' is not a valid origin; ignored",
                extra
            ),
        }
    }
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
}

pub fn router(
    pool: DatabasePool,
    metrics: Arc<crate::metrics::Metrics>,
    cancel: CancellationToken,
) -> (Router, TaskTracker) {
    let approvals = Arc::new(ApprovalState::for_pool(&pool));
    router_with_approval_state(pool, metrics, approvals, cancel, None)
}
