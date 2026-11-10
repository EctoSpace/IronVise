// Embedded Axum backend - starts the IronVise host server in-process so the
// Tauri desktop app is fully self-contained (no separate CLI launch required).
//
// On startup we:
//   1. Point ECTO_DATA_DIR at the Tauri app-data directory (settings + markers).
//   2. Resolve Postgres from DATABASE_URL / settings.json, else local SQLite.
//   3. Run migrations.
//   4. Build the Axum router from `ectoledger::server`.
//   5. Bind to `127.0.0.1:0` (OS-assigned ephemeral port).
//   6. Spawn the server on a background Tokio task.
//
// The server is automatically shut down when the Tauri app exits (the Tokio
// runtime is dropped, cancelling all spawned tasks).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use ectoledger::metrics::Metrics;
use ectoledger::pool;
use ectoledger::server;
use tauri::{Emitter, Manager};
use tokio::net::TcpListener;

/// Opaque handle stored in Tauri managed state **and** in a global `OnceLock`
/// so that `commands.rs` can resolve the base URL / auth token without
/// requiring `tauri::State` on every command signature.
#[derive(Clone)]
pub struct EmbeddedServer {
    /// The `127.0.0.1:<port>` the Axum server is listening on.
    pub port: u16,
    /// Bootstrap admin API token used by the Rust-side IPC proxy commands.
    /// Never handed to the frontend.
    pub token: String,
    /// Read-only (auditor-role) token for the frontend's SSE / observer URLs,
    /// where EventSource cannot send an Authorization header. Leaking this
    /// token exposes read access only - not admin operations.
    pub stream_token: String,
}

/// Global singleton - initialised once in `start()`, read by `commands.rs`.
static INSTANCE: OnceLock<EmbeddedServer> = OnceLock::new();

/// Keep an optional embedded PostgreSQL process alive for the app lifetime.
/// Dropping `PgEmbed` stops the server; the GUI must not do that mid-session.
static KEEP_ALIVE_PG: OnceLock<ectoledger::db_setup::EmbeddedDb> = OnceLock::new();

/// Returns the embedded server info, if started.
pub fn instance() -> Option<&'static EmbeddedServer> {
    INSTANCE.get()
}

/// Resolve the SQLite database path inside the Tauri app-data directory.
///
/// Falls back to `$HOME/.ectoledger/ectoledger.db` when the Tauri path resolver
/// is not available (e.g. during tests).
pub(crate) fn db_path(app: &tauri::AppHandle) -> PathBuf {
    let base = app.path().app_data_dir().unwrap_or_else(|_| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ectoledger")
    });
    std::fs::create_dir_all(&base).ok();
    base.join("ectoledger.db")
}

/// Point `ECTO_DATA_DIR` at the Tauri app-data folder so `settings.json`,
/// tripwire config, and the CLI share one directory with the embedded DB.
fn ensure_data_dir(app: &tauri::AppHandle) -> PathBuf {
    let base = app.path().app_data_dir().unwrap_or_else(|_| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ectoledger")
    });
    std::fs::create_dir_all(&base).ok();
    if std::env::var_os("ECTO_DATA_DIR").is_none() {
        // SAFETY: called once at startup before worker threads use settings.
        unsafe {
            std::env::set_var("ECTO_DATA_DIR", &base);
        }
    }
    base
}

/// Open the ledger pool for the desktop app.
///
/// Postgres when `DATABASE_URL` or `settings.json` asks for it (Custom wizard /
/// Settings); otherwise the local SQLite file. Restart is required after
/// changing the URL - the pool is created once here.
async fn open_pool(
    app: &tauri::AppHandle,
) -> Result<pool::DatabasePool, Box<dyn std::error::Error>> {
    if let Some(pg_url) = pool::resolve_postgres_url_from_config() {
        tracing::info!(
            "Embedded backend requesting PostgreSQL at {}",
            redact_url(&pg_url)
        );
        let (ready_url, embedded) = ectoledger::db_setup::ensure_postgres_ready(&pg_url)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { format!("{e}").into() })?;
        let _ = KEEP_ALIVE_PG.set(embedded);
        // Stamp so /api/config display and any code that reads DATABASE_URL agree
        // with the live pool (without ERROR spam from database_url()).
        // SAFETY: startup, before request handlers run.
        unsafe {
            std::env::set_var("DATABASE_URL", &ready_url);
        }
        let pool = pool::create_postgres_pool(&ready_url)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
        tracing::info!("Embedded PostgreSQL ledger ready.");
        return Ok(pool);
    }

    let path = db_path(app);
    tracing::info!("Embedded SQLite database: {}", path.display());
    let sqlite_url = format!("sqlite://{}", path.display());
    // SAFETY: startup, before request handlers run.
    unsafe {
        std::env::set_var("DATABASE_URL", &sqlite_url);
    }
    pool::create_sqlite_pool(&path)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e })
}

fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("****"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

/// Start the embedded Axum backend and return the assigned port + bootstrap token.
///
/// This must be called from inside `tauri::Builder::setup` (which runs on the
/// Tokio runtime that Tauri owns).
pub async fn start(app: &tauri::AppHandle) -> Result<EmbeddedServer, Box<dyn std::error::Error>> {
    ensure_data_dir(app);

    // The semantic guard is off by default in the desktop app: it costs a
    // model call per action and needs a guard model, so the user turns it on
    // in Settings (the app runs the worker itself, as `<app> --guard-worker`).
    // An explicit GUARD_REQUIRED in the environment is honoured.
    if std::env::var("GUARD_REQUIRED").is_err() {
        // SAFETY: called once at startup before any threads spawn.
        unsafe { std::env::set_var("GUARD_REQUIRED", "false") };
    }

    // The embedded server does not go through the CLI's main(), so emit the
    // same insecure-mode banner here (the Settings panel surfaces it in the UI).
    ectoledger::config::warn_if_insecure_mode();

    // …and the same policy check, for the same reason. `server::router` logs and
    // continues if the policy does not load, which is the right behaviour for a
    // library entry point and the wrong one for a process start: it would leave
    // the GUI serving with the declarative policy layer silently switched off
    // while `ECTO_POLICY_PATH` was set. `docs/guides/configuration.md` says a path that
    // does not load fails startup; this is what makes that true here too.
    ectoledger::policy::ensure_server_policy()?;

    let pool = open_pool(app).await?;

    let raw: [u8; 32] = rand::random();
    let token = hex::encode(raw);
    let token_hash = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(token.as_bytes()))
    };
    // Use the pool's own method so it works for both PG and SQLite.
    // Replaced, not added: each launch's tokens retire the previous launch's.
    pool.replace_labelled_token("gui-bootstrap", &token_hash, "admin")
        .await?;

    // Read-only token for frontend EventSource URLs (?token=…). Auditor role:
    // can read events/streams but cannot create sessions or manage tokens.
    let raw_stream: [u8; 32] = rand::random();
    let stream_token = hex::encode(raw_stream);
    let stream_token_hash = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(stream_token.as_bytes()))
    };
    pool.replace_labelled_token("gui-stream", &stream_token_hash, "auditor")
        .await?;

    // If OBSERVER_TOKEN is configured, register it
    // in the embedded DB too so requests authenticated with it succeed
    // even when ECTO_HOST isn't set.
    if let Ok(env_tok) = std::env::var("OBSERVER_TOKEN")
        && !env_tok.is_empty()
        && env_tok != token
    {
        let env_hash = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(env_tok.as_bytes()))
        };
        if let Err(e) = pool
            .replace_labelled_token("env-observer-token", &env_hash, "admin")
            .await
        {
            tracing::warn!(
                "Failed to register OBSERVER_TOKEN in embedded DB: {e}. Requests using this token may fail with 401."
            );
        }
        tracing::info!("Registered OBSERVER_TOKEN from environment in embedded DB.");
    }

    let metrics = Arc::new(Metrics::default());
    let cancel = tokio_util::sync::CancellationToken::new();
    let (router, _task_tracker) = server::router(pool, metrics, cancel);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let port = addr.port();
    tracing::info!("Embedded server listening on http://127.0.0.1:{port}");

    // Store in global OnceLock so commands.rs can resolve port/token.
    let srv = EmbeddedServer {
        port,
        token: token.clone(),
        stream_token,
    };
    let _ = INSTANCE.set(srv.clone());

    let app_handle = app.clone();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Embedded Axum server exited with error: {e}");
        }
    });

    // Spawn a watcher that emits a Tauri event if the backend dies.
    // Without this, a crashed server leaves the GUI visually functional
    // but every API call silently fails.
    tokio::spawn(async move {
        match server_handle.await {
            Ok(()) => {
                tracing::warn!("Embedded Axum server exited unexpectedly");
                let _ = app_handle.emit("backend-crash", "Server exited");
            }
            Err(e) => {
                tracing::error!("Embedded Axum server panicked: {e}");
                let _ = app_handle.emit("backend-crash", format!("Server panicked: {e}"));
            }
        }
    });

    Ok(srv)
}
