//! Runtime-dispatched database pool abstraction.
//!
//! `DatabasePool` wraps either a PostgreSQL or SQLite connection pool behind a
//! single enum so the server and embedded Tauri backend can work with both
//! engines from a single binary.  Query dispatch uses match-arms - thin runtime
//! cost, zero monomorphisation bloat. The queries are grouped by what they
//! serve: the ledger's events, sessions, API tokens, webhooks, verification,
//! and the `ledger_api` traits.

mod backend;
mod events;
mod sessions;
mod tokens;
mod verification;
mod webhooks;

pub use tokens::TokenRow;
pub use webhooks::WebhookRow;

use sqlx::{PgPool, SqlitePool};
use std::path::Path;

/// Runtime-dispatched database pool.
#[derive(Clone)]
pub enum DatabasePool {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

/// What the live pool can actually do. Derived from the open connection -
/// never from wishful `settings.json` fields that have not taken effect yet.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PoolCapabilities {
    /// `"postgres"` or `"sqlite"`.
    pub ledger_backend: &'static str,
    /// Cognitive loop / Home → Run (PostgreSQL and SQLite).
    pub agent_supported: bool,
    /// `.elc` certificate and HTML report export.
    pub exports_supported: bool,
    /// Webhook egress worker is live (CRUD may still exist on SQLite).
    pub webhooks_live: bool,
}

/// How long a consumed request id is remembered. A replay older than this is
/// no longer recognised; Claude Code never reuses a `tool_use_id`, so the
/// window only has to outlast any plausible capture-and-resend.
pub const REPLAY_RETENTION_DAYS: i64 = 30;

impl DatabasePool {
    /// The PostgreSQL pool, or `None` on SQLite.
    pub fn as_pg(&self) -> Option<&PgPool> {
        match self {
            Self::Postgres(p) => Some(p),
            _ => None,
        }
    }

    /// The SQLite pool, or `None` on PostgreSQL.
    pub fn as_sqlite(&self) -> Option<&SqlitePool> {
        match self {
            Self::Sqlite(p) => Some(p),
            _ => None,
        }
    }

    /// Capability flags for the GUI and `/api/status`.
    pub fn capabilities(&self) -> PoolCapabilities {
        match self {
            Self::Postgres(_) => PoolCapabilities {
                ledger_backend: "postgres",
                agent_supported: true,
                exports_supported: true,
                webhooks_live: true,
            },
            Self::Sqlite(_) => PoolCapabilities {
                ledger_backend: "sqlite",
                agent_supported: true,
                exports_supported: true,
                webhooks_live: true,
            },
        }
    }
}

/// Most events `stream_events_since` returns at once. A full batch means more
/// may be waiting, so a stream asks again at once instead of waiting for the
/// next write.
pub const STREAM_BATCH_SIZE: usize = 100;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Connect options for the ledger at `path`, keyed when SQLCipher is built in:
/// the key is a pragma of the options, so every connection the pool opens
/// gets it first. `:memory:` becomes sqlx's shared in-memory database, so all
/// connections in a pool see the same one.
fn sqlite_options(
    path: &Path,
    read_only: bool,
) -> Result<sqlx::sqlite::SqliteConnectOptions, BoxError> {
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr;
    let opts = if path == Path::new(":memory:") {
        SqliteConnectOptions::from_str("sqlite::memory:")?
    } else {
        SqliteConnectOptions::new().filename(path)
    };
    // Per connection, like the key: retry transient locks for 5 seconds
    // rather than failing at once (file locks contend most on Windows).
    let opts = opts.busy_timeout(std::time::Duration::from_secs(5));
    let opts = if read_only {
        opts.read_only(true)
    } else {
        opts.create_if_missing(true)
    };
    #[cfg(feature = "sqlcipher")]
    let opts = crate::sqlcipher::keyed(opts, crate::sqlcipher::read_sqlcipher_key()?);
    Ok(opts)
}

/// Create a new SQLite pool at `path`, running all migrations.
/// Creates parent directories and the file if they do not exist.
pub async fn create_sqlite_pool(path: &Path) -> Result<DatabasePool, BoxError> {
    Ok(DatabasePool::Sqlite(open_sqlite_ledger(path).await?))
}

/// [`create_sqlite_pool`] without the enum, for callers that need SQLite.
pub(crate) async fn open_sqlite_ledger(path: &Path) -> Result<SqlitePool, BoxError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(sqlite_options(path, false)?)
        .await?;
    #[cfg(feature = "sqlcipher")]
    crate::sqlcipher::check_pool(&pool).await?;

    // WAL is a property of the file, so setting it once covers every connection.
    sqlx::query("PRAGMA journal_mode=WAL;")
        .execute(&pool)
        .await?;

    // Run all SQLite migrations.
    crate::migrations::migrate_sqlite(&pool)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    Ok(pool)
}

/// Open an existing SQLite ledger strictly read-only.
///
/// [`create_sqlite_pool`] is the wrong tool for inspecting a ledger you do not
/// own: `mode=rwc` creates the file when it is absent, `PRAGMA journal_mode=WAL`
/// rewrites the database header, and the migrations then rewrite the schema. A
/// command documented as read-only must do none of those to a ledger it has
/// been handed as evidence.
///
/// `mode=ro` makes SQLite itself refuse writes, so this is enforced by the
/// driver rather than by convention. Migrations are deliberately not run: a
/// ledger written by an older schema is surveyed as it stands, which is the
/// point - silently upgrading the artifact under inspection is the behaviour
/// being removed.
pub async fn open_sqlite_pool_read_only(path: &Path) -> Result<DatabasePool, BoxError> {
    if !path.exists() {
        return Err(format!(
            "no SQLite ledger at '{}' - read-only mode will not create one",
            path.display()
        )
        .into());
    }
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(sqlite_options(path, true)?)
        .await?;
    #[cfg(feature = "sqlcipher")]
    crate::sqlcipher::check_pool(&pool).await?;
    Ok(DatabasePool::Sqlite(pool))
}

/// Connect to PostgreSQL at `url`, run migrations, and wrap the pool.
pub async fn create_postgres_pool(
    url: &str,
) -> Result<DatabasePool, Box<dyn std::error::Error + Send + Sync>> {
    let pool_size = crate::config::database_pool_size();
    let pg = sqlx::postgres::PgPoolOptions::new()
        .max_connections(pool_size)
        .min_connections(1)
        .idle_timeout(std::time::Duration::from_secs(600))
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(url)
        .await?;

    crate::migrations::migrate_postgres(&pg)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    Ok(DatabasePool::Postgres(pg))
}

/// True when `url` selects the PostgreSQL transport.
pub fn is_postgres_url(url: &str) -> bool {
    let u = url.trim().to_ascii_lowercase();
    u.starts_with("postgres://") || u.starts_with("postgresql://")
}

/// Resolve a Postgres URL for the embedded GUI / server start.
///
/// Precedence: `DATABASE_URL` env, then `settings.json` `database_url`.
/// Returns `None` when the operator has not asked for Postgres (SQLite path).
pub fn resolve_postgres_url_from_config() -> Option<String> {
    if let Ok(env_url) = std::env::var("DATABASE_URL") {
        let trimmed = env_url.trim().to_string();
        if is_postgres_url(&trimmed) {
            return Some(trimmed);
        }
        // Explicit sqlite:// (or anything else) → do not open Postgres.
        if !trimmed.is_empty() {
            return None;
        }
    }
    crate::config::load_settings_config()
        .and_then(|c| c.database_url)
        .map(|s| s.trim().to_string())
        .filter(|s| is_postgres_url(s))
}

#[cfg(test)]
mod capability_tests;
#[cfg(test)]
mod finish_session_tests;
#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod reset_tests;
#[cfg(test)]
mod token_tests;
