//! Opening the ledger a command runs against, and the checks before any
//! command uses it.

use super::BoxError;
use super::exit::cannot_survey;
use crate::Commands;
use ectoledger::pool::DatabasePool;
use ectoledger::{config, db_setup, ledger};
use sqlx::postgres::PgPoolOptions;

/// The open ledger, and the embedded PostgreSQL serving it, if one was
/// started: it must outlive the command.
pub struct Ledger {
    pub pool: DatabasePool,
    pub embedded: Option<db_setup::EmbeddedDb>,
}

/// What a command may do to the ledger it opens.
struct Access {
    /// `verify-ledger` is documented as read-only and is pointed at ledgers
    /// the operator may not own, evidence handed over for inspection among
    /// them. Ordinary start-up migrates and seeds the OBSERVER_TOKEN, so
    /// merely surveying a ledger once rewrote its schema and added a row. A
    /// read-only command does neither, and the driver enforces it.
    read_only: bool,
    /// Only a command that serves the API has a token to register. On SQLite
    /// registering replaces the bootstrapped admin row, so when every command
    /// did it, `verify-session` run beside a live `serve` locked that server,
    /// and the Claude Code hook calling it, out with 401s.
    serves_api: bool,
}

/// Opens the ledger `DATABASE_URL` names, migrated and ready for `command`.
pub async fn open(command: &Commands) -> Result<Ledger, BoxError> {
    let url = database_url_or_exit();
    let access = Access {
        read_only: matches!(command, Commands::VerifyLedger { .. }),
        serves_api: matches!(command, Commands::Serve { .. } | Commands::Audit { .. }),
    };
    if !is_sqlite_url(&url) {
        return open_postgres(&url, &access).await;
    }
    if matches!(
        command,
        Commands::Orchestrate { .. } | Commands::DiffAudit { .. } | Commands::RedTeam { .. }
    ) {
        return Err("This command requires PostgreSQL. \
             SQLite mode does not support multi-agent orchestration yet. \
             Set DATABASE_URL to a postgres:// URL and try again."
            .into());
    }
    open_sqlite(&url, &access).await
}

/// `DATABASE_URL`, or the three working ways to set it and exit 1. A bare
/// `NotPresent` tells a first-time user nothing.
fn database_url_or_exit() -> String {
    config::database_url().unwrap_or_else(|_| {
        eprintln!(
            "\nDATABASE_URL is not set.\n\n\
             Pick one:\n  \
             • Zero infrastructure (no Docker, no server):\n      \
             export DATABASE_URL=sqlite://ectoledger.db\n  \
             • An existing PostgreSQL instance:\n      \
             export DATABASE_URL=postgres://user:pass@localhost:5432/ectoledger\n  \
             • Local development with embedded PostgreSQL and default credentials:\n      \
             export ECTO_DEV_MODE=true\n\n\
             See docs/getting-started/quickstart.md and docs/getting-started/running-securely.md.\n"
        );
        std::process::exit(1);
    })
}

async fn open_sqlite(url: &str, access: &Access) -> Result<Ledger, BoxError> {
    let db_path = sqlite_path_from_url(url).unwrap_or_else(|| {
        db_setup::app_data_dir()
            .join("ectoledger")
            .join("ledger.db")
    });
    let pool = if access.read_only {
        match ectoledger::pool::open_sqlite_pool_read_only(&db_path).await {
            Ok(p) => p,
            // Exit 2, not 1: "there is no ledger here" is the survey being
            // unable to run, which a script must be able to tell apart from
            // `--strict` finding a session that does not verify. See the
            // exit-code contract on `Commands::VerifyLedger`.
            Err(e) => return Err(cannot_survey(&e)),
        }
    } else {
        ectoledger::pool::create_sqlite_pool(&db_path).await?
    };

    // Bearer-token auth then works out of the box, the in-memory database of
    // the integration tests included.
    if access.serves_api {
        match pool
            .replace_labelled_token(
                "observer_token (bootstrapped)",
                &observer_token_hash(),
                "admin",
            )
            .await
        {
            Ok(_) => tracing::info!("OBSERVER_TOKEN registered as admin in api_tokens (SQLite)."),
            Err(e) => tracing::warn!("Failed to seed OBSERVER_TOKEN into api_tokens: {e}"),
        }
    }
    Ok(Ledger {
        pool,
        embedded: None,
    })
}

async fn open_postgres(url: &str, access: &Access) -> Result<Ledger, BoxError> {
    // A survey reads a ledger that exists: it must not start an embedded
    // server, and a database it cannot reach is "could not survey" (exit 2),
    // as a missing SQLite file is.
    let (database_url, embedded) = if access.read_only {
        (url.to_string(), None)
    } else {
        // Printed with Display: these errors carry multi-line hints (a port
        // conflict, for one) that Debug would escape into one unreadable line.
        match db_setup::ensure_postgres_ready(url).await {
            Ok((database_url, embedded)) => (database_url, Some(embedded)),
            Err(e) => {
                eprintln!("\n{e}\n");
                std::process::exit(1);
            }
        }
    };

    // Sized so multi-agent runs do not exhaust connections: 2×CPU, between 5
    // and 50, unless DATABASE_POOL_SIZE says otherwise.
    let mut pg_options = PgPoolOptions::new()
        .max_connections(config::database_pool_size())
        .min_connections(1)
        .idle_timeout(std::time::Duration::from_secs(600))
        .acquire_timeout(std::time::Duration::from_secs(30));
    if access.read_only {
        // PostgreSQL has no read-only equivalent of SQLite's `mode=ro`, so
        // the nearest thing is refusing writes at the transaction level.
        // It has to be set per connection: `SET` affects only the session
        // that runs it, so issuing it once against the pool would leave
        // every other pooled connection writable and give a false sense of
        // protection. `after_connect` runs it on each one.
        pg_options = pg_options.after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_read_only = on")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        });
    }
    let pg = match pg_options.connect(&database_url).await {
        Ok(pg) => pg,
        Err(e) if access.read_only => return Err(cannot_survey(&e)),
        Err(e) => return Err(e.into()),
    };
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pg)
        .await?;
    tracing::info!("Database connected (PostgreSQL).");

    if !access.read_only {
        ectoledger::migrations::migrate_postgres(&pg).await?;
    }
    // Idempotent: the same token across restarts is a no-op.
    if access.serves_api {
        match sqlx::query(
            "INSERT INTO api_tokens (token_hash, role, label) \
             VALUES ($1, 'admin', 'observer_token (bootstrapped)') \
             ON CONFLICT (token_hash) DO NOTHING",
        )
        .bind(observer_token_hash())
        .execute(&pg)
        .await
        {
            Ok(_) => tracing::info!("OBSERVER_TOKEN registered as admin in api_tokens."),
            Err(e) => tracing::warn!("Failed to seed OBSERVER_TOKEN into api_tokens: {e}"),
        }
    }
    Ok(Ledger {
        pool: DatabasePool::Postgres(pg),
        embedded,
    })
}

/// The OBSERVER_TOKEN as stored in api_tokens, so it authenticates as admin.
fn observer_token_hash() -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(config::observer_token().as_bytes()))
}

/// Verifies the latest 1,000 events (every event with `--verify-full`) and
/// writes genesis on a new ledger.
pub async fn check(command: &Commands, backend: &DatabasePool) -> Result<(), BoxError> {
    let read_only_command = matches!(command, Commands::VerifyLedger { .. });
    let verify_full = match command {
        Commands::Serve { verify_full, .. } | Commands::Audit { verify_full, .. } => *verify_full,
        _ => false,
    };
    // `verify-ledger` is the tool you reach for *because* the ledger might be
    // bad. Aborting here would mean the only command that can explain a broken
    // ledger is the one command that refuses to open one, so it surveys instead
    // and reports what it finds.
    //
    // The guard has to short-circuit before `get_latest()`, not after: since
    // this command does not run migrations, pointing it at a database with no
    // ledger schema makes that call fail, and `?` would surface a raw driver
    // error from here instead of the command's own explanation.
    if !read_only_command && let Some((latest_seq, _)) = backend.get_latest().await? {
        let from = if verify_full {
            0
        } else {
            (latest_seq - 999).max(0)
        };
        let to = latest_seq;
        let chain_ok = match &backend {
            ectoledger::pool::DatabasePool::Postgres(p) => {
                ledger::verify_chain(p, from, to).await?
            }
            ectoledger::pool::DatabasePool::Sqlite(p) => {
                ledger::sqlite::verify_chain_sqlite(p, from, to).await?
            }
        };
        if !chain_ok {
            return Err("Ledger chain verification failed: tampering detected.".into());
        }
    }

    // Skipped for the read-only survey. This *appends* a genesis event when one
    // is absent, so running it would have `verify-ledger` write the very first
    // entry of a chain it was only asked to read - and against a `mode=ro` pool
    // it cannot succeed anyway.
    if !read_only_command {
        let appended = backend.ensure_genesis().await?;
        if appended.sequence == 0 {
            tracing::info!("Genesis block created.");
        } else {
            tracing::info!(
                "Genesis already present; latest sequence = {}.",
                appended.sequence
            );
        }
    }
    Ok(())
}

fn is_sqlite_url(url: &str) -> bool {
    url.starts_with("sqlite:") || url.starts_with("sqlite://")
}

/// `C:/...` or `C:\...` after the `sqlite:///` prefix. A drive letter is an
/// absolute path; it must not gain another leading slash.
fn windows_drive_path(rest: &str) -> bool {
    let b = rest.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
}

/// Extract a filesystem path from a SQLite DATABASE_URL.
///
/// Handles the common variants:
///   sqlite:ledger.db      → ledger.db
///   sqlite://ledger.db    → ledger.db
///   sqlite:///tmp/l.db    → /tmp/l.db
///   sqlite:///C:/l.db     → C:/l.db
///   sqlite::memory:       → :memory:  (in-memory, no file)
fn sqlite_path_from_url(url: &str) -> Option<std::path::PathBuf> {
    let path_str = if let Some(rest) = url.strip_prefix("sqlite:///") {
        // sqlite:///tmp/l.db → /tmp/l.db. A Windows drive is already absolute:
        // sqlite:///C:/l.db must stay C:/l.db. Prefixing `/` makes `/C:/l.db`,
        // which Windows rejects.
        if windows_drive_path(rest) {
            rest.to_string()
        } else {
            format!("/{rest}")
        }
    } else if let Some(rest) = url.strip_prefix("sqlite://") {
        rest.to_string()
    } else if let Some(rest) = url.strip_prefix("sqlite:") {
        rest.to_string()
    } else {
        url.to_string()
    };
    // `:memory:` is passed through: create_sqlite_pool opens sqlx's shared
    // in-memory database for it. Mapping it to None would fall back to the
    // default ledger file, and `DATABASE_URL=sqlite::memory:` would persist.
    if path_str.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(path_str))
    }
}

#[cfg(test)]
mod sqlite_url_tests {
    use super::sqlite_path_from_url;
    use std::path::PathBuf;

    #[test]
    fn memory_stays_in_memory_and_paths_are_paths() {
        // `:memory:` must reach create_sqlite_pool, which opens an in-memory
        // database; None would fall back to the persistent default ledger.
        assert_eq!(
            sqlite_path_from_url("sqlite::memory:"),
            Some(PathBuf::from(":memory:"))
        );
        assert_eq!(
            sqlite_path_from_url("sqlite:///tmp/l.db"),
            Some(PathBuf::from("/tmp/l.db"))
        );
        assert_eq!(
            sqlite_path_from_url("sqlite:///C:/ledger/ectoledger.db"),
            Some(PathBuf::from("C:/ledger/ectoledger.db"))
        );
        assert_eq!(
            sqlite_path_from_url(r"sqlite:///C:\ledger\ectoledger.db"),
            Some(PathBuf::from(r"C:\ledger\ectoledger.db"))
        );
        assert_eq!(
            sqlite_path_from_url(r"sqlite://C:\ledger\ectoledger.db"),
            Some(PathBuf::from(r"C:\ledger\ectoledger.db"))
        );
        assert_eq!(
            sqlite_path_from_url("sqlite:l.db"),
            Some(PathBuf::from("l.db"))
        );
        assert_eq!(sqlite_path_from_url("sqlite:"), None);
    }
}
