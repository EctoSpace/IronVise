//! The ledger database: `DATABASE_URL`, demo and dev modes, the pool size.

use super::*;

pub(super) const DEFAULT_DATABASE_URL: &str =
    "postgres://ectoledger:ectoledger@localhost:5432/ectoledger";

/// Returns true when ECTO_DEMO_MODE=true|1 is set (demo launcher flag).
pub fn is_demo_mode() -> bool {
    std::env::var("ECTO_DEMO_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Returns true when the process is running in developer/test mode.
/// Production deployments should never set ECTO_DEV_MODE.
pub fn is_dev_mode() -> bool {
    std::env::var("ECTO_DEV_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn database_url() -> Result<String, std::env::VarError> {
    match std::env::var("DATABASE_URL") {
        Ok(s) => Ok(s),
        Err(std::env::VarError::NotPresent) => {
            if is_dev_mode() {
                tracing::info!(
                    "DATABASE_URL not set - using default dev credentials (ECTO_DEV_MODE=true)."
                );
                Ok(DEFAULT_DATABASE_URL.to_string())
            } else {
                tracing::error!(
                    "DATABASE_URL not set. Set DATABASE_URL explicitly for production, \
                     or set ECTO_DEV_MODE=true to use default dev credentials."
                );
                Err(std::env::VarError::NotPresent)
            }
        }
        Err(e) => Err(e),
    }
}

/// URL for Settings / `/api/config` display - never ERROR-logs.
///
/// The embedded desktop app opens SQLite by path and may leave `DATABASE_URL`
/// unset; calling [`database_url`] on every config poll spammed the terminal.
pub fn database_url_display() -> String {
    if let Ok(s) = std::env::var("DATABASE_URL") {
        let t = s.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Some(s) = load_settings_config()
        .and_then(|c| c.database_url)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return s;
    }
    String::new()
}

/// Database connection-pool size.
/// Env: `DATABASE_POOL_SIZE`. Default: `2 × CPU count`, clamped to `[5, 50]`.
/// The clamp is applied to the **final** value regardless of whether it came
/// from the environment variable or the CPU-based default.
pub fn database_pool_size() -> u32 {
    std::env::var("DATABASE_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4);
            cpus * 2
        })
        .clamp(5, 50)
}
