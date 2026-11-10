//! The Observer server: its token, bind address, CORS, rate limits, trusted
//! proxies and the insecure-mode warning.

use super::*;
use std::sync::OnceLock;

pub(super) static OBSERVER_TOKEN_CACHE: OnceLock<String> = OnceLock::new();

/// Token for Observer dashboard auth. Env: OBSERVER_TOKEN.
/// If unset, a 32-byte hex token is generated and printed to stdout for this process.
/// API requests send it as `Authorization: Bearer`; `?token=` is taken only
/// where a browser cannot send a header (event streams, `/metrics`).
pub fn observer_token() -> String {
    OBSERVER_TOKEN_CACHE
        .get_or_init(|| {
            std::env::var("OBSERVER_TOKEN")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    let token = hex::encode(rand::random::<[u8; 32]>());
                    let host = bind_host();
                    let port = bind_port();
                    let display_host = if host == "0.0.0.0" {
                        "localhost".to_string()
                    } else {
                        host
                    };
                    println!(
                        "⚠️  No OBSERVER_TOKEN set. Generated token for this session: {token}"
                    );
                    println!("    Dashboard: http://{display_host}:{port}?token={token}");
                    token
                })
        })
        .clone()
}

/// Emits a single WARN banner when the process is running with demo-grade
/// security settings, naming each one.
///
/// The demo image and `docker-compose.demo.yml` ship `GUARD_REQUIRED=false`,
/// `ECTO_DEV_MODE=true`, and a `0.0.0.0` bind. That is a reasonable trade for a
/// zero-friction first run, but it must never be mistaken for a production
/// posture - so the running server says so out loud, regardless of how it was
/// launched. Returns the list of active weakenings (empty when hardened) so
/// callers and tests can inspect the same decision.
pub fn insecure_mode_reasons() -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if !guard_required() {
        reasons.push("semantic guard disabled (GUARD_REQUIRED=false)");
    }
    if is_dev_mode() {
        reasons.push("dev mode on (ECTO_DEV_MODE=true)");
    }
    reasons
}

/// Report the effective value of each security-relevant setting, and what
/// decided it, at startup.
///
/// An operator who exports `GUARD_REQUIRED=true` and gets no guard deserves to
/// find out from the log rather than from an incident. The line is emitted
/// whether the configuration is hardened or not: "it is on, and here is why" is
/// as worth knowing as the warning.
pub fn log_effective_security_settings() {
    let (guard, source) = guard_required_effective();
    if source == SettingSource::StricterOfTwo {
        tracing::warn!(
            "GUARD_REQUIRED: the environment and .ectoledger/settings.json disagree. \
             The guard is REQUIRED, because a security control is resolved \
             most-restrictive-wins - see docs/guides/configuration.md"
        );
    } else {
        tracing::info!("guard_required = {guard} (from: {})", source.as_str());
    }
}

/// Logs the insecure-mode banner if any demo-grade setting is active.
/// Call once during startup.
pub fn warn_if_insecure_mode() {
    log_effective_security_settings();
    let reasons = insecure_mode_reasons();
    if reasons.is_empty() {
        return;
    }
    let host = bind_host();
    let exposure = if host == "0.0.0.0" {
        " - and the dashboard is bound to all interfaces (ECTO_BIND_HOST=0.0.0.0)"
    } else {
        ""
    };
    tracing::warn!(
        "INSECURE DEMO MODE: {}{}. Do not use in production - see docs/getting-started/running-securely.md",
        reasons.join(" / "),
        exposure
    );
}

/// Host address for the Observer dashboard TCP listener.
/// Env: `ECTO_BIND_HOST`, default `"127.0.0.1"` (loopback only).
/// Set to `"0.0.0.0"` explicitly to expose the dashboard on all interfaces;
/// doing so makes the Bearer token the only access control, so front it with
/// TLS and a reverse proxy in that configuration.
pub fn bind_host() -> String {
    std::env::var("ECTO_BIND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Extra origins allowed by the Observer API's CORS layer, comma-separated.
/// Env: `ECTO_CORS_ALLOWED_ORIGINS`, default empty. The Tauri webview origins
/// and the local Vite dev server are always allowed; see `server::cors_layer`.
pub fn cors_extra_origins() -> Vec<String> {
    std::env::var("ECTO_CORS_ALLOWED_ORIGINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Port for the Observer dashboard TCP listener.
/// Env: `ECTO_BIND_PORT`, default `3000`.
/// Set to `0` to let the OS assign a free port (useful in integration test suites).
///
/// **Panics** if `ECTO_BIND_PORT` is set but cannot be parsed as a `u16`.
pub fn bind_port() -> u16 {
    match std::env::var("ECTO_BIND_PORT") {
        Ok(s) => s
            .parse::<u16>()
            .unwrap_or_else(|e| panic!("ECTO_BIND_PORT='{s}' is not a valid u16 port number: {e}")),
        Err(_) => 3000,
    }
}

/// Per-IP rate limit for `POST /api/sessions` (and `/api/chat`) - requests per second.
/// Env: `SESSION_RATE_LIMIT_PER_SECOND`, default `2`.
/// Set to a high value (e.g. `1000`) in integration-test environments.
pub fn session_rate_limit_per_second() -> u64 {
    std::env::var("SESSION_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2)
}

/// Burst allowance for the `POST /api/sessions` rate limiter.
/// Env: `SESSION_RATE_LIMIT_BURST`, default `5`.
pub fn session_rate_limit_burst() -> u32 {
    std::env::var("SESSION_RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}

/// SSE keep-alive interval (seconds). Env: `SSE_KEEPALIVE_SECS`, default `15`.
/// Lower this in integration-test environments so keepalive events arrive
/// before pytest's global timeout fires.
pub fn sse_keepalive_secs() -> u64 {
    std::env::var("SSE_KEEPALIVE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15)
}

/// Global per-IP API rate limit - requests per second.
/// Env: `API_RATE_LIMIT_PER_SECOND`, default `60`.
pub fn api_rate_limit_per_second() -> u64 {
    std::env::var("API_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60)
}

/// Burst allowance for the global API rate limiter.
/// Env: `API_RATE_LIMIT_BURST`, default `120`.
pub fn api_rate_limit_burst() -> u32 {
    std::env::var("API_RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120)
}

/// Per-IP rate limit for the SSE `GET /api/stream` endpoint - connections per second.
/// Env: `SSE_RATE_LIMIT_PER_SECOND`, default `4`.
/// Set to a high value in integration-test environments.
pub fn sse_rate_limit_per_second() -> u64 {
    std::env::var("SSE_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4)
}

/// Reverse-proxy addresses allowed to set the rate-limit client IP via the
/// `X-Forwarded-For`, `X-Real-Ip` or `Forwarded` headers (comma-separated
/// IPs or CIDRs, e.g. `127.0.0.1,10.0.0.0/8`). Env: `ECTO_TRUSTED_PROXIES`,
/// default empty - meaning these headers are never trusted and the TCP
/// socket peer address is always the key, so a caller cannot evade its own
/// rate limit by sending a fresh spoofed header per request. Parsing and
/// validation (CIDR, malformed entries) happen where this is consumed; see
/// `server::auth::TrustedProxyKeyExtractor`.
pub fn trusted_proxies() -> Vec<String> {
    std::env::var("ECTO_TRUSTED_PROXIES")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Burst allowance for the SSE stream rate limiter.
/// Env: `SSE_RATE_LIMIT_BURST`, default `10`.
pub fn sse_rate_limit_burst() -> u32 {
    std::env::var("SSE_RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
}
