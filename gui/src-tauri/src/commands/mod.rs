// Tauri commands, grouped per screen - HTTP proxy to the embedded Axum server on localhost.
// Port and auth token are resolved from the embedded server's global OnceLock
// (populated in `embedded::start`).  Env var overrides are still honoured for
// development against a standalone server.

use serde::Deserialize;
// Used by `open_devtools` (debug builds only) for `app.get_webview_window()`.
use tauri::Emitter;
#[allow(unused_imports)]
use tauri::Manager;

use crate::embedded;

pub mod access;
pub mod app;
pub mod keys;
pub mod policy;
pub mod sessions;
pub mod settings;

/// Overridable in millis so the mock-server tests can exercise the timeout
/// path without an actual multi-second wait; unset in the real app, where
/// `default_ms` applies.
fn env_timeout_ms(var: &str, default_ms: u64) -> std::time::Duration {
    let ms = std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&ms: &u64| ms > 0)
        .unwrap_or(default_ms);
    std::time::Duration::from_millis(ms)
}

/// Shared HTTP client - reuses connection pool across all Tauri commands.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(env_timeout_ms("ECTO_HTTP_CONNECT_TIMEOUT_MS", 5_000))
            .timeout(env_timeout_ms("ECTO_HTTP_TIMEOUT_MS", 30_000))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("reqwest Client::builder() with plain timeouts always succeeds")
    })
}

fn base_url() -> String {
    // 1. Explicit override wins (useful for dev against standalone server).
    if let Ok(host) = std::env::var("ECTO_HOST") {
        return host;
    }
    // 2. Read from the embedded server global.
    if let Some(srv) = embedded::instance() {
        return format!("http://127.0.0.1:{}", srv.port);
    }
    // 3. Legacy fallback.
    let port = std::env::var("ECTO_BIND_PORT").unwrap_or_else(|_| "3000".to_string());
    format!("http://127.0.0.1:{port}")
}

fn obs_token() -> Option<String> {
    // Env var override first.
    if let Ok(t) = std::env::var("OBSERVER_TOKEN")
        && !t.is_empty()
    {
        return Some(t);
    }
    // Then try the embedded server's bootstrap token.
    embedded::instance().map(|s| s.token.clone())
}

fn auth_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = obs_token()
        && let Ok(value) = format!("Bearer {token}").parse()
    {
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    headers
}

/// Strip HTML tags from error response bodies so that styled HTML 404 pages
/// from wrong servers don't flood the GUI error display with raw markup.
fn sanitize_error_body(body: &str) -> String {
    if !body.contains('<') {
        return body.trim().to_string();
    }
    let mut result = String::new();
    let mut in_tag = false;
    for ch in body.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                if !result.ends_with(' ') {
                    result.push(' ');
                }
            }
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    let cleaned: String = result.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        "(empty HTML response - the backend may not be running on the expected port)".to_string()
    } else {
        cleaned
    }
}
