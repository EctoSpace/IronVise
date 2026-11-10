//! Webhook egress: destination, signing secret, rate limit and filters.

/// Configuration for outbound webhook / SIEM egress.
/// Set `WEBHOOK_URL` to enable; `WEBHOOK_BEARER_TOKEN` and `SIEM_FORMAT` are optional.
#[derive(Clone, Debug)]
pub struct WebhookConfig {
    /// Full URL to POST security events to (e.g. Slack, Splunk HEC, custom SIEM endpoint).
    pub url: String,
    /// Optional `Authorization: Bearer <token>` header value.
    pub bearer_token: Option<String>,
    /// Output format: `json` (default), `cef` (ArcSight CEF), or `leef` (IBM LEEF).
    pub siem_format: String,
}

/// Returns `Some(WebhookConfig)` when `WEBHOOK_URL` is set, otherwise `None` (egress disabled).
pub fn webhook_config() -> Option<WebhookConfig> {
    let url = std::env::var("WEBHOOK_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    let bearer_token = std::env::var("WEBHOOK_BEARER_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let siem_format = std::env::var("SIEM_FORMAT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "json".to_string());
    Some(WebhookConfig {
        url,
        bearer_token,
        siem_format,
    })
}

/// HMAC-SHA256 secret for signing outbound webhook payloads.
/// When set, every webhook POST includes an `X-EctoLedger-Signature: sha256=<hex>` header
/// so receivers can verify authenticity (GitHub webhook signature convention).
/// Env: `WEBHOOK_HMAC_SECRET`. Default: `None` (signing disabled).
pub fn webhook_hmac_secret() -> Option<String> {
    std::env::var("WEBHOOK_HMAC_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
}

/// `WEBHOOK_LEGACY_SIGNATURE=true` adds the pre-0.8 body-only signature, which
/// any receiver can replay to any other. Off by default.
pub fn webhook_legacy_signature() -> bool {
    std::env::var("WEBHOOK_LEGACY_SIGNATURE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Maximum outbound webhook deliveries per second, per target URL.
/// Env: `WEBHOOK_RATE_LIMIT_PER_SECOND`, default `10`.
pub fn webhook_rate_limit_per_second() -> u64 {
    std::env::var("WEBHOOK_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
}

/// Whether to forward `GuardDenial` events to the webhook egress worker.
/// Env: `WEBHOOK_INCLUDE_GUARD`, default `true`.
/// Set `false` (or `0`) to suppress guard-denial events from SIEM egress.
pub fn webhook_include_guard() -> bool {
    std::env::var("WEBHOOK_INCLUDE_GUARD")
        .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0"))
        .unwrap_or(true)
}

/// Whether to forward `TripwireRejection` events to the webhook egress worker.
/// Env: `WEBHOOK_INCLUDE_TRIPWIRE`, default `true`.
/// Set `false` (or `0`) to suppress tripwire-rejection events from SIEM egress.
pub fn webhook_include_tripwire() -> bool {
    std::env::var("WEBHOOK_INCLUDE_TRIPWIRE")
        .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0"))
        .unwrap_or(true)
}
