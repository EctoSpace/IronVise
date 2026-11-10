// Async webhook / SIEM egress dispatcher.
//
// When WEBHOOK_URL is set, security events are forwarded to an external endpoint
// in the background without blocking the cognitive loop.
//
// Supported SIEM_FORMAT values:
//   json  - standard JSON body (default, works with Slack, custom endpoints, Splunk HEC)
//   cef   - ArcSight Common Event Format (syslog-style header line)
//   leef  - IBM LEEF 2.0 (tab-separated key-value pairs)
//
// Security env vars:
//   WEBHOOK_HMAC_SECRET=<secret>   - signs each POST for its receiver (see `signed_headers`)
//   WEBHOOK_LEGACY_SIGNATURE=true  - also send the pre-0.8 body-only X-EctoLedger-Signature
//   WEBHOOK_INCLUDE_GUARD=true     - also fire for GuardDenial events (default: true)
//   WEBHOOK_INCLUDE_TRIPWIRE=true  - also fire for TripwireRejection events (default: true)
//
// Rate / capacity:
//   WEBHOOK_RATE_LIMIT_PER_SECOND  - max deliveries per second per URL (default: 10)
//   CHANNEL_CAPACITY (256)         - event queue depth; excess events are logged and dropped
//                                    to keep the agent cognitive loop non-blocking.

use crate::config::{self, WebhookConfig};
use crate::pool::DatabasePool;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use uuid::Uuid;

const CHANNEL_CAPACITY: usize = 256;
/// Maximum number of HTTP retry attempts for a single webhook delivery.
const MAX_RETRIES: u32 = 3;

/// Kind of security event being dispatched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressKind {
    /// An observation rule flagged or aborted the session.
    Observation,
    /// The semantic guard process denied a hostile action.
    GuardDenial,
    /// A tripwire pattern was matched and the action was rejected.
    TripwireRejection,
}

impl EgressKind {
    fn as_str(&self) -> &'static str {
        match self {
            EgressKind::Observation => "observation",
            EgressKind::GuardDenial => "guard_denial",
            EgressKind::TripwireRejection => "tripwire_rejection",
        }
    }
}

/// A security event dispatched from the cognitive loop to the egress worker.
#[derive(Clone, Debug)]
pub struct EgressEvent {
    pub session_id: Uuid,
    /// `"flag"` when an observation rule triggers a warning, `"abort"` when it terminates the session.
    pub severity: String,
    /// Short label from the `ObservationRule` / guard / tripwire that matched.
    pub rule_label: String,
    /// First 200 chars of the sanitized observation content (no raw secrets).
    pub observation_preview: String,
    /// Category of event being reported.
    pub kind: EgressKind,
}

/// The `observation_preview` for `text`: its first 200 characters. Callers
/// pass text that the scanner and the policy's redact rules have already seen.
pub fn preview(text: &str) -> String {
    text.chars().take(200).collect()
}

/// Spawns the background egress worker and returns the sender end of its channel.
/// The worker dispatches to:
///   1. The legacy `WEBHOOK_URL` env-var target (if `config` is `Some`), with retry.
///   2. Any active rows in the `webhooks` database table created via the API.
///
/// The worker runs until all senders are dropped.
///
/// The channel is bounded to `CHANNEL_CAPACITY`. Callers should prefer
/// `try_enqueue_event` over direct `.send()` to avoid blocking the cognitive loop
/// when the worker cannot keep up with event production.
pub fn spawn_egress_worker(
    config: Option<WebhookConfig>,
    pool: DatabasePool,
) -> (mpsc::Sender<EgressEvent>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<EgressEvent>(CHANNEL_CAPACITY);
    if config::webhook_legacy_signature() {
        tracing::warn!(
            "WEBHOOK_LEGACY_SIGNATURE is on: deliveries also carry the pre-0.8 body-only \
             X-EctoLedger-Signature, which any receiver can replay to any other"
        );
    }
    let handle = tokio::spawn(async move {
        loop {
            let result =
                std::panic::AssertUnwindSafe(egress_loop(config.clone(), pool.clone(), &mut rx));
            match futures_util::FutureExt::catch_unwind(result).await {
                Ok(()) => {
                    tracing::info!("Webhook egress worker shutting down (all senders dropped)");
                    break;
                }
                Err(e) => {
                    // The receiver is passed by &mut reference, so it survives
                    // the panicked future.  Log, back off briefly, and restart.
                    tracing::error!(
                        "webhook egress_loop panicked: {:?} - restarting worker in 1s",
                        e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    });
    (tx, handle)
}

/// Non-blocking enqueue: attempts `try_send`; on a full channel the event is
/// immediately dropped with a warning.  This prevents unbounded task spawning
/// under sustained load (DoS) while keeping the cognitive loop non-blocking.
pub fn try_enqueue_event(tx: &mpsc::Sender<EgressEvent>, event: EgressEvent) {
    match tx.try_send(event) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(ev)) => {
            tracing::warn!(
                "Webhook egress channel full (capacity {}); dropping {} event for session {}. System is under heavy load.",
                CHANNEL_CAPACITY,
                ev.kind.as_str(),
                ev.session_id
            );
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("Webhook egress channel closed; event dropped.");
        }
    }
}

/// Domain separation for the two uses of `WEBHOOK_HMAC_SECRET`.
const RECEIVER_KEY_CONTEXT: &str = "ectoledger-webhook-key-v1";
const SIGNATURE_CONTEXT: &str = "ectoledger-webhook-v1";
/// How far a receiver should let `X-EctoLedger-Timestamp` drift, in seconds.
/// Retries reuse the first attempt's timestamp and finish well inside it.
pub const WEBHOOK_TOLERANCE_SECS: i64 = 300;

fn hmac_sha256(key: &[u8], parts: &[&str]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC takes a key of any length");
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            mac.update(b"\n");
        }
        mac.update(part.as_bytes());
    }
    mac.finalize().into_bytes().into()
}

/// The key one receiver verifies with, derived from the server secret and the
/// receiver's URL. Receivers hold only their own key (`ironvise webhook-key
/// --url`), so none of them can sign a delivery another would accept.
pub fn receiver_key(secret: &str, receiver_url: &str) -> [u8; 32] {
    hmac_sha256(secret.as_bytes(), &[RECEIVER_KEY_CONTEXT, receiver_url])
}

/// `X-EctoLedger-Signature-V1`: HMAC-SHA256 under the receiver's key over the
/// delivery id, the timestamp, the receiver URL and the body, newline-joined.
/// A delivery captured at one receiver fails at any other, and a receiver that
/// remembers delivery ids for the tolerance window refuses a replay.
pub fn signature_v1(
    key: &[u8; 32],
    delivery_id: &str,
    timestamp: i64,
    receiver_url: &str,
    body: &str,
) -> String {
    hex::encode(hmac_sha256(
        key,
        &[
            SIGNATURE_CONTEXT,
            delivery_id,
            &timestamp.to_string(),
            receiver_url,
            body,
        ],
    ))
}

/// The signing headers for one delivery to `receiver_url`, fixed before the
/// first attempt so retries carry the same id, timestamp and signature.
fn signed_headers(
    secret: Option<&str>,
    legacy: bool,
    receiver_url: &str,
    body: &str,
) -> Vec<(&'static str, String)> {
    let Some(secret) = secret else {
        return Vec::new();
    };
    let id = Uuid::new_v4().to_string();
    let ts = chrono::Utc::now().timestamp();
    let key = receiver_key(secret, receiver_url);
    let mut headers = vec![
        ("X-EctoLedger-Delivery", id.clone()),
        ("X-EctoLedger-Timestamp", ts.to_string()),
        (
            "X-EctoLedger-Signature-V1",
            signature_v1(&key, &id, ts, receiver_url, body),
        ),
    ];
    if legacy && let Some(sig) = hmac_signature(body, secret) {
        headers.push(("X-EctoLedger-Signature", sig));
    }
    headers
}

/// The pre-0.8 signature: HMAC over the body alone, under the one shared
/// secret. Replayable, and valid at every receiver. Sent only with
/// `WEBHOOK_LEGACY_SIGNATURE=true`.
fn hmac_signature(body: &str, secret: &str) -> Option<String> {
    type HmacSha256 = Hmac<Sha256>;
    match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mut mac) => {
            mac.update(body.as_bytes());
            let result = mac.finalize();
            Some(format!("sha256={}", hex::encode(result.into_bytes())))
        }
        Err(e) => {
            // InvalidLength is the only possible error; log and skip signing
            // rather than panicking inside the egress task.
            tracing::error!(
                "HMAC-SHA256 init failed (invalid key length {}): {}",
                secret.len(),
                e
            );
            None
        }
    }
}

/// Send one delivery: POST `body` with its content type, bearer token and
/// signing headers, retrying a failed attempt after 1 s and 2 s. The headers
/// are fixed by the caller, so every attempt carries the same delivery id,
/// timestamp and signature. Both the environment-configured webhook and the
/// ones saved in the app deliver through here.
async fn deliver(
    client: &reqwest::Client,
    url: &str,
    format: &str,
    body: &str,
    bearer_token: Option<&str>,
    signing: &[(&'static str, String)],
) -> Result<(), String> {
    let mut last_err = String::new();
    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay_secs = std::cmp::min(1u64 << (attempt - 1), 60);
            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
        }
        let mut req = client
            .post(url)
            .header("Content-Type", content_type(format))
            .body(body.to_string());
        if let Some(token) = bearer_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        for (name, value) in signing {
            req = req.header(*name, value);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => last_err = format!("HTTP {}", resp.status()),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

/// Per-URL per-second rate limiter for webhook deliveries.
type RateWindowMap =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u64)>>>;

fn allow_webhook_delivery(windows: &RateWindowMap, url: &str, limit_per_sec: u64) -> bool {
    if limit_per_sec == 0 {
        return false;
    }
    let now = std::time::Instant::now();
    let mut guard = windows.lock().unwrap_or_else(|e| e.into_inner());
    let entry = guard.entry(url.to_string()).or_insert((now, 0));
    if now.duration_since(entry.0) >= std::time::Duration::from_secs(1) {
        *entry = (now, 1);
        true
    } else if entry.1 < limit_per_sec {
        entry.1 += 1;
        true
    } else {
        false
    }
}

fn is_private_resolved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_private() || v4.is_link_local())
        }
    }
}

async fn egress_loop(
    config: Option<WebhookConfig>,
    pool: DatabasePool,
    rx: &mut mpsc::Receiver<EgressEvent>,
) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "reqwest Client::builder() failed in webhook egress ({e}); using default client"
            );
            reqwest::Client::new()
        });

    let include_guard = config::webhook_include_guard();
    let include_tripwire = config::webhook_include_tripwire();
    let rate_limit = config::webhook_rate_limit_per_second();
    let rate_windows: RateWindowMap =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // Validate the legacy WEBHOOK_URL against SSRF via actual DNS resolution.
    if let Some(ref cfg) = config {
        if let Ok(parsed) = url::Url::parse(&cfg.url) {
            let scheme = parsed.scheme();
            if scheme != "http" && scheme != "https" {
                tracing::error!(
                    "WEBHOOK_URL has disallowed scheme '{}' - webhook egress disabled",
                    scheme
                );
                return;
            }
            if let Some(host) = parsed.host_str() {
                let port = parsed
                    .port()
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                match tokio::net::lookup_host(format!("{host}:{port}")).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            let ip = addr.ip();
                            if is_private_resolved_ip(ip) {
                                tracing::error!(
                                    "WEBHOOK_URL host '{}' resolves to internal address {} - webhook egress disabled (SSRF/DNS-rebinding protection)",
                                    host,
                                    ip
                                );
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "WEBHOOK_URL host '{}' DNS resolution failed: {} - webhook egress disabled",
                            host,
                            e
                        );
                        return;
                    }
                }
            }
        } else {
            tracing::error!("WEBHOOK_URL is not a valid URL - webhook egress disabled");
            return;
        }
    }

    while let Some(event) = rx.recv().await {
        let should_send = match event.kind {
            EgressKind::Observation => true,
            EgressKind::GuardDenial => include_guard,
            EgressKind::TripwireRejection => include_tripwire,
        };
        if !should_send {
            continue;
        }

        // 1. Dispatch to the legacy env-var configured webhook (if present) in a
        //    background task so one slow/failing webhook doesn't block the loop.
        if let Some(ref cfg) = config {
            if !allow_webhook_delivery(&rate_windows, &cfg.url, rate_limit) {
                tracing::warn!(
                    "Webhook rate limit ({}/s) exceeded for {} - dropping event",
                    rate_limit,
                    cfg.url
                );
            } else {
                let body = format_event(&event, &cfg.siem_format);
                let cfg_url = cfg.url.clone();
                let signing = signed_headers(
                    config::webhook_hmac_secret().as_deref(),
                    config::webhook_legacy_signature(),
                    &cfg_url,
                    &body,
                );
                let cfg_bearer = cfg.bearer_token.clone();
                let cfg_format = cfg.siem_format.clone();
                let client_clone = client.clone();
                let event_session = event.session_id;
                let event_label = event.rule_label.clone();
                let event_kind = event.kind.as_str().to_string();
                tokio::spawn(async move {
                    if let Err(err) = deliver(
                        &client_clone,
                        &cfg_url,
                        &cfg_format,
                        &body,
                        cfg_bearer.as_deref(),
                        &signing,
                    )
                    .await
                    {
                        tracing::warn!(
                            "Webhook egress failed after {} attempts (session={} label={} kind={}): {}",
                            MAX_RETRIES,
                            event_session,
                            event_label,
                            event_kind,
                            err
                        );
                    }
                });
            }
        }

        // 2. Dispatch to all active DB-configured webhook rows in the background.
        let client_for_db = client.clone();
        let pool_for_db = pool.clone();
        let windows_for_db = rate_windows.clone();
        tokio::spawn(async move {
            dispatch_db_webhooks(
                &client_for_db,
                &pool_for_db,
                &event,
                &windows_for_db,
                rate_limit,
            )
            .await;
        });
    }
}

/// Loads active webhook rows from the database and dispatches the event to each one,
/// respecting each row's `filter_kinds` and applying the same retry policy as the
/// env-var webhook target.
async fn dispatch_db_webhooks(
    client: &reqwest::Client,
    pool: &DatabasePool,
    event: &EgressEvent,
    rate_windows: &RateWindowMap,
    rate_limit: u64,
) {
    let rows = match pool.list_webhooks().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to load webhook rows from DB: {}", e);
            return;
        }
    };

    for row in rows {
        if !row.enabled {
            continue;
        }
        let url = row.url;
        let bearer_token = row.bearer_token;
        let siem_format = row.siem_format;
        let filter_kinds: Vec<String> = row
            .filter_kinds
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Per-row kind filter: empty filter_kinds means accept everything.
        if !filter_kinds.is_empty() && !filter_kinds.contains(&event.kind.as_str().to_string()) {
            continue;
        }

        if !allow_webhook_delivery(rate_windows, &url, rate_limit) {
            tracing::warn!(
                "DB webhook rate limit ({}/s) exceeded for {} - dropping event",
                rate_limit,
                url
            );
            continue;
        }

        // Re-validate every DB-stored URL for SSRF via DNS resolution.
        // A URL that was valid at insertion time may have been mutated in the DB,
        // or internal DNS may have changed since the row was written.
        match url::Url::parse(&url) {
            Ok(parsed) => {
                let scheme = parsed.scheme();
                if scheme != "http" && scheme != "https" {
                    tracing::warn!(
                        "DB webhook URL has disallowed scheme '{}' - skipping (SSRF protection)",
                        scheme
                    );
                    continue;
                }
                if let Some(host) = parsed.host_str() {
                    let port = parsed
                        .port()
                        .unwrap_or(if scheme == "https" { 443 } else { 80 });
                    match tokio::net::lookup_host(format!("{host}:{port}")).await {
                        Ok(addrs) => {
                            let mut blocked = false;
                            for addr in addrs {
                                let ip = addr.ip();
                                if is_private_resolved_ip(ip) {
                                    tracing::warn!(
                                        "DB webhook host '{}' resolves to internal address {} - skipping (SSRF/DNS-rebinding)",
                                        host,
                                        ip
                                    );
                                    blocked = true;
                                    break;
                                }
                            }
                            if blocked {
                                continue;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "DB webhook host '{}' DNS resolution failed: {} - skipping",
                                host,
                                e
                            );
                            continue;
                        }
                    }
                }
            }
            Err(_) => {
                tracing::warn!("DB webhook URL '{}' is not a valid URL - skipping", url);
                continue;
            }
        }

        let body = format_event(event, &siem_format);
        let signing = signed_headers(
            config::webhook_hmac_secret().as_deref(),
            config::webhook_legacy_signature(),
            &url,
            &body,
        );
        let client_clone = client.clone();
        let session_id = event.session_id;
        let rule_label = event.rule_label.clone();

        // Spawn a new task so this webhook's retries don't block the next webhook
        tokio::spawn(async move {
            if let Err(err) = deliver(
                &client_clone,
                &url,
                &siem_format,
                &body,
                bearer_token.as_deref(),
                &signing,
            )
            .await
            {
                tracing::warn!(
                    "DB webhook {} delivery failed after {} attempts (session={} label={}): {}",
                    url,
                    MAX_RETRIES,
                    session_id,
                    rule_label,
                    err
                );
            }
        });
    }
}

fn content_type(format: &str) -> &'static str {
    match format {
        "cef" | "leef" => "text/plain",
        _ => "application/json",
    }
}

fn format_event(event: &EgressEvent, format: &str) -> String {
    match format {
        "cef" => format_cef(event),
        "leef" => format_leef(event),
        _ => format_json(event),
    }
}

fn format_json(event: &EgressEvent) -> String {
    serde_json::json!({
        "source": "ectoledger",
        "session_id": event.session_id.to_string(),
        "event_kind": event.kind.as_str(),
        "severity": event.severity,
        "rule_label": event.rule_label,
        "observation_preview": event.observation_preview,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
    .to_string()
}

/// Sanitise a string for use in CEF header fields (pipe-delimited).
fn sanitize_cef_header(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

/// Sanitise a string for use in CEF extension key=value pairs.
fn sanitize_cef_extension(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace(['\n', '\r'], "\\n")
}

/// ArcSight CEF (Common Event Format): syslog-like header + key-value extension.
fn format_cef(event: &EgressEvent) -> String {
    let cef_severity = if event.severity == "abort" { "9" } else { "5" };
    format!(
        "CEF:0|EctoLedger|EctoLedger|1.0|{kind}|{rule}|{sev}|session={sid} label={label} preview={prev}",
        kind = event.kind.as_str(),
        rule = sanitize_cef_header(&event.rule_label),
        sev = cef_severity,
        sid = event.session_id,
        label = sanitize_cef_extension(&event.rule_label),
        prev = sanitize_cef_extension(&event.observation_preview),
    )
}

/// Sanitise a string for use in LEEF header/extension fields.
fn sanitize_leef(s: &str) -> String {
    s.replace('|', "_").replace(['\t', '\n', '\r'], " ")
}

/// IBM LEEF 2.0: tab-separated key-value attributes after a header.
fn format_leef(event: &EgressEvent) -> String {
    format!(
        "LEEF:2.0|EctoLedger|EctoLedger|1.0|{kind}|\tsrc=ectoledger\tsessionId={sid}\tseverity={sev}\truleLabel={label}\tobservation={prev}",
        kind = event.kind.as_str(),
        sid = event.session_id,
        sev = sanitize_leef(&event.severity),
        label = sanitize_leef(&event.rule_label),
        prev = sanitize_leef(&event.observation_preview),
    )
}

/// v1 signing, pinned by a fixture the TypeScript and Python SDK verifiers
/// test against, so the three cannot drift apart.
#[cfg(test)]
mod v1_tests;

#[cfg(test)]
mod format_sanitization_tests {
    use super::*;

    fn event(rule_label: &str, observation_preview: &str, severity: &str) -> EgressEvent {
        EgressEvent {
            session_id: Uuid::nil(),
            severity: severity.to_string(),
            rule_label: rule_label.to_string(),
            observation_preview: observation_preview.to_string(),
            kind: EgressKind::TripwireRejection,
        }
    }

    #[test]
    fn cef_header_escapes_backslash_then_pipe() {
        assert_eq!(sanitize_cef_header("a\\b"), "a\\\\b");
        assert_eq!(sanitize_cef_header("a|b"), "a\\|b");
    }

    #[test]
    fn cef_header_collapses_newlines_and_carriage_returns_to_a_space() {
        assert_eq!(sanitize_cef_header("a\nb"), "a b");
        assert_eq!(sanitize_cef_header("a\rb"), "a b");
    }

    #[test]
    fn cef_extension_escapes_backslash_then_equals() {
        assert_eq!(sanitize_cef_extension("a\\b"), "a\\\\b");
        assert_eq!(sanitize_cef_extension("a=b"), "a\\=b");
    }

    #[test]
    fn cef_extension_escapes_newlines_as_literal_backslash_n() {
        assert_eq!(sanitize_cef_extension("a\nb"), "a\\nb");
        assert_eq!(sanitize_cef_extension("a\rb"), "a\\nb");
    }

    #[test]
    fn leef_replaces_pipe_with_underscore() {
        assert_eq!(sanitize_leef("a|b"), "a_b");
    }

    #[test]
    fn leef_collapses_tabs_and_newlines_to_a_space() {
        assert_eq!(sanitize_leef("a\tb"), "a b");
        assert_eq!(sanitize_leef("a\nb"), "a b");
        assert_eq!(sanitize_leef("a\rb"), "a b");
    }

    #[test]
    fn a_pipe_in_the_rule_label_is_escaped_in_both_cef_header_and_extension_positions() {
        let ev = event("forged|9|injected", "preview|x", "flag");
        let out = format_cef(&ev);
        let header_rule = sanitize_cef_header("forged|9|injected");
        let ext_label = sanitize_cef_extension("forged|9|injected");
        let ext_preview = sanitize_cef_extension("preview|x");
        assert!(
            out.contains(&format!("|{header_rule}|5|")),
            "header-position rule field must be pipe-escaped, got: {out}"
        );
        assert!(
            out.contains(&format!("label={ext_label}")),
            "extension-position label must be equals-escaped, got: {out}"
        );
        assert!(
            out.contains(&format!("preview={ext_preview}")),
            "extension-position preview must be equals-escaped, got: {out}"
        );
    }

    #[test]
    fn a_tab_in_the_observation_cannot_forge_an_extra_leef_attribute() {
        let ev = event("rule", "evil\tinjected=true", "flag");
        let out = format_leef(&ev);
        assert!(
            !out.contains("\tinjected="),
            "a raw tab in the observation must not start a new LEEF attribute, got: {out}"
        );
    }

    #[test]
    fn content_type_matches_the_wire_format() {
        assert_eq!(content_type("cef"), "text/plain");
        assert_eq!(content_type("leef"), "text/plain");
        assert_eq!(content_type("json"), "application/json");
        assert_eq!(content_type("unknown-format"), "application/json");
    }

    #[test]
    fn format_json_round_trips_through_serde() {
        let ev = event("rule-x", "preview text", "abort");
        let parsed: serde_json::Value = serde_json::from_str(&format_json(&ev)).unwrap();
        assert_eq!(parsed["event_kind"], "tripwire_rejection");
        assert_eq!(parsed["rule_label"], "rule-x");
        assert_eq!(parsed["observation_preview"], "preview text");
        assert_eq!(parsed["severity"], "abort");
    }

    #[test]
    fn cef_severity_is_nine_for_abort_and_five_otherwise() {
        assert!(format_cef(&event("r", "p", "abort")).contains("|9|"));
        assert!(format_cef(&event("r", "p", "flag")).contains("|5|"));
    }

    #[test]
    fn rate_limiter_enforces_per_url_per_second_cap() {
        let windows: RateWindowMap =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        assert!(allow_webhook_delivery(
            &windows,
            "https://a.example/hook",
            2
        ));
        assert!(allow_webhook_delivery(
            &windows,
            "https://a.example/hook",
            2
        ));
        assert!(!allow_webhook_delivery(
            &windows,
            "https://a.example/hook",
            2
        ));
        assert!(allow_webhook_delivery(
            &windows,
            "https://b.example/hook",
            2
        ));
        assert!(!allow_webhook_delivery(
            &windows,
            "https://a.example/hook",
            0
        ));
    }

    #[test]
    fn private_ip_check_blocks_ipv6_ula_and_link_local() {
        assert!(is_private_resolved_ip("fe80::1".parse().unwrap()));
        assert!(is_private_resolved_ip("fd00::1".parse().unwrap()));
        assert!(is_private_resolved_ip("fc00::1".parse().unwrap()));
        assert!(!is_private_resolved_ip(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }
}
