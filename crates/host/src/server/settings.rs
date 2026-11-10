//! Runtime configuration, status, tripwire settings, and demo reset.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;
use crate::intent::ProposedIntent;
use crate::pool::PoolCapabilities;

#[derive(serde::Serialize)]
pub(crate) struct ConfigResponse {
    database_url: String,
    llm_backend: String,
    ollama_base_url: String,
    openai_base_url: String,
    ollama_model: String,
    guard_required: bool,
    /// What decided `guard_required`: the environment, the settings file, both,
    /// or the stricter of two that disagreed. Surfaced so an operator can see
    /// *why* the effective value is what it is rather than inferring it.
    guard_required_source: String,
    guard_llm_backend: Option<String>,
    guard_llm_model: Option<String>,
    max_steps: u32,
    agent_allowed_domains: Vec<String>,
    /// "none" | "docker" | "firecracker"
    sandbox_mode: String,
    /// true when ECTO_DEMO_MODE=true|1 - used by the GUI to display a "Demo" tag
    demo_mode: bool,
    /// Desktop GUI: show Testing / Prometheus / Dev Hub in the sidebar.
    show_developer_tools: bool,
    /// Live pool backend: `"postgres"` or `"sqlite"`.
    ledger_backend: String,
    /// Cognitive loop (Home → Run) works on this live pool.
    agent_supported: bool,
    /// Certificate / report export works on this live pool.
    exports_supported: bool,
    /// Webhook egress worker is delivering events.
    webhooks_live: bool,
    /// The policy chosen in Settings for Home → Run, by name.
    active_policy: Option<String>,
    /// `ECTO_POLICY_PATH` when set: it wins over `active_policy`, and the GUI
    /// shows it instead of offering a choice.
    policy_from_environment: Option<String>,
}

/// Returns `true` if `host` resolves to a private, loopback, link-local, or cloud
/// metadata address.  Covers the full RFC 1918 172.16.0.0/12 range (172.16-172.31),
/// IPv6 loopback, IPv4-mapped IPv6, and common metadata hostnames.
pub fn is_internal_host(host: &str) -> bool {
    let clean = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()       // covers 10.*, 172.16-31.*, 192.168.*
                    || v4.is_link_local()     // 169.254.*
                    || v4.is_unspecified() // 0.0.0.0
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()             // ::1
                    || v6.is_unspecified()    // ::
                    || (v6.segments()[0] & 0xffc0) == 0xfe80  // link-local fe80::/10
                    || (v6.segments()[0] & 0xfe00) == 0xfc00  // ULA fc00::/7 (fd…/fc…)
                    || v6.to_ipv4_mapped().is_some_and(|v4| {
                        v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    })
            }
        };
    }
    host == "localhost"
        || host == "metadata.google.internal"
        || host.ends_with(".internal")
        || host.ends_with(".local")
}

/// Redact the password (if any) from a database connection URL.
///
/// SQLite URLs are paths, not hierarchical URLs. `url::Url` parses
/// `sqlite://C:\Users\ledger.db` as host `C` plus a path, and serialises it
/// back as `sqlite://C/\Users\ledger.db` (the drive colon is gone). That
/// string was written into the desktop app's `settings.json` on Windows.
/// A SQLite URL has no password, so it is returned unchanged apart from
/// repairing that one corrupted shape.
pub(crate) fn redact_db_url(url: &str) -> String {
    if sqlite_url(url) {
        return repair_windows_sqlite_url(url);
    }
    if let Ok(mut parsed) = url::Url::parse(url) {
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("****"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

fn sqlite_url(url: &str) -> bool {
    url.trim_start()
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("sqlite:"))
}

/// `sqlite://C/\Users\...` → `sqlite://C:\Users\...`.
///
/// Produced by round-tripping a Windows path through `url::Url`: the colon
/// of the drive was taken as a port separator and the following backslash
/// stayed in the path. Only that shape is rewritten.
fn repair_windows_sqlite_url(url: &str) -> String {
    let bytes = url.as_bytes();
    const PREFIX: &str = "sqlite://";
    if bytes.len() >= PREFIX.len() + 3
        && bytes[..PREFIX.len()].eq_ignore_ascii_case(PREFIX.as_bytes())
        && bytes[PREFIX.len()].is_ascii_alphabetic()
        && bytes[PREFIX.len() + 1] == b'/'
        && bytes[PREFIX.len() + 2] == b'\\'
    {
        let mut out = String::with_capacity(url.len());
        out.push_str(&url[..PREFIX.len() + 1]);
        out.push(':');
        out.push_str(&url[PREFIX.len() + 2..]);
        return out;
    }
    url.to_string()
}

/// A text setting in a `PUT /api/config` body: absent keeps the stored value,
/// an empty string clears it (back to the environment or built-in default),
/// anything else replaces it. The empty string is what lets a saved field be
/// emptied again.
fn merge_text(incoming: Option<String>, stored: Option<String>) -> Option<String> {
    match incoming {
        Some(v) if v.trim().is_empty() => None,
        Some(v) => Some(v),
        None => stored,
    }
}

/// The GUI reads the URL redacted and sends it back unchanged on save. A
/// password of `****` is that placeholder, not a new password: keep the stored
/// one, as long as it is the same user on the same server.
fn restore_redacted_password(incoming: &str, stored: Option<&str>) -> String {
    if sqlite_url(incoming) {
        return repair_windows_sqlite_url(incoming);
    }
    let (Ok(mut new), Some(Ok(old))) = (url::Url::parse(incoming), stored.map(url::Url::parse))
    else {
        return incoming.to_string();
    };
    let same_account = new.username() == old.username()
        && new.host_str() == old.host_str()
        && new.port_or_known_default() == old.port_or_known_default();
    if new.password() == Some("****") && same_account {
        let _ = new.set_password(old.password());
    }
    new.to_string()
}

pub(crate) fn merged_config(caps: &PoolCapabilities) -> ConfigResponse {
    let allowed_domains: Vec<String> = std::env::var("AGENT_ALLOWED_DOMAINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let sandbox_mode = if std::env::var("ECTO_FC_BINARY").is_ok() {
        "firecracker".to_string()
    } else if std::env::var("ECTO_DOCKER_IMAGE").is_ok() {
        "docker".to_string()
    } else {
        "none".to_string()
    };
    let demo_mode = std::env::var("ECTO_DEMO_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let (guard_required_value, guard_required_source) = config::guard_required_effective();
    let base = ConfigResponse {
        // Prefer env / settings without calling `database_url()`, which ERROR-logs
        // when unset - the embedded GUI uses a file-backed SQLite pool and never
        // sets DATABASE_URL unless we stamp it at startup.
        database_url: redact_db_url(&config::database_url_display()),
        llm_backend: config::llm_provider(),
        ollama_base_url: config::ollama_base_url(),
        openai_base_url: config::openai_base_url(),
        ollama_model: config::ollama_model(),
        guard_required: guard_required_value,
        guard_required_source: guard_required_source.as_str().to_string(),
        guard_llm_backend: config::guard_llm_backend(),
        guard_llm_model: config::guard_llm_model(),
        max_steps: config::max_steps(),
        agent_allowed_domains: allowed_domains,
        sandbox_mode: sandbox_mode.clone(),
        demo_mode,
        // Demo mode turns developer tools on so the built-in test runners are
        // reachable without hunting for a checkbox.
        show_developer_tools: demo_mode,
        ledger_backend: caps.ledger_backend.to_string(),
        agent_supported: caps.agent_supported,
        exports_supported: caps.exports_supported,
        webhooks_live: caps.webhooks_live,
        active_policy: None,
        policy_from_environment: std::env::var("ECTO_POLICY_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty()),
    };
    if let Some(ov) = config::load_settings_config() {
        ConfigResponse {
            database_url: ov
                .database_url
                .map(|u| redact_db_url(&u))
                .unwrap_or(base.database_url),
            llm_backend: ov.llm_backend.unwrap_or(base.llm_backend),
            ollama_base_url: ov.ollama_base_url.unwrap_or(base.ollama_base_url),
            openai_base_url: ov.openai_base_url.unwrap_or(base.openai_base_url),
            ollama_model: ov.ollama_model.unwrap_or(base.ollama_model),
            // Not `ov.guard_required.unwrap_or(...)`: for this one key the
            // settings file does not simply win. `config::guard_required()`
            // has already resolved both sources most-restrictive-wins, and
            // re-applying the override here would put the silent downgrade
            // back into what the GUI displays.
            guard_required: base.guard_required,
            guard_required_source: base.guard_required_source,
            guard_llm_backend: ov.guard_llm_backend.or(base.guard_llm_backend),
            guard_llm_model: ov.guard_llm_model.or(base.guard_llm_model),
            max_steps: ov.max_steps.unwrap_or(base.max_steps),
            agent_allowed_domains: ov
                .agent_allowed_domains
                .unwrap_or(base.agent_allowed_domains),
            sandbox_mode,
            demo_mode,
            show_developer_tools: ov.show_developer_tools.unwrap_or(base.show_developer_tools),
            // Capabilities always come from the live pool, not settings.
            ledger_backend: base.ledger_backend,
            agent_supported: base.agent_supported,
            exports_supported: base.exports_supported,
            webhooks_live: base.webhooks_live,
            active_policy: ov.active_policy.filter(|s| !s.trim().is_empty()),
            policy_from_environment: base.policy_from_environment,
        }
    } else {
        base
    }
}

pub(crate) async fn get_config(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
) -> Result<axum::Json<ConfigResponse>, StatusCode> {
    // Restrict to Admin - the response includes database_url which may contain credentials.
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(axum::Json(merged_config(&state.pool.capabilities())))
}

/// Lightweight public status endpoint - no auth required.
/// Only exposes non-sensitive information that the GUI needs on startup.
#[derive(Serialize)]
pub(crate) struct StatusResponse {
    /// `ECTO_DEMO_MODE`. Turns on `/api/admin/reset-demo` and, on PostgreSQL,
    /// an isolated embedded instance. Not the insecure-defaults banner.
    demo_mode: bool,
    /// True when the process would log `INSECURE DEMO MODE` (guard off, or
    /// dev mode on). Independent of `demo_mode`.
    insecure_demo: bool,
    version: &'static str,
    ledger_backend: &'static str,
    agent_supported: bool,
    exports_supported: bool,
    webhooks_live: bool,
}

pub(crate) async fn get_status(State(state): State<Arc<AppState>>) -> axum::Json<StatusResponse> {
    let caps = state.pool.capabilities();
    axum::Json(StatusResponse {
        demo_mode: config::is_demo_mode(),
        insecure_demo: !config::insecure_mode_reasons().is_empty(),
        version: env!("CARGO_PKG_VERSION"),
        ledger_backend: caps.ledger_backend,
        agent_supported: caps.agent_supported,
        exports_supported: caps.exports_supported,
        webhooks_live: caps.webhooks_live,
    })
}

#[derive(serde::Deserialize)]
pub(crate) struct ConfigUpdate {
    database_url: Option<String>,
    llm_backend: Option<String>,
    ollama_base_url: Option<String>,
    openai_base_url: Option<String>,
    ollama_model: Option<String>,
    guard_required: Option<bool>,
    guard_llm_backend: Option<String>,
    guard_llm_model: Option<String>,
    max_steps: Option<u32>,
    agent_allowed_domains: Option<Vec<String>>,
    show_developer_tools: Option<bool>,
    active_policy: Option<String>,
}

pub(crate) async fn put_config(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::Json(body): axum::Json<ConfigUpdate>,
) -> Result<axum::Json<ConfigResponse>, (StatusCode, String)> {
    if role != Role::Admin {
        return Err((StatusCode::FORBIDDEN, "Admin role required".to_string()));
    }
    let current = config::load_settings_config().unwrap_or_default();
    let cfg = config::SettingsConfig {
        database_url: match merge_text(body.database_url, current.database_url.clone()) {
            Some(url) => Some(restore_redacted_password(
                &url,
                current.database_url.as_deref(),
            )),
            None => None,
        },
        llm_backend: body.llm_backend.or(current.llm_backend),
        ollama_base_url: merge_text(body.ollama_base_url, current.ollama_base_url),
        openai_base_url: merge_text(body.openai_base_url, current.openai_base_url),
        ollama_model: merge_text(body.ollama_model, current.ollama_model),
        guard_required: body.guard_required.or(current.guard_required),
        guard_llm_backend: merge_text(body.guard_llm_backend, current.guard_llm_backend),
        guard_llm_model: merge_text(body.guard_llm_model, current.guard_llm_model),
        max_steps: body.max_steps.or(current.max_steps),
        agent_allowed_domains: body.agent_allowed_domains.or(current.agent_allowed_domains),
        show_developer_tools: body.show_developer_tools.or(current.show_developer_tools),
        active_policy: merge_text(body.active_policy, current.active_policy),
    };
    // A policy chosen for new runs must load now, not fail the next run.
    if let Some(name) = &cfg.active_policy {
        super::policies::load_named(name).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
    }
    config::save_settings_config(&cfg).map_err(|e| {
        tracing::error!("save_settings_config: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e)
    })?;
    Ok(axum::Json(merged_config(&state.pool.capabilities())))
}

/// `POST /api/admin/reset-demo`
///
/// Deletes all agent sessions, events, snapshots, and action-log rows.
/// Only available in demo mode and only to admins.
pub(crate) async fn reset_demo_data(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    if role != Role::Admin {
        return Err((StatusCode::FORBIDDEN, "Admin role required".into()));
    }
    if !config::is_demo_mode() {
        return Err((
            StatusCode::FORBIDDEN,
            "Reset is only available in demo mode".into(),
        ));
    }
    state.pool.reset_demo_data().await.map_err(|e| {
        tracing::error!("reset_demo_data: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to reset demo data: {e}"),
        )
    })?;
    // Re-create the genesis event so the ledger chain is valid.
    if let Err(e) = state.pool.ensure_genesis().await {
        tracing::warn!("Failed to re-create genesis event after reset: {}", e);
    }
    tracing::info!("Demo data reset by admin");
    Ok(axum::Json(
        serde_json::json!({"ok": true, "message": "Demo database reset successfully"}),
    ))
}

/// The tripwire configuration, and whether it is saved.
///
/// Unsaved, the allowed paths shown are the server's working directory, which
/// only the audit loop uses: Claude Code hook sessions are confined to their
/// own project instead (`hook::build_tripwire_for`). Saving applies the paths
/// to both, so the screen has to be able to say which case it is showing.
#[derive(serde::Serialize)]
pub(crate) struct TripwireConfigView {
    #[serde(flatten)]
    config: config::TripwireConfig,
    saved: bool,
}

pub(crate) async fn get_tripwire_config() -> axum::Json<TripwireConfigView> {
    axum::Json(TripwireConfigView {
        config: config::load_tripwire_config(),
        saved: config::tripwire_config_path().exists(),
    })
}

#[derive(serde::Deserialize)]
pub(crate) struct TripwireConfigUpdate {
    allowed_paths: Vec<String>,
    allowed_domains: Vec<String>,
    banned_command_patterns: Vec<String>,
    #[serde(default)]
    min_justification_length: Option<u32>,
    #[serde(default)]
    require_https: Option<bool>,
    /// Absent keeps the saved list: the desktop app does not edit it.
    #[serde(default)]
    allowed_mcp_tools: Option<Vec<String>>,
}

pub(crate) async fn put_tripwire_config(
    axum::Extension(role): axum::Extension<Role>,
    axum::Json(body): axum::Json<TripwireConfigUpdate>,
) -> Result<axum::Json<config::TripwireConfig>, (StatusCode, String)> {
    if role != Role::Admin {
        return Err((StatusCode::FORBIDDEN, "Admin role required".to_string()));
    }
    // An empty entry is a prefix that matches every path, so accepting one here
    // would silently disable the path allowlist for the whole install. The GUI
    // filters blank lines already; this closes the same hole for a direct PUT.
    if body.allowed_paths.iter().any(|p| p.trim().is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "allowed_paths may not contain an empty entry: an empty prefix matches every path"
                .to_string(),
        ));
    }
    let current = config::load_tripwire_config();
    let cfg = config::TripwireConfig {
        allowed_paths: body.allowed_paths,
        allowed_domains: body.allowed_domains,
        banned_command_patterns: body.banned_command_patterns,
        min_justification_length: body
            .min_justification_length
            .unwrap_or(current.min_justification_length),
        require_https: body.require_https.unwrap_or(current.require_https),
        allowed_mcp_tools: body.allowed_mcp_tools.unwrap_or(current.allowed_mcp_tools),
    };
    config::save_tripwire_config(&cfg).map_err(|e| {
        tracing::error!("save_tripwire_config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to save tripwire configuration".to_string(),
        )
    })?;
    Ok(axum::Json(cfg))
}

/// Long enough to clear `min_justification_length` for any sane configuration,
/// so a caller that only wants to try a command is not denied for
/// `min_justification` instead of the rule it actually came here to see.
fn default_check_justification() -> String {
    "Checking a proposed action from the GUI's tripwire test panel before taking it.".to_string()
}

#[derive(serde::Deserialize)]
pub(crate) struct TripwireCheckRequest {
    action: String,
    #[serde(default)]
    params: serde_json::Value,
    #[serde(default = "default_check_justification")]
    justification: String,
}

#[derive(serde::Serialize)]
pub(crate) struct TripwireCheckResponse {
    allowed: bool,
    reason: Option<String>,
    rule: Option<&'static str>,
    matched: Option<String>,
}

/// Which settings screen owns the rule a [`tripwire::TripwireError`] variant
/// enforces, so a denial can be explained to the GUI without it having to
/// parse the human-readable message.
fn tripwire_rule(err: &tripwire::TripwireError) -> &'static str {
    use tripwire::TripwireError::*;
    match err {
        BannedCommand(_) => "banned_command_patterns",
        PathTraversal(_) | PathNotAllowed(_) | ProtectedPath(_) | SymlinkEscape(_) => {
            "allowed_paths"
        }
        DomainNotAllowed(_) => "allowed_domains",
        HttpsRequired(_) => "require_https",
        InsufficientJustification(_) => "min_justification",
        UnknownAction(_) | MissingParam(_) | InvalidPath(_) | InvalidMcpTool(_)
        | McpToolNotAllowed(_) | PolicyViolation(_) | InvalidUrl(_) => "other",
    }
}

/// The configured list item that decided the denial: the banned pattern that
/// matched the command, or - for every other rule - the detail the error
/// itself carries (the offending path, host, or token).
fn tripwire_matched(
    err: &tripwire::TripwireError,
    banned_patterns: &[String],
    intent: &ProposedIntent,
) -> String {
    use tripwire::TripwireError::*;
    match err {
        BannedCommand(detail) => {
            let cmd = intent.params_command().unwrap_or(detail).to_lowercase();
            banned_patterns
                .iter()
                .find(|p| cmd.contains(&p.to_lowercase()))
                .cloned()
                .unwrap_or_else(|| detail.clone())
        }
        MissingParam(s) => (*s).to_string(),
        InsufficientJustification(n) => format!("min_justification_length={n}"),
        UnknownAction(s) | PathTraversal(s) | InvalidPath(s) | PathNotAllowed(s)
        | ProtectedPath(s) | InvalidMcpTool(s) | McpToolNotAllowed(s) | SymlinkEscape(s)
        | PolicyViolation(s) | InvalidUrl(s) | HttpsRequired(s) | DomainNotAllowed(s) => s.clone(),
    }
}

/// `POST /api/tripwire/check` - ask whether a proposed action would pass the
/// tripwire, **without recording anything**: no session, no ledger event.
///
/// Built from the same `tripwire.json` the hook and cognitive loop use
/// ([`config::load_tripwire_config`]), run through the identical
/// [`tripwire::Tripwire::validate`]. This exercises only the tripwire layer -
/// no policy engine, no semantic guard - which is what the GUI's "try a
/// command" panel is asking about: the allowlists and banned patterns on the
/// screen it is next to, not a specific session's full evaluation pipeline.
pub(crate) async fn check_tripwire(
    axum::Json(body): axum::Json<TripwireCheckRequest>,
) -> axum::Json<TripwireCheckResponse> {
    let tw_cfg = config::load_tripwire_config();
    let banned_command_patterns = tw_cfg.banned_command_patterns.clone();
    let allowed_paths = config::canonical_allowed_prefixes(&tw_cfg.allowed_paths);
    let tw = tripwire::Tripwire::from_config(tw_cfg, allowed_paths);

    let intent = ProposedIntent {
        action: body.action,
        params: body.params,
        justification: body.justification,
        reasoning: String::new(),
    };

    axum::Json(match tw.validate(&intent) {
        Ok(_) => TripwireCheckResponse {
            allowed: true,
            reason: None,
            rule: None,
            matched: None,
        },
        Err(e) => {
            let rule = tripwire_rule(&e);
            let matched = tripwire_matched(&e, &banned_command_patterns, &intent);
            TripwireCheckResponse {
                allowed: false,
                reason: Some(e.to_string()),
                rule: Some(rule),
                matched: Some(matched),
            }
        }
    })
}

#[cfg(test)]
mod redacted_password_tests {
    use super::*;

    #[test]
    fn an_empty_text_setting_clears_and_an_absent_one_keeps() {
        let stored = Some("qwen2.5:7b".to_string());
        assert_eq!(merge_text(Some(String::new()), stored.clone()), None);
        assert_eq!(merge_text(Some("  ".into()), stored.clone()), None);
        assert_eq!(merge_text(None, stored.clone()), stored);
        assert_eq!(merge_text(Some("phi3".into()), stored), Some("phi3".into()));
    }

    const STORED: &str = "postgres://ecto:s3cret@db.example:5432/ledger";

    #[test]
    fn saving_the_redacted_url_keeps_the_stored_password() {
        let shown = redact_db_url(STORED);
        assert!(shown.contains("****"));
        assert_eq!(restore_redacted_password(&shown, Some(STORED)), STORED);
    }

    #[test]
    fn a_real_new_password_is_kept() {
        let new = "postgres://ecto:rotated@db.example:5432/ledger";
        assert_eq!(restore_redacted_password(new, Some(STORED)), new);
    }

    /// The placeholder must not carry the old password to another server or user.
    #[test]
    fn the_stored_password_does_not_move_to_another_account() {
        for other in [
            "postgres://ecto:****@elsewhere.example:5432/ledger",
            "postgres://admin:****@db.example:5432/ledger",
            "postgres://ecto:****@db.example:6543/ledger",
        ] {
            assert_eq!(restore_redacted_password(other, Some(STORED)), other);
        }
        let sqlite = "sqlite:ledger.db";
        assert_eq!(restore_redacted_password(sqlite, Some(STORED)), sqlite);
    }

    #[test]
    fn a_windows_sqlite_path_is_not_rewritten_by_the_url_parser() {
        let url =
            r"sqlite://C:\Users\user01\AppData\Roaming\io.ectoledger.agent-ledger\ectoledger.db";
        let mangled =
            r"sqlite://C/\Users\user01\AppData\Roaming\io.ectoledger.agent-ledger\ectoledger.db";
        // `url::Url` is what used to rewrite the path. Pin that so a crate
        // upgrade that stops mangling is visible.
        assert_eq!(url::Url::parse(url).unwrap().to_string(), mangled);
        assert_eq!(redact_db_url(url), url);
        assert_eq!(restore_redacted_password(url, Some(url)), url);
        assert_eq!(redact_db_url(mangled), url);
        assert_eq!(restore_redacted_password(mangled, Some(mangled)), url);
    }
}
