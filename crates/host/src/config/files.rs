//! Files under the data directory: settings.json, tripwire.json, policies,
//! session keys and rollback rules.

/// Directory for encrypted session key files. Env: ECTO_DATA_DIR, default `.ectoledger/keys`.
pub fn session_key_dir() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("keys")
}

/// Path to rollback rules TOML file. Env: ECTO_DATA_DIR, default `.ectoledger/rollback_rules.toml`.
pub fn rollback_rules_path() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("rollback_rules.toml")
}

/// Directory for user-editable policy files. Env: ECTO_DATA_DIR, default `.ectoledger/policies`.
pub fn policies_dir() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("policies")
}

/// Path to settings config file. Env: ECTO_DATA_DIR, default `.ectoledger/settings.json`.
pub fn settings_config_path() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("settings.json")
}

/// Settings override (persisted to file). When present, overrides env vars for display/API.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SettingsConfig {
    pub database_url: Option<String>,
    pub llm_backend: Option<String>,
    pub ollama_base_url: Option<String>,
    pub ollama_model: Option<String>,
    /// Base URL for the OpenAI-compatible transport (LM Studio, llama.cpp,
    /// vLLM, MLX-LM, LocalAI, OpenAI). Persisted so the desktop app can set it
    /// without the operator editing an env var: most providers' base URLs
    /// remain env-var only, which is why they feel unsupported from the GUI.
    #[serde(default)]
    pub openai_base_url: Option<String>,
    pub guard_required: Option<bool>,
    pub guard_llm_backend: Option<String>,
    pub guard_llm_model: Option<String>,
    pub max_steps: Option<u32>,
    pub agent_allowed_domains: Option<Vec<String>>,
    /// When true, the desktop app shows Testing, Prometheus, and Dev Hub in
    /// the sidebar. Default off: those screens are developer tools, not part
    /// of a first-time evaluation.
    #[serde(default)]
    pub show_developer_tools: Option<bool>,
    /// The policy Home → Run checks against, by name: a built-in pack or a
    /// file in [`policies_dir`]. Ignored while `ECTO_POLICY_PATH` is set (the
    /// operator's choice). Read at each session start, so edits apply.
    #[serde(default)]
    pub active_policy: Option<String>,
}

/// The policy chosen in Settings for new runs (see `SettingsConfig::active_policy`).
pub fn active_policy() -> Option<String> {
    load_settings_config()
        .and_then(|c| c.active_policy)
        .filter(|s| !s.trim().is_empty())
}

/// Load settings override from file. Returns None if file missing or invalid.
pub fn load_settings_config() -> Option<SettingsConfig> {
    let path = settings_config_path();
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str::<SettingsConfig>(&content).ok()
}

/// Save settings override to file.
pub fn save_settings_config(cfg: &SettingsConfig) -> Result<(), String> {
    let path = settings_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

/// Path to tripwire config file. Env: ECTO_DATA_DIR, default `.ectoledger/tripwire.json`.
pub fn tripwire_config_path() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("tripwire.json")
}

/// Tripwire configuration (persisted to file).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TripwireConfig {
    pub allowed_paths: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub banned_command_patterns: Vec<String>,
    /// Minimum justification length (chars) for non-complete actions. Default 5.
    #[serde(default = "default_min_justification_length")]
    pub min_justification_length: u32,
    /// Require HTTPS for http_get intents. Default true.
    #[serde(default = "default_require_https")]
    pub require_https: bool,
    /// MCP tools a call may use, as `server/tool` or `server/*`. Empty: any.
    #[serde(default)]
    pub allowed_mcp_tools: Vec<String>,
}

pub(super) fn default_min_justification_length() -> u32 {
    5
}

pub(super) fn default_require_https() -> bool {
    true
}

/// Load tripwire config from file. Falls back to defaults if file missing.
/// **Panics** if `tripwire.json` exists but contains invalid JSON - a broken
/// config must never be silently ignored.
pub fn load_tripwire_config() -> TripwireConfig {
    let path = tripwire_config_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<TripwireConfig>(&content) {
            Ok(cfg) => return cfg,
            Err(e) => panic!(
                "tripwire.json at '{}' has invalid JSON syntax: {}. \
                 Fix or delete the file to use defaults.",
                path.display(),
                e
            ),
        },
        Err(_) => { /* file missing - fall through to defaults */ }
    }
    let workspace = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .to_string_lossy()
        .to_string();
    let allowed_domains: Vec<String> = std::env::var("AGENT_ALLOWED_DOMAINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    TripwireConfig {
        allowed_paths: vec![workspace],
        allowed_domains,
        banned_command_patterns: crate::tripwire::default_banned_command_patterns(),
        min_justification_length: 5,
        require_https: true,
        allowed_mcp_tools: Vec::new(),
    }
}

/// Resolve `allowed_paths` config strings into prefixes fit for comparison.
///
/// The tripwire always validates a *canonicalized* candidate, so a prefix left
/// as raw configuration text is being compared across namespaces: on Windows
/// `canonicalize` expands 8.3 short names and resolves junctions, on macOS it
/// resolves `/tmp` to `/private/tmp`. A mismatch does not merely deny - for a
/// path that exists it is reported as a symlink escape, which is recorded as a
/// distinct attack label in the ledger.
///
/// Two call sites already did this and three did not; this is the single
/// implementation for all five. Entries that cannot be canonicalized (a work
/// directory the agent has yet to create) fall back to the raw path with a
/// warning, matching the previous behaviour of the sites that had it.
///
/// Empty entries are dropped: an empty prefix matches every path, so one blank
/// line in `tripwire.json` would otherwise disable the allowlist entirely.
pub fn canonical_allowed_prefixes(allowed_paths: &[String]) -> Vec<std::path::PathBuf> {
    allowed_paths
        .iter()
        .filter(|p| {
            if p.trim().is_empty() {
                tracing::warn!(
                    "ignoring an empty allowed_paths entry - an empty prefix matches every \
                     path, which would disable the allowlist"
                );
                return false;
            }
            true
        })
        .map(|p| {
            let raw = std::path::PathBuf::from(p);
            match raw.canonicalize() {
                Ok(canonical) => canonical,
                Err(err) => {
                    tracing::warn!(
                        "allowed_paths entry '{}' could not be canonicalized ({}); \
                         using raw path - symlink-escape protection is reduced for this entry. \
                         Pre-create the directory to restore full protection.",
                        p,
                        err
                    );
                    raw
                }
            }
        })
        .collect()
}

/// Save tripwire config to file (atomic write via tempfile + rename).
pub fn save_tripwire_config(cfg: &TripwireConfig) -> Result<(), String> {
    let path = tripwire_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    // Atomic write: write to temp file then rename to prevent torn configs on crash.
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut tmp, json.as_bytes()).map_err(|e| e.to_string())?;
    tmp.persist(&path).map_err(|e| e.to_string())?;
    Ok(())
}
