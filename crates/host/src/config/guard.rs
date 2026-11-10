//! Whether the semantic guard is required, and where that answer came from.

use super::*;

/// Where the effective value of a security-relevant setting came from.
///
/// Returned alongside the value so an operator can be shown *why* it is what it
/// is, instead of being told a number and left to guess which of two files
/// produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSource {
    /// Neither the environment nor the settings file said anything.
    Default,
    /// Only the environment said so.
    Environment,
    /// Only `.ectoledger/settings.json` said so.
    SettingsFile,
    /// Both said so, and they agreed.
    Both,
    /// They disagreed, and the stricter of the two won.
    StricterOfTwo,
}

impl SettingSource {
    pub fn as_str(self) -> &'static str {
        match self {
            SettingSource::Default => "default",
            SettingSource::Environment => "environment",
            SettingSource::SettingsFile => "settings file",
            SettingSource::Both => "environment and settings file (agreeing)",
            SettingSource::StricterOfTwo => {
                "environment and settings file disagreed; the stricter value won"
            }
        }
    }
}

/// Parse a boolean the way this project's environment variables are written.
pub(super) fn parse_env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .and_then(|s| match s.to_lowercase().as_str() {
            "0" | "false" | "no" => Some(false),
            _ => s.parse().ok(),
        })
}

/// The effective value of `GUARD_REQUIRED`, and what decided it.
///
/// **Most-restrictive-wins.** Every other key in this module reads
/// `.ectoledger/settings.json` first and the environment second, because the
/// desktop GUI owns that file and expects its own toggle to win. For the
/// primary security control that ordering meant `export GUARD_REQUIRED=true` -
/// which `docs/getting-started/running-securely.md` instructs - was silently discarded on any
/// machine where the GUI had ever written `"guard_required": false`. The export
/// is the thing that looks authoritative, and it was the thing being ignored.
///
/// Inverting the order would have swapped which side loses. Requiring the guard
/// whenever *either* source requires it loses nothing: an operator who sets the
/// environment variable gets the protection, and a GUI user who has not set it
/// keeps the toggle. The only behaviour that becomes unreachable is turning the
/// guard off from the desktop on a host whose environment demands it - which is
/// the case this exists to prevent.
///
/// Default is `true` when neither source speaks. `GUARD_LLM_BACKEND` and
/// `GUARD_LLM_MODEL` keep settings-first precedence: they select *which* guard
/// runs, not whether one is required.
pub fn guard_required_effective() -> (bool, SettingSource) {
    let from_settings = load_settings_config().and_then(|c| c.guard_required);
    let from_env = parse_env_bool("GUARD_REQUIRED");

    match (from_settings, from_env) {
        (None, None) => (true, SettingSource::Default),
        (Some(v), None) => (v, SettingSource::SettingsFile),
        (None, Some(v)) => (v, SettingSource::Environment),
        (Some(a), Some(b)) if a == b => (a, SettingSource::Both),
        // Disagreement: `true` is the restrictive value, so `true` wins.
        (Some(_), Some(_)) => (true, SettingSource::StricterOfTwo),
    }
}

/// When true, guard is required and GUARD_LLM_BACKEND / GUARD_LLM_MODEL must be set.
/// Env: GUARD_REQUIRED, default TRUE. Set GUARD_REQUIRED=false only for development.
/// In production, a guard running the same model class as the primary is not a real guard.
///
/// See [`guard_required_effective`] for the precedence rule and why it differs
/// from the rest of this module.
pub fn guard_required() -> bool {
    guard_required_effective().0
}

/// Returns an error if guard is required but GUARD_LLM_BACKEND or GUARD_LLM_MODEL are unset.
pub fn ensure_guard_config() -> Result<(), String> {
    if !guard_required() {
        return Ok(());
    }
    let missing: Vec<&str> = [
        guard_llm_backend().is_none().then_some("GUARD_LLM_BACKEND"),
        guard_llm_model().is_none().then_some("GUARD_LLM_MODEL"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "GUARD_REQUIRED is set but {} are unset. Set them for production mode.",
            missing.join(" and ")
        ))
    }
}
