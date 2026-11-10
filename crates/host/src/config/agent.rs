//! Limits and settings of the agent loop: steps, failure limits, the token
//! budget, snapshots, key rotation, sandbox strictness, the credential audience.

use super::*;

/// Number of steps between auto-snapshots. Env: AGENT_SNAPSHOT_INTERVAL, default 50.
pub fn snapshot_interval() -> u32 {
    std::env::var("AGENT_SNAPSHOT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
}

/// Consecutive LLM errors before aborting the session. Env: AGENT_LLM_ERROR_LIMIT, default 5.
pub fn llm_error_limit() -> u32 {
    std::env::var("AGENT_LLM_ERROR_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}

/// Consecutive Guard denials before aborting the session. Env: AGENT_GUARD_DENIAL_LIMIT, default 3.
pub fn guard_denial_limit() -> u32 {
    std::env::var("AGENT_GUARD_DENIAL_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

/// Consecutive schema failures (missing/too-short justification) before aborting. Env: AGENT_JUSTIFICATION_FAILURE_LIMIT, default 3.
pub fn justification_failure_limit() -> u32 {
    std::env::var("AGENT_JUSTIFICATION_FAILURE_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

/// Max approximate token budget per session (character count / 4 estimate).
/// Env: AGENT_TOKEN_BUDGET_MAX. Default: unlimited (None).
pub fn token_budget_max() -> Option<u64> {
    std::env::var("AGENT_TOKEN_BUDGET_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Max cognitive loop steps. Precedence: `.ectoledger/settings.json` (`max_steps`),
/// then `AGENT_MAX_STEPS`, default 20.
pub fn max_steps() -> u32 {
    max_steps_configured().unwrap_or(20)
}

/// Explicitly configured max steps from `.ectoledger/settings.json` or `AGENT_MAX_STEPS`,
/// or `None` when neither is set (allowing a loaded policy's `max_steps` to take effect).
pub fn max_steps_configured() -> Option<u32> {
    load_settings_config()
        .and_then(|c| c.max_steps)
        .or_else(|| {
            std::env::var("AGENT_MAX_STEPS")
                .ok()
                .and_then(|s| s.parse().ok())
        })
}

/// Number of cognitive-loop steps between automatic signing-key rotations.
/// Env: `AGENT_KEY_ROTATION_STEPS`. Default: `None` (rotation disabled).
///
/// Example: `AGENT_KEY_ROTATION_STEPS=50` rotates after every 50 agent steps.
pub fn key_rotation_interval_steps() -> Option<u32> {
    std::env::var("AGENT_KEY_ROTATION_STEPS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n > 0)
}

/// When true, sandbox setup failures fall back to less-isolated execution
/// (unsandboxed child processes, host executor after container-tier errors)
/// instead of aborting the action. This weakens isolation and is intended for
/// development environments where no OS sandbox is available.
/// Env: `ECTO_SANDBOX_PERMISSIVE`, default `false` (fail closed).
pub fn sandbox_permissive() -> bool {
    std::env::var("ECTO_SANDBOX_PERMISSIVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// `ECTO_VC_AUDIENCE`: who session credentials are issued to. Set, each VC
/// carries it as `aud`, and verifiers must name it to accept the VC. Unset, a
/// VC is for anyone to verify.
pub fn vc_audience() -> Option<String> {
    std::env::var("ECTO_VC_AUDIENCE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
