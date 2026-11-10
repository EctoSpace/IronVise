//! `ironvise hook install`: put the hook into Claude Code's settings,
//! Codex's `hooks.json`, which has the same shape, or Antigravity CLI's
//! `hooks.json`, which names each hook.
//!
//! Merges into an existing settings file rather than replacing it, and never
//! adds a second IronVise hook: two hooks for one tool call would send the
//! same `tool_use_id` twice, and the second is refused as a replay.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

const TIMEOUT_SECS: u64 = 15;

/// Which Claude Code settings file to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// `<project>/.claude/settings.local.json`: this machine only, not checked in.
    Local,
    /// `<project>/.claude/settings.json`: shared with everyone on the project.
    Shared,
    /// `~/.claude/settings.json`: every project of this user.
    User,
    /// `<project>/.codex/hooks.json`: Codex runs it once the project's
    /// `.codex/` layer is trusted.
    CodexProject,
    /// `~/.codex/hooks.json`: Codex, every project of this user.
    CodexUser,
    /// `<project>/.agents/hooks.json`: Antigravity CLI, this workspace.
    AntigravityProject,
    /// `~/.gemini/config/hooks.json`: Antigravity CLI, every workspace.
    AntigravityUser,
}

pub fn settings_path(scope: Scope, project: &Path, home: &Path) -> PathBuf {
    match scope {
        Scope::Local => project.join(".claude/settings.local.json"),
        Scope::Shared => project.join(".claude/settings.json"),
        Scope::User => home.join(".claude/settings.json"),
        Scope::CodexProject => project.join(".codex/hooks.json"),
        Scope::CodexUser => home.join(".codex/hooks.json"),
        Scope::AntigravityProject => project.join(".agents/hooks.json"),
        Scope::AntigravityUser => home.join(".gemini/config/hooks.json"),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Added,
    Updated,
    Unchanged,
}

fn is_ours(hook: &Value) -> bool {
    hook.get("command")
        .and_then(Value::as_str)
        .is_some_and(|c| {
            (c.contains("ectoledger") || c.contains("ironvise")) && c.trim_end().ends_with(" hook")
        })
}

/// The events the hook answers: a decision before a tool runs, a data
/// receipt after.
const EVENTS: [&str; 2] = ["PreToolUse", "PostToolUse"];

/// Merge the IronVise hook into `settings` for every event in [`EVENTS`],
/// keeping everything else.
pub fn merge_hook(
    settings: Value,
    command: &str,
    matcher: &str,
) -> Result<(Value, Change), String> {
    let mut settings = match settings {
        Value::Null => json!({}),
        v @ Value::Object(_) => v,
        _ => return Err("the settings file is not a JSON object".into()),
    };
    let wanted_hook = json!({ "type": "command", "command": command, "timeout": TIMEOUT_SECS });
    let hooks = settings
        .as_object_mut()
        .expect("checked above")
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("`hooks` is not an object")?;
    let (mut found, mut changed) = (false, false);
    for event in EVENTS {
        let entries = hooks
            .entry(event)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or(format!("`hooks.{event}` is not an array"))?;
        let (had_ours, merged) = merge_entries(entries, matcher, &wanted_hook);
        found |= had_ours;
        changed |= merged;
    }
    let change = match (changed, found) {
        (false, _) => Change::Unchanged,
        (true, true) => Change::Updated,
        (true, false) => Change::Added,
    };
    Ok((settings, change))
}

/// Leave exactly one IronVise entry in one event's list. Returns whether
/// there was one before, and whether the list changed.
fn merge_entries(entries: &mut Vec<Value>, matcher: &str, wanted_hook: &Value) -> (bool, bool) {
    let ours: Vec<&Value> = entries
        .iter()
        .filter(|e| hooks_of(e).iter().any(is_ours))
        .collect();
    let already = matches!(ours.as_slice(), [e]
        if e["matcher"] == matcher && hooks_of(e) == [wanted_hook.clone()]);
    let found = !ours.is_empty();
    if already {
        return (true, false);
    }
    for entry in entries.iter_mut() {
        if let Some(list) = entry.get_mut("hooks").and_then(Value::as_array_mut) {
            list.retain(|h| !is_ours(h));
        }
    }
    entries.retain(|e| e.get("hooks").is_none() || !hooks_of(e).is_empty());
    entries.push(json!({ "matcher": matcher, "hooks": [wanted_hook] }));
    (found, true)
}

/// The name the IronVise hook has in Antigravity's `hooks.json`.
const ANTIGRAVITY_HOOK_NAME: &str = "ectoledger";

/// Set the IronVise hook in Antigravity's `hooks.json`, keeping every other
/// named hook. One matcher per tool: its documentation does not say whether
/// a matcher is a pattern or a name, and a single name works as either.
/// Only `PreToolUse`: Antigravity gives a hook no tool result to receipt.
pub fn merge_antigravity_hook(
    settings: Value,
    command: &str,
    tools: &[&str],
) -> Result<(Value, Change), String> {
    let mut settings = match settings {
        Value::Null => json!({}),
        v @ Value::Object(_) => v,
        _ => return Err("the hooks file is not a JSON object".into()),
    };
    let entries: Vec<Value> = tools
        .iter()
        .map(|tool| {
            json!({
                "matcher": tool,
                "hooks": [{ "type": "command", "command": command, "timeout": TIMEOUT_SECS }],
            })
        })
        .collect();
    let wanted = json!({ "PreToolUse": entries });
    let hooks = settings.as_object_mut().expect("checked above");
    let change = match hooks.get(ANTIGRAVITY_HOOK_NAME) {
        Some(current) if *current == wanted => return Ok((settings, Change::Unchanged)),
        Some(_) => Change::Updated,
        None => Change::Added,
    };
    hooks.insert(ANTIGRAVITY_HOOK_NAME.to_string(), wanted);
    Ok((settings, change))
}

fn hooks_of(entry: &Value) -> &[Value] {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// The command Claude Code runs: this binary's absolute path, so the hook
/// works whether or not `ectoledger` is on Claude Code's PATH.
pub fn default_command() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("locating this binary: {e}"))?;
    let exe = exe.to_string_lossy();
    Ok(if exe.contains(char::is_whitespace) {
        format!("'{exe}' hook")
    } else {
        format!("{exe} hook")
    })
}

/// Write the hook into `path`, creating the file and `.claude/` if needed.
pub fn install(path: &Path, command: &str, matcher: &str) -> Result<Change, String> {
    write_merged(path, |current| merge_hook(current, command, matcher))
}

/// Write the hook into Antigravity's `hooks.json` at `path`.
pub fn install_antigravity(path: &Path, command: &str, tools: &[&str]) -> Result<Change, String> {
    write_merged(path, |current| {
        merge_antigravity_hook(current, command, tools)
    })
}

/// Read `path`, `merge` the hook in, and write it back if that changed it.
fn write_merged(
    path: &Path,
    merge: impl FnOnce(Value) -> Result<(Value, Change), String>,
) -> Result<Change, String> {
    let current = match std::fs::read_to_string(path) {
        Ok(text) if text.trim().is_empty() => Value::Null,
        Ok(text) => serde_json::from_str(&text).map_err(|e| {
            format!(
                "{} is not valid JSON ({e}); fix or move it first",
                path.display()
            )
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Value::Null,
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    let (merged, change) = merge(current)?;
    if change == Change::Unchanged {
        return Ok(change);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(&merged).expect("a Value serialises") + "\n";
    std::fs::write(&tmp, text).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replacing {}: {e}", path.display()))?;
    Ok(change)
}

/// What the Observer says about the configured URL and token, for the
/// install summary. Never fails the install: the Observer may start later.
pub async fn check_observer(url: &str, token: Option<&str>) -> String {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => return format!("could not build an HTTP client: {e}"),
    };
    let base = url.trim_end_matches('/');
    if client
        .get(format!("{base}/api/status"))
        .send()
        .await
        .is_err()
    {
        return format!(
            "not reachable at {base}. Start it (`ironvise serve` or the desktop app); \
             until then the hook blocks every checked tool call."
        );
    }
    let Some(token) = token else {
        return format!(
            "reachable at {base}, but ECTOLEDGER_TOKEN is not set: the hook will block every call."
        );
    };
    match client
        .get(format!("{base}/api/sessions"))
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => format!("reachable at {base}, token accepted."),
        Ok(r) => format!(
            "reachable at {base}, but the token was refused ({}).",
            r.status()
        ),
        Err(e) => format!("reachable at {base}, but the token check failed: {e}"),
    }
}

#[cfg(test)]
mod tests;
