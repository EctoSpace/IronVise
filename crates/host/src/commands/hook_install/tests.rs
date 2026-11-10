use super::*;

const CMD: &str = "/opt/ectoledger hook";
const M: &str = "Bash|Read";

fn ours(v: &Value) -> Vec<&Value> {
    v["hooks"]["PreToolUse"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|e| hooks_of(e).iter())
        .filter(|h| is_ours(h))
        .collect()
}

#[test]
fn an_empty_file_gets_the_hook() {
    let (v, change) = merge_hook(Value::Null, CMD, M).unwrap();
    assert_eq!(change, Change::Added);
    assert_eq!(v["hooks"]["PreToolUse"][0]["matcher"], M);
    assert_eq!(v["hooks"]["PreToolUse"][0]["hooks"][0]["command"], CMD);
}

#[test]
fn everything_else_in_the_file_is_kept() {
    let before = json!({
        "model": "opus",
        "permissions": { "allow": ["Bash(ls:*)"] },
        "hooks": {
            "PostToolUse": [{ "matcher": "Write", "hooks": [{ "type": "command", "command": "fmt" }] }],
            "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "other-guard" }] }],
        },
    });
    let (v, change) = merge_hook(before.clone(), CMD, M).unwrap();
    assert_eq!(change, Change::Added);
    assert_eq!(v["model"], before["model"]);
    assert_eq!(v["permissions"], before["permissions"]);
    assert_eq!(
        v["hooks"]["PostToolUse"][0],
        before["hooks"]["PostToolUse"][0]
    );
    assert_eq!(
        v["hooks"]["PreToolUse"][0],
        before["hooks"]["PreToolUse"][0]
    );
    assert_eq!(ours(&v).len(), 1);
}

#[test]
fn the_hook_answers_before_and_after_every_matched_tool() {
    let (v, _) = merge_hook(Value::Null, CMD, M).unwrap();
    for event in EVENTS {
        assert_eq!(v["hooks"][event][0]["matcher"], M, "{event}");
        assert_eq!(v["hooks"][event][0]["hooks"][0]["command"], CMD, "{event}");
    }
}

/// An install from before data receipts has only `PreToolUse`; running
/// install again adds the `PostToolUse` half and reports an update.
#[test]
fn an_install_without_receipts_gains_them() {
    let before = json!({ "hooks": { "PreToolUse": [
            { "matcher": M, "hooks": [{ "type": "command", "command": CMD, "timeout": TIMEOUT_SECS }] },
        ] } });
    let (v, change) = merge_hook(before.clone(), CMD, M).unwrap();
    assert_eq!(change, Change::Updated);
    assert_eq!(v["hooks"]["PreToolUse"], before["hooks"]["PreToolUse"]);
    assert_eq!(v["hooks"]["PostToolUse"][0]["hooks"][0]["command"], CMD);
}

#[test]
fn installing_twice_changes_nothing() {
    let (once, _) = merge_hook(Value::Null, CMD, M).unwrap();
    let (twice, change) = merge_hook(once.clone(), CMD, M).unwrap();
    assert_eq!(change, Change::Unchanged);
    assert_eq!(once, twice);
}

/// Two IronVise hooks would send each tool use twice, and the second
/// is refused as a replay. An old install is replaced, never added to.
#[test]
fn an_old_or_duplicated_hook_is_replaced_by_one() {
    let before = json!({ "hooks": { "PreToolUse": [
            { "matcher": "Bash", "hooks": [{ "type": "command", "command": "ectoledger hook" }] },
            { "matcher": "Read", "hooks": [
                { "type": "command", "command": "/usr/bin/ectoledger hook" },
                { "type": "command", "command": "keep-me" },
            ] },
        ] } });
    let (v, change) = merge_hook(before, CMD, M).unwrap();
    assert_eq!(change, Change::Updated);
    let mine = ours(&v);
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0]["command"], CMD);
    let text = v.to_string();
    assert!(text.contains("keep-me"), "{text}");
    assert!(
        !text.contains("\"Bash\""),
        "the emptied entry is gone: {text}"
    );
}

#[test]
fn a_file_that_is_not_settings_is_not_touched() {
    assert!(merge_hook(json!([1, 2]), CMD, M).is_err());
    assert!(merge_hook(json!({ "hooks": [] }), CMD, M).is_err());
    assert!(merge_hook(json!({ "hooks": { "PreToolUse": {} } }), CMD, M).is_err());
}

#[test]
fn install_writes_the_file_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = settings_path(Scope::Local, dir.path(), Path::new("/nonexistent"));
    assert_eq!(install(&path, CMD, M).unwrap(), Change::Added);
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(ours(&written).len(), 1);
    assert_eq!(install(&path, CMD, M).unwrap(), Change::Unchanged);

    std::fs::write(&path, "{ not json").unwrap();
    assert!(
        install(&path, CMD, M).is_err(),
        "a broken file is reported, not overwritten"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
}

#[test]
fn each_scope_names_its_file() {
    let (p, h) = (Path::new("/p"), Path::new("/h"));
    assert_eq!(
        settings_path(Scope::Local, p, h),
        Path::new("/p/.claude/settings.local.json")
    );
    assert_eq!(
        settings_path(Scope::Shared, p, h),
        Path::new("/p/.claude/settings.json")
    );
    assert_eq!(
        settings_path(Scope::User, p, h),
        Path::new("/h/.claude/settings.json")
    );
}

#[tokio::test]
async fn an_unreachable_observer_is_reported_not_fatal() {
    let msg = check_observer("http://127.0.0.1:9", Some("t")).await;
    assert!(msg.starts_with("not reachable"), "{msg}");
}

#[test]
fn the_codex_scopes_name_codexs_hooks_file() {
    let (p, h) = (Path::new("/p"), Path::new("/h"));
    assert_eq!(
        settings_path(Scope::CodexProject, p, h),
        Path::new("/p/.codex/hooks.json")
    );
    assert_eq!(
        settings_path(Scope::CodexUser, p, h),
        Path::new("/h/.codex/hooks.json")
    );
}

#[test]
fn the_antigravity_scopes_name_its_hooks_files() {
    let (p, h) = (Path::new("/p"), Path::new("/h"));
    assert_eq!(
        settings_path(Scope::AntigravityProject, p, h),
        Path::new("/p/.agents/hooks.json")
    );
    assert_eq!(
        settings_path(Scope::AntigravityUser, p, h),
        Path::new("/h/.gemini/config/hooks.json")
    );
}

#[test]
fn antigravity_gets_one_named_hook_with_a_matcher_per_tool() {
    let other = json!({ "lint": { "PostToolUse": [{ "matcher": "run_command", "hooks": [] }] } });
    let (v, change) =
        merge_antigravity_hook(other.clone(), CMD, &["run_command", "view_file"]).unwrap();
    assert_eq!(change, Change::Added);
    assert_eq!(v["lint"], other["lint"], "other named hooks are kept");
    let entries = v["ectoledger"]["PreToolUse"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1]["matcher"], "view_file");
    assert_eq!(entries[1]["hooks"][0]["command"], CMD);
    assert!(
        v["ectoledger"].get("PostToolUse").is_none(),
        "no result to receipt"
    );

    let (again, change) =
        merge_antigravity_hook(v.clone(), CMD, &["run_command", "view_file"]).unwrap();
    assert_eq!(change, Change::Unchanged);
    assert_eq!(again, v);
    let (_, change) = merge_antigravity_hook(v, "/new/ectoledger hook", &["run_command"]).unwrap();
    assert_eq!(change, Change::Updated);
}

#[test]
fn rebrand_updates_legacy_hooks_without_duplicates() {
    let (legacy, _) = merge_hook(Value::Null, CMD, M).unwrap();
    let (branded, change) = merge_hook(legacy, "/opt/ironvise hook", M).unwrap();
    assert_eq!(change, Change::Updated);
    assert_eq!(ours(&branded).len(), 1);
    let (again, change) = merge_hook(branded.clone(), "/opt/ironvise hook", M).unwrap();
    assert_eq!(change, Change::Unchanged);
    assert_eq!(again, branded);
}
