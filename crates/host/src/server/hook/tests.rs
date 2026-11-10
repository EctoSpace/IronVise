use super::*;

fn run(cmd: &str) -> ProposedIntent {
    map_tool("Bash", &serde_json::json!({ "command": cmd }), None).unwrap()
}

async fn judge(policy: Option<&str>, cmd: &str) -> Verdict {
    let engine = policy.map(|toml| {
        ectoledger_core::policy::PolicyEngine::new(toml::from_str(toml).unwrap()).unwrap()
    });
    let tripwire = Tripwire::new(
        vec![],
        vec![],
        crate::tripwire::default_banned_command_patterns(),
        0,
        true,
    );
    let ctx = EvaluationContext {
        policy: engine.as_ref(),
        tripwire: &tripwire,
        goal: "test",
        step: 0,
        guard_required: false,
    };
    evaluate_chain(&ctx, None, &run(cmd)).await
}

#[test]
fn an_mcp_tool_maps_to_its_own_action_name() {
    let args = serde_json::json!({ "repo": "x", "title": "t" });
    let i = map("mcp__github__create_issue", &args).expect("maps");
    assert_eq!(i.action, "mcp:github/create_issue");
    assert_eq!(i.params["server"], "github");
    assert_eq!(i.params["tool"], "create_issue");
    assert_eq!(i.params["arguments"], args);
    let nested = map("mcp__my_server__do__it", &args).expect("maps");
    assert_eq!(
        nested.action, "mcp:my_server/do__it",
        "the first `__` ends the server name"
    );
}

async fn judge_mcp(
    policy: Option<&str>,
    allow: &[&str],
    tool: &str,
    args: serde_json::Value,
) -> Verdict {
    let engine = policy.map(|toml| {
        ectoledger_core::policy::PolicyEngine::new(toml::from_str(toml).unwrap()).unwrap()
    });
    let tripwire = Tripwire::new(
        vec![],
        vec![],
        crate::tripwire::default_banned_command_patterns(),
        0,
        true,
    )
    .with_allowed_mcp_tools(allow.iter().map(|s| s.to_string()).collect());
    let ctx = EvaluationContext {
        policy: engine.as_ref(),
        tripwire: &tripwire,
        goal: "test",
        step: 0,
        guard_required: false,
    };
    evaluate_chain(&ctx, None, &map(tool, &args).unwrap()).await
}

#[tokio::test]
async fn mcp_tools_are_judged_by_allowlist_policy_and_command_arguments() {
    use serde_json::json;
    let t = "mcp__github__create_issue";
    assert!(
        judge_mcp(None, &[], t, json!({})).await.is_allowed(),
        "no allowlist: any tool"
    );
    assert!(
        judge_mcp(None, &["github/*"], t, json!({}))
            .await
            .is_allowed()
    );
    assert!(
        judge_mcp(None, &["github/create_issue"], t, json!({}))
            .await
            .is_allowed()
    );
    assert!(
        !judge_mcp(None, &["github/list_issues"], t, json!({}))
            .await
            .is_allowed()
    );
    assert!(
        !judge_mcp(None, &["gitlab/*"], t, json!({}))
            .await
            .is_allowed()
    );

    let forbid = r#"
            name = "no deletes"
            [[forbidden_actions]]
            action = "mcp:github/delete_repository"
        "#;
    let Verdict::Deny { stage, .. } = judge_mcp(
        Some(forbid),
        &[],
        "mcp__github__delete_repository",
        json!({}),
    )
    .await
    else {
        panic!("a forbidden MCP tool was allowed");
    };
    assert_eq!(stage, DenyStage::Policy);

    let shell = "mcp__shell__run";
    assert!(
        judge_mcp(None, &[], shell, json!({ "command": "ls && pwd" }))
            .await
            .is_allowed()
    );
    assert!(
        !judge_mcp(None, &[], shell, json!({ "command": "ls && sudo id" }))
            .await
            .is_allowed()
    );
    assert!(
        !judge_mcp(None, &[], shell, json!({ "cmd": "echo $(id)" }))
            .await
            .is_allowed()
    );
}

#[tokio::test]
async fn everyday_chains_are_allowed() {
    for cmd in [
        "git status && git diff",
        "cargo test 2>&1 | tail -5",
        "cd crates || true; ls",
        "git commit -m \"$(cat <<'EOF'\nFix: sudo docs && more\nEOF\n)\"",
    ] {
        assert!(judge(None, cmd).await.is_allowed(), "{cmd}");
    }
}

#[tokio::test]
async fn one_bad_part_refuses_the_chain_and_is_named() {
    let Verdict::Deny { reason, stage } = judge(None, "ls && sudo rm x | cat").await else {
        panic!("allowed");
    };
    assert_eq!(stage, DenyStage::Tripwire);
    assert!(reason.contains("(in `sudo rm x`)"), "{reason}");
}

/// The reason chains are split rather than allowed whole.
#[tokio::test]
async fn a_chain_cannot_ride_past_a_policy_on_its_first_program() {
    let policy = r#"
            name = "git only"
            [[allowed_actions]]
            action = "run_command"
            allowed_commands = ["git"]
        "#;
    assert!(
        judge(Some(policy), "git status && git log")
            .await
            .is_allowed()
    );
    let Verdict::Deny { reason, stage } = judge(Some(policy), "git status && ls /").await else {
        panic!("a chain rode past the policy");
    };
    assert_eq!(stage, DenyStage::Policy);
    assert!(reason.contains("(in `ls /`)"), "{reason}");
}

#[tokio::test]
async fn substitutions_and_redirects_are_still_refused() {
    for cmd in [
        "echo $(whoami)",
        "echo x > ~/.ssh/authorized_keys",
        "ls `id`",
    ] {
        assert!(!judge(None, cmd).await.is_allowed(), "{cmd}");
    }
}

fn map(tool: &str, input: &serde_json::Value) -> Option<ProposedIntent> {
    map_tool(tool, input, None)
}

// Only the Unix-path tests below use it; on Windows it would be dead code,
// which CI's `-D warnings` build refuses.
#[cfg(unix)]
fn root(tool: &str, input: serde_json::Value) -> Option<String> {
    map_tool(tool, &input, Some("/proj")).map(|i| {
        assert_eq!(i.action, "read_file");
        i.params["path"].as_str().unwrap().to_string()
    })
}

/// The list the ask message consults and the match that does the mapping
/// must not drift apart.
#[test]
fn mapped_tools_lists_exactly_what_maps() {
    let full = serde_json::json!({
        // A shell command for Bash and a one-file patch for apply_patch.
        "command": "*** Add File: /w/p\nls", "file_path": "/w/a", "notebook_path": "/w/n.ipynb",
        "url": "https://example.com", "pattern": "*", "path": "w",
    });
    let map = |tool: &str, input: &serde_json::Value| map_tool(tool, input, Some("/proj"));
    for tool in MAPPED_TOOLS {
        assert!(
            map(tool, &full).is_some(),
            "{tool} is listed but does not map"
        );
    }
    for tool in ["Task", "LS", "TodoWrite", "WebSearch", "mcp__no_tool_part"] {
        assert!(!MAPPED_TOOLS.contains(&tool));
        assert!(map(tool, &full).is_none(), "{tool} maps but is not listed");
    }
}

/// Antigravity's tools, each with the arguments its documentation gives,
/// map onto the action and the field the check reads.
#[test]
fn antigravity_tools_map_to_the_policy_vocabulary() {
    use serde_json::json;
    let cases = [
        (
            "run_command",
            json!({ "CommandLine": "ls -la", "Cwd": "/w" }),
            "run_command",
            "command",
            "ls -la",
        ),
        (
            "view_file",
            json!({ "AbsolutePath": "/w/a.rs" }),
            "read_file",
            "path",
            "/w/a.rs",
        ),
        (
            "write_to_file",
            json!({ "TargetFile": "/w/n.md", "CodeContent": "x" }),
            "write_file",
            "path",
            "/w/n.md",
        ),
        (
            "replace_file_content",
            json!({ "TargetFile": "/w/b.rs" }),
            "write_file",
            "path",
            "/w/b.rs",
        ),
        (
            "multi_replace_file_content",
            json!({ "TargetFile": "/w/c.rs" }),
            "write_file",
            "path",
            "/w/c.rs",
        ),
        (
            "list_dir",
            json!({ "DirectoryPath": "/w" }),
            "read_file",
            "path",
            "/w",
        ),
        (
            "find_by_name",
            json!({ "SearchDirectory": "/w", "Pattern": "*.rs" }),
            "read_file",
            "path",
            "/w",
        ),
        (
            "grep_search",
            json!({ "SearchPath": "/etc", "Query": "root" }),
            "read_file",
            "path",
            "/etc",
        ),
        (
            "read_url_content",
            json!({ "Url": "https://example.com" }),
            "http_get",
            "url",
            "https://example.com",
        ),
    ];
    assert_eq!(
        cases.len(),
        ANTIGRAVITY_TOOLS.len(),
        "every listed tool has a case"
    );
    for (tool, input, action, field, value) in cases {
        assert!(ANTIGRAVITY_TOOLS.contains(&tool), "{tool}");
        let intent = map_tool(tool, &input, None).unwrap_or_else(|| panic!("{tool} maps"));
        assert_eq!(intent.action, action, "{tool}");
        assert_eq!(intent.params[field], value, "{tool}");
    }
    // Without the argument the check needs, nothing is claimed.
    assert!(map_tool("view_file", &json!({ "StartLine": 1 }), None).is_none());
    // Its other tools have no equivalent and are escalated.
    for tool in [
        "search_web",
        "invoke_subagent",
        "generate_image",
        "ask_question",
    ] {
        assert!(map_tool(tool, &json!({}), None).is_none(), "{tool}");
    }
}

// Unix paths: on Windows `/proj` has no drive and is not absolute.
#[cfg(unix)]
#[test]
fn a_search_is_checked_as_a_read_of_the_directory_it_can_reach() {
    use serde_json::json;
    assert_eq!(
        root("Grep", json!({ "pattern": "fn main" })).as_deref(),
        Some("/proj")
    );
    assert_eq!(
        root("Glob", json!({ "pattern": "**/*.rs" })).as_deref(),
        Some("/proj")
    );
    assert_eq!(
        root(
            "Grep",
            json!({ "pattern": "x", "path": "/etc", "glob": "*.conf" })
        )
        .as_deref(),
        Some("/etc")
    );
    assert_eq!(
        root("Glob", json!({ "pattern": "*.rs", "path": "src" })).as_deref(),
        Some("/proj/src")
    );
    // The literal head of a glob narrows it, and an absolute one replaces
    // the path, which is how `Glob("/etc/*")` would otherwise slip by.
    assert_eq!(
        root("Glob", json!({ "pattern": "crates/*/src/**" })).as_deref(),
        Some("/proj/crates")
    );
    assert_eq!(
        root(
            "Glob",
            json!({ "pattern": "/etc/ssh/*_key", "path": "/proj" })
        )
        .as_deref(),
        Some("/etc/ssh")
    );
}

#[cfg(unix)]
#[test]
fn a_search_that_climbs_or_has_nowhere_to_start_is_not_mapped() {
    use serde_json::json;
    for pattern in ["../*", "src/../../x", "{src,..}/*", "a/{b,../..}/c"] {
        assert!(
            root("Glob", json!({ "pattern": pattern })).is_none(),
            "{pattern}"
        );
    }
    // Names with dots in them are not climbing.
    assert!(root("Glob", json!({ "pattern": "*..bak" })).is_some());
    // Without a working directory there is nothing to resolve against.
    assert!(map("Grep", &json!({ "pattern": "x" })).is_none());
    assert!(map("Grep", &json!({ "pattern": "x", "path": "src" })).is_none());
    assert!(map("Grep", &json!({ "pattern": "x", "path": "/abs" })).is_some());
    assert!(
        map("Glob", &json!({ "path": "/abs" })).is_none(),
        "Glob needs a pattern"
    );
}

#[cfg(windows)]
fn root_windows(tool: &str, input: serde_json::Value) -> Option<String> {
    map_tool(tool, &input, Some(r"C:\proj")).map(|i| {
        assert_eq!(i.action, "read_file");
        i.params["path"].as_str().unwrap().to_string()
    })
}

#[cfg(windows)]
#[test]
fn a_search_is_checked_as_a_read_of_the_directory_it_can_reach_on_windows() {
    use serde_json::json;
    assert_eq!(
        root_windows("Grep", json!({ "pattern": "fn main" })).as_deref(),
        Some(r"C:\proj")
    );
    assert_eq!(
        root_windows("Glob", json!({ "pattern": "**/*.rs" })).as_deref(),
        Some(r"C:\proj")
    );
    assert_eq!(
        root_windows(
            "Grep",
            json!({ "pattern": "x", "path": r"C:\etc", "glob": "*.conf" })
        )
        .as_deref(),
        Some(r"C:\etc")
    );
    assert_eq!(
        root_windows("Glob", json!({ "pattern": "*.rs", "path": "src" })).as_deref(),
        Some(r"C:\proj\src")
    );
    assert_eq!(
        root_windows("Glob", json!({ "pattern": "crates/*/src/**" })).as_deref(),
        Some(r"C:\proj\crates")
    );
    assert_eq!(
        root_windows(
            "Glob",
            json!({ "pattern": r"C:\etc\ssh\*_key", "path": r"C:\proj" })
        )
        .as_deref(),
        Some(r"C:\etc\ssh")
    );
    assert_eq!(
        root_windows("Glob", json!({ "pattern": r"\\server\share\*.rs" })).as_deref(),
        Some(r"\\server\share\"),
        "a UNC glob pattern is itself absolute and overrides the cwd base entirely"
    );
}

#[cfg(windows)]
#[test]
fn a_search_that_climbs_or_has_nowhere_to_start_is_not_mapped_on_windows() {
    use serde_json::json;
    for pattern in [
        "../*",
        r"..\*",
        "src/../../x",
        r"src\..\..\x",
        "{src,..}/*",
        "a/{b,../..}/c",
    ] {
        assert!(
            root_windows("Glob", json!({ "pattern": pattern })).is_none(),
            "{pattern}"
        );
    }
    assert!(root_windows("Glob", json!({ "pattern": "*..bak" })).is_some());
    assert!(map("Grep", &json!({ "pattern": "x" })).is_none());
    assert!(map("Grep", &json!({ "pattern": "x", "path": "src" })).is_none());
    assert!(map("Grep", &json!({ "pattern": "x", "path": r"C:\abs" })).is_some());
    assert!(
        map("Glob", &json!({ "path": r"C:\abs" })).is_none(),
        "Glob needs a pattern"
    );
}

#[test]
fn the_read_and_run_tools_produce_the_right_actions() {
    let bash = map("Bash", &serde_json::json!({ "command": "ls -la" })).expect("Bash maps");
    assert_eq!(bash.action, "run_command");
    assert_eq!(bash.params["command"], "ls -la");

    let read = map("Read", &serde_json::json!({ "file_path": "/etc/hosts" })).expect("Read maps");
    assert_eq!(read.action, "read_file");
    assert_eq!(read.params["path"], "/etc/hosts");

    let web = map(
        "WebFetch",
        &serde_json::json!({ "url": "https://example.com" }),
    )
    .expect("WebFetch maps");
    assert_eq!(web.action, "http_get");
    assert_eq!(web.params["url"], "https://example.com");
}

#[test]
fn every_file_changing_tool_maps_to_write_file_on_its_path() {
    for (tool, key) in [
        ("Write", "file_path"),
        ("Edit", "file_path"),
        ("MultiEdit", "file_path"),
        ("NotebookEdit", "notebook_path"),
    ] {
        let i = map(
            tool,
            &serde_json::json!({ key: "/w/a.txt", "content": "x" }),
        )
        .unwrap_or_else(|| panic!("{tool} maps"));
        assert_eq!(i.action, "write_file", "{tool}");
        assert_eq!(i.params["path"], "/w/a.txt", "{tool}");
        // The content is not forwarded: the policy has no vocabulary for it.
        assert!(i.params.get("content").is_none(), "{tool}");
    }
    assert!(map("NotebookEdit", &serde_json::json!({ "file_path": "/w" })).is_none());
}

#[test]
fn unmapped_tools_are_not_mapped_rather_than_guessed() {
    // Sub-agent and MCP tools have no policy equivalent. Guessing a
    // mapping would make the hook claim to evaluate something it cannot.
    for tool in ["Task", "LS", "mcp__no_tool_part"] {
        assert!(
            map(tool, &serde_json::json!({ "file_path": "/tmp/x" })).is_none(),
            "{tool} should not map"
        );
    }
}

#[test]
fn a_tool_missing_its_key_field_does_not_map() {
    // A Bash call with no command is malformed; mapping it to an empty
    // command would send nonsense through the tripwire.
    assert!(map("Bash", &serde_json::json!({})).is_none());
    assert!(map("Read", &serde_json::json!({ "path": "/etc" })).is_none());
}

#[test]
fn the_synthesised_justification_states_its_own_absence() {
    let intent = map("Bash", &serde_json::json!({ "command": "ls" })).unwrap();
    assert!(
        intent.justification.contains("no model justification"),
        "the placeholder must not read as a real rationale: {:?}",
        intent.justification
    );
    // Long enough to clear the tripwire's minimum, which is the practical
    // reason it exists at all.
    assert!(intent.justification.len() >= 20);
}

#[test]
fn decisions_serialise_as_the_lowercase_strings_the_client_expects() {
    let json = |d: Decision| serde_json::to_string(&d).unwrap();
    assert_eq!(json(Decision::Allow), "\"allow\"");
    assert_eq!(json(Decision::Deny), "\"deny\"");
    assert_eq!(json(Decision::Ask), "\"ask\"");
}

#[cfg(unix)]
#[test]
fn a_patch_names_every_file_it_touches_once_relative_to_cwd() {
    let patch = "*** Begin Patch\n\
*** Add File: new.rs\n+x\n\
*** Update File: src/lib.rs\n*** Move to: src/core.rs\n@@\n-a\n+b\n\
*** Delete File: /abs/old.rs\n\
*** Update File: new.rs\n@@\n-x\n+y\n\
*** End Patch\n";
    let intent = map_tool(
        "apply_patch",
        &serde_json::json!({ "command": patch }),
        Some("/proj"),
    )
    .unwrap();
    assert_eq!(intent.action, "write_file");
    assert_eq!(
        intent.params["paths"],
        serde_json::json!([
            "/proj/new.rs",
            "/proj/src/lib.rs",
            "/proj/src/core.rs",
            "/abs/old.rs"
        ])
    );
}

#[test]
fn a_patch_with_no_file_or_a_relative_one_without_cwd_does_not_map() {
    let none = serde_json::json!({ "command": "*** Begin Patch\n*** End Patch\n" });
    assert!(map_tool("apply_patch", &none, Some("/proj")).is_none());
    let relative = serde_json::json!({ "command": "*** Add File: a.rs\n+x\n" });
    assert!(map_tool("apply_patch", &relative, None).is_none());
}
