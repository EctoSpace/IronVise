use super::*;

fn split(c: &str) -> Vec<String> {
    split_command_chain(c).unwrap()
}

#[test]
fn a_chain_splits_at_every_unquoted_operator() {
    assert_eq!(
        split("cd crates && cargo test 2>&1 | tail -5; echo done || true & wait"),
        [
            "cd crates",
            "cargo test 2>&1",
            "tail -5",
            "echo done",
            "true",
            "wait"
        ]
    );
    assert_eq!(split("a\nb |& c"), ["a", "b", "c"]);
    assert_eq!(
        split("ls &> out.log"),
        ["ls &> out.log"],
        "&> is a redirect"
    );
    assert_eq!(
        split("ls >& out.log"),
        ["ls >& out.log"],
        ">& is a redirect"
    );
    assert_eq!(split("ls;;"), ["ls"], "empty parts are dropped");
}

#[test]
fn operators_inside_quotes_or_escaped_are_text() {
    assert_eq!(split(r#"echo "a && b | c""#), [r#"echo "a && b | c""#]);
    assert_eq!(split("echo 'x; rm -rf /'"), ["echo 'x; rm -rf /'"]);
    assert_eq!(split(r"echo a \&\& b"), [r"echo a \&\& b"]);
    assert_eq!(split(r#"echo "it's" && ls"#), [r#"echo "it's""#, "ls"]);
}

#[test]
fn an_unterminated_quote_is_refused() {
    for c in ["echo 'open", r#"echo "open"#] {
        assert!(
            matches!(split_command_chain(c), Err(TripwireError::BannedCommand(_))),
            "{c}"
        );
    }
    assert!(matches!(
        split_command_chain(" ; "),
        Err(TripwireError::MissingParam(_))
    ));
}

/// Claude Code's commit form. The body may contain anything, since it is
/// never expanded, and must not split or trip a banned word.
#[test]
fn a_quoted_heredoc_commit_message_is_text() {
    let cmd = "git add -A && git commit -m \"$(cat <<'EOF'\nFix: stop sudo && rm -rf in docs | \"quoted\"\n\nBody $(not run)\nEOF\n)\" && git push";
    assert_eq!(
        split(cmd),
        ["git add -A", "git commit -m \"heredoc-text\"", "git push"]
    );
    assert_eq!(
        split("cat > f <<-\"END\"\n\tx\n\tEND\n"),
        ["cat > f <<-\"END\"", "x", "END"],
        "only the $(cat <<…) form is rewritten; a bare heredoc's lines are checked as commands, which can only refuse more"
    );
}

#[test]
fn a_heredoc_that_is_not_plain_text_is_left_for_the_tripwire() {
    // Unquoted delimiter: the body is expanded, so it is code.
    let unquoted = "echo \"$(cat <<EOF\n$(rm -rf /)\nEOF\n)\"";
    assert!(split(unquoted).join(" ").contains("$("));
    // Something after the closing delimiter: not a plain substitution.
    let smuggled = "echo \"$(cat <<'EOF'\nx\nEOF\nrm -rf /)\"";
    assert!(split(smuggled).join(" ").contains("$("));
}

#[test]
fn a_single_word_ban_matches_a_whole_word_only() {
    let tw = Tripwire::new(vec![], vec![], default_banned_command_patterns(), 0, true);
    let run = |c: &str| {
        tw.validate(&ProposedIntent {
            action: "run_command".into(),
            params: serde_json::json!({ "command": c }),
            justification: String::new(),
            reasoning: String::new(),
        })
    };
    for ok in [
        "git add README.md",
        "cat address.txt",
        "grep -r pseudocode .",
        "ls hidden",
        "sudoku --solve puzzle.txt",
    ] {
        assert!(run(ok).is_ok(), "{ok} should pass");
    }
    for banned in [
        "dd if=/dev/zero of=x",
        "/bin/dd bs=1M",
        "sudo ls",
        "sudoedit /etc/hosts",
        "/usr/bin/sudo ls",
        "mkfs.ext4 x",
        "wget example.com",
        "rm -rfv /tmp/x",
    ] {
        assert!(
            matches!(run(banned), Err(TripwireError::BannedCommand(_))),
            "{banned} should be refused"
        );
    }
}

fn tw(root: &Path) -> Tripwire {
    Tripwire::new(vec![root.to_path_buf()], vec![], vec![], 0, true)
}

fn write(path: &Path) -> ProposedIntent {
    ProposedIntent {
        action: "write_file".into(),
        params: serde_json::json!({ "path": path.to_string_lossy() }),
        justification: String::new(),
        reasoning: String::new(),
    }
}

#[test]
fn a_write_inside_the_workspace_is_allowed_even_to_a_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("src")).unwrap();
    assert!(tw(&root).validate(&write(&root.join("src/new.rs"))).is_ok());
}

#[test]
fn a_write_may_create_directories_inside_the_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    assert!(tw(&root).validate(&write(&root.join("a/b/c.rs"))).is_ok());
    // ...but not outside it, and not by climbing out.
    let other = tempfile::tempdir().unwrap();
    let outside = other.path().canonicalize().unwrap().join("a/b.rs");
    assert!(matches!(
        tw(&root).validate(&write(&outside)),
        Err(TripwireError::SymlinkEscape(_) | TripwireError::PathNotAllowed(_))
    ));
    // As a client sends it: on Windows `canonicalize` adds `\\?\`, under
    // which `/` is not a separator and `..` would hide inside one name.
    let plain = root.display().to_string();
    let plain = plain.strip_prefix(r"\\?\").unwrap_or(&plain);
    let climb = Path::new(plain)
        .join("a")
        .join("..")
        .join("..")
        .join("x.rs");
    assert!(matches!(
        tw(&root).validate(&write(&climb)),
        Err(TripwireError::PathTraversal(_))
    ));
    // The verbatim form with `/` is refused too, if not as a traversal.
    #[cfg(windows)]
    assert!(
        tw(&root)
            .validate(&write(Path::new(&format!(
                "{}/a/../../x.rs",
                root.display()
            ))))
            .is_err()
    );
    // A new directory does not hide a protected target.
    assert!(matches!(
        tw(&root).validate(&write(&root.join(".claude/settings.json"))),
        Err(TripwireError::ProtectedPath(_))
    ));
}

#[cfg(unix)]
#[test]
fn a_symlinked_directory_cannot_carry_a_write_out() {
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::os::unix::fs::symlink(other.path(), root.join("link")).unwrap();
    assert!(
        tw(&root)
            .validate(&write(&root.join("link/new/x.rs")))
            .is_err()
    );
}

#[test]
fn a_write_outside_the_workspace_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let outside = other.path().canonicalize().unwrap().join("x.txt");
    assert!(matches!(
        tw(&root).validate(&write(&outside)),
        Err(TripwireError::PathNotAllowed(_))
    ));
}

#[test]
fn the_agents_own_hook_configuration_is_protected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    for sub in [
        ".claude",
        ".codex",
        ".agents",
        ".gemini/config",
        ".git/hooks",
        ".ssh",
    ] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    for target in [
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".codex/hooks.json",
        ".codex/config.toml",
        ".agents/hooks.json",
        ".gemini/config/hooks.json",
        ".git/hooks/pre-commit",
        ".ssh/authorized_keys",
    ] {
        assert!(
            matches!(
                tw(&root).validate(&write(&root.join(target))),
                Err(TripwireError::ProtectedPath(_))
            ),
            "{target}"
        );
    }
    // A file that merely sits beside them is fine.
    assert!(
        tw(&root)
            .validate(&write(&root.join(".claude/notes.md")))
            .is_ok()
    );
    assert!(
        tw(&root)
            .validate(&write(&root.join(".codex/notes.md")))
            .is_ok()
    );
    // Only Antigravity's own config folder: any other config/hooks.json is a
    // project file.
    std::fs::create_dir_all(root.join("config")).unwrap();
    assert!(
        tw(&root)
            .validate(&write(&root.join("config/hooks.json")))
            .is_ok()
    );
}
