//! `docs/guides/cli.md` documents every subcommand `--help` lists, with each long
//! flag (nested subcommands included) inside that subcommand's own section.
//! A new command or flag without documentation fails here.

use std::collections::BTreeSet;
use std::process::Command;

fn help(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_ironvise"))
        .args(args)
        .arg("--help")
        .output()
        .expect("run ectoledger --help");
    assert!(out.status.success(), "{args:?} --help failed");
    String::from_utf8(out.stdout).expect("utf-8 help")
}

fn subcommands(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| l.starts_with(' '))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|c| *c != "help")
        .map(String::from)
        .collect()
}

/// Long flags from the option lines (`  -o, --output <OUTPUT>`), not from
/// descriptions that happen to mention another flag.
fn long_flags(help: &str) -> BTreeSet<String> {
    help.lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with('-'))
        .filter_map(|l| l.split([' ', ',']).find(|t| t.starts_with("--")))
        .filter(|f| *f != "--help" && *f != "--version")
        .map(String::from)
        .collect()
}

fn section<'a>(doc: &'a str, command: &str) -> Option<&'a str> {
    let heading = format!("### `{command}`");
    let start = doc.find(&heading)?;
    let body = &doc[start + heading.len()..];
    Some(body.find("\n### ").map_or(body, |end| &body[..end]))
}

#[test]
fn every_subcommand_and_flag_is_documented_in_its_section() {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/guides/cli.md"
    ))
    .expect("docs/guides/cli.md");
    let commands = subcommands(&help(&[]));
    assert!(
        commands.len() >= 15,
        "parsed too few commands: {commands:?}"
    );
    let mut missing = Vec::new();
    for command in &commands {
        let Some(text) = section(&doc, command) else {
            missing.push(format!("no `### \\`{command}\\`` section"));
            continue;
        };
        let top = help(&[command]);
        let mut flags = long_flags(&top);
        for nested in subcommands(&top) {
            flags.extend(long_flags(&help(&[command, &nested])));
        }
        missing.extend(
            flags
                .iter()
                .filter(|f| !text.contains(f.as_str()))
                .map(|f| format!("{command}: {f}")),
        );
    }
    assert!(
        missing.is_empty(),
        "undocumented in docs/guides/cli.md: {missing:#?}"
    );
}

/// Every relative link in the published Markdown (README, CHANGELOG, docs,
/// examples, SDK READMEs) points at a file that exists. Code blocks are
/// skipped. The maintainer directory is not part of the published doc set.
#[test]
fn relative_links_in_published_docs_resolve() {
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let mut files = vec![root.join("README.md"), root.join("CHANGELOG.md")];
    for dir in ["docs", "examples", "sdk"] {
        collect_markdown(&root.join(dir), &mut files);
    }
    let mut broken = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read markdown");
        let prose: String = text.split("```").step_by(2).collect::<Vec<_>>().join("\n");
        for target in prose
            .split("](")
            .skip(1)
            .filter_map(|rest| rest.split(')').next())
        {
            let path = target.split('#').next().unwrap_or_default();
            if path.is_empty()
                || path.contains("://")
                || path.starts_with("mailto:")
                || path.contains(' ')
            {
                continue;
            }
            if !file.parent().expect("parent").join(path).exists() {
                broken.push(format!(
                    "{} -> {target}",
                    file.strip_prefix(root).unwrap_or(file).display()
                ));
            }
        }
    }
    assert!(
        files.len() > 20,
        "found too few Markdown files: {}",
        files.len()
    );
    assert!(broken.is_empty(), "broken links: {broken:#?}");
}

/// The settings people copy (the docs, the desktop app's Connect panel) name
/// the same tools as `hook install`. They once left out `mcp__.*`, so a
/// copied snippet checked none of Claude Code's MCP tool calls.
#[test]
fn copied_hook_settings_match_what_hook_install_writes() {
    let want = format!("\"matcher\": \"{}\"", ectoledger::server::hook_matcher());
    for file in [
        "docs/guides/integrations.md",
        "gui/src/lib/ConnectClaudeCode.svelte",
    ] {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../").to_string() + file;
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains(&want), "{file} does not contain {want}");
    }
}

fn collect_markdown(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for path in entries.filter_map(|e| e.ok().map(|e| e.path())) {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if !matches!(name, "doNotPublish" | "node_modules" | "dist" | ".venv") {
                collect_markdown(&path, out);
            }
        } else if name.ends_with(".md") {
            out.push(path);
        }
    }
}
