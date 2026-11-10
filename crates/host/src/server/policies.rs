//! Policy pack listing and editing.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;

pub(crate) const BUILTIN_POLICIES: &[(&str, &str)] = &[
    ("soc2-audit", include_str!("../../policies/soc2-audit.toml")),
    (
        "pci-dss-audit",
        include_str!("../../policies/pci-dss-audit.toml"),
    ),
    (
        "owasp-top10",
        include_str!("../../policies/owasp-top10.toml"),
    ),
    ("iso42001", include_str!("../../policies/iso42001.toml")),
];

/// Policy names are file stems: no path separators, no `..`.
fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains("..") && !name.contains('/') && !name.contains('\\')
}

/// The policy named in Settings (`active_policy`), read now so an edit applies
/// to the next run: a built-in pack, or `<policies_dir>/<name>.toml`.
pub(crate) fn load_named(name: &str) -> Result<crate::policy::LoadedPolicy, String> {
    let name = name.trim();
    if !valid_name(name) {
        return Err(format!("'{name}' is not a policy name"));
    }
    let (text, origin) = match BUILTIN_POLICIES.iter().find(|(n, _)| *n == name) {
        Some((_, content)) => (
            content.to_string(),
            std::path::PathBuf::from(format!("builtin:{name}")),
        ),
        None => {
            let path = config::policies_dir().join(format!("{name}.toml"));
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("policy '{name}' ({}): {e}", path.display()))?;
            (text, path)
        }
    };
    let loaded = crate::policy::loaded_policy_from_text(&text, origin)
        .map_err(|e| format!("policy '{name}' does not load: {e}"))?;
    // A run records the hash of the policy it ran under; one with no rules
    // would claim a baseline that checked nothing (the ISO 42001 pack is a
    // controls mapping, not rules).
    let parsed: crate::policy::AuditPolicy =
        toml::from_str(&text).map_err(|e| format!("policy '{name}' does not load: {e}"))?;
    if !parsed.has_enforceable_rules() {
        return Err(format!(
            "policy '{name}' has no rules to check actions against, so it cannot be used for runs"
        ));
    }
    Ok(loaded)
}

pub(crate) async fn list_policies() -> axum::Json<Vec<String>> {
    let mut names: Vec<String> = BUILTIN_POLICIES
        .iter()
        .map(|(n, _)| n.to_string())
        .collect();
    let dir = config::policies_dir();
    if dir.exists()
        && let Ok(entries) = std::fs::read_dir(&dir)
    {
        for e in entries.flatten() {
            if e.path().extension().is_some_and(|e| e == "toml")
                && let Some(stem) = e.path().file_stem()
            {
                let name = stem.to_string_lossy().to_string();
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names.sort();
    axum::Json(names)
}

pub(crate) async fn get_policy_content(Path(name): Path<String>) -> Result<String, StatusCode> {
    let name = name.trim();
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some((_, content)) = BUILTIN_POLICIES.iter().find(|(n, _)| *n == name) {
        return Ok(content.to_string());
    }
    let path = config::policies_dir().join(format!("{name}.toml"));
    if path.exists() {
        std::fs::read_to_string(&path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub(crate) async fn save_policy(
    axum::Extension(role): axum::Extension<Role>,
    Path(name): Path<String>,
    body: String,
) -> Result<StatusCode, (StatusCode, String)> {
    let fail = |code: StatusCode, msg: &str| (code, msg.to_string());
    if role != Role::Admin {
        return Err(fail(StatusCode::FORBIDDEN, "Admin role required"));
    }
    let name = name.trim();
    if !valid_name(name) {
        return Err(fail(StatusCode::BAD_REQUEST, "Not a policy name"));
    }
    if BUILTIN_POLICIES.iter().any(|(n, _)| *n == name) {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "Built-in policies are read only; save a copy under a new name",
        ));
    }
    let content = body;
    // Reject a policy the engine cannot load before touching the filesystem:
    // TOML that parses but is not a policy (a list where rules are expected)
    // must be caught here, or it would save fine and then fail every run
    // that uses it.
    if let Err(e) = crate::policy::loaded_policy_from_text(&content, std::path::PathBuf::from(name))
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Not a valid policy: {e}"),
        ));
    }
    let io = |_| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not write the policy file",
        )
    };
    let dir = config::policies_dir();
    std::fs::create_dir_all(&dir).map_err(io)?;
    let target = dir.join(format!("{name}.toml"));
    // Atomic write: write to a sibling temp file then rename into place.
    // This prevents a concurrent save from producing a torn/corrupted file.
    let mut tmp = tempfile::NamedTempFile::new_in(&dir).map_err(io)?;
    std::io::Write::write_all(&mut tmp, content.as_bytes()).map_err(io)?;
    tmp.persist(&target).map_err(|_| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not write the policy file",
        )
    })?;
    Ok(StatusCode::OK)
}

pub(crate) async fn delete_policy(
    axum::Extension(role): axum::Extension<Role>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let name = name.trim();
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    if BUILTIN_POLICIES.iter().any(|(n, _)| *n == name) {
        return Err(StatusCode::FORBIDDEN);
    }
    let path = config::policies_dir().join(format!("{name}.toml"));
    if path.exists() {
        std::fs::remove_file(&path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[cfg(test)]
mod tests {
    use super::BUILTIN_POLICIES;

    /// Every built-in pack loads; the rule packs can be the policy for new
    /// runs, the ISO 42001 controls mapping cannot (it has no rules).
    #[test]
    fn every_builtin_pack_loads_and_the_rule_packs_can_run() {
        for (name, text) in BUILTIN_POLICIES {
            if let Err(e) =
                crate::policy::loaded_policy_from_text(text, std::path::PathBuf::from(*name))
            {
                panic!("{name}: {e}");
            }
            let runnable = super::load_named(name);
            match (*name, runnable) {
                ("iso42001", Err(e)) => assert!(e.contains("no rules"), "{e}"),
                ("iso42001", Ok(_)) => panic!("iso42001 has no rules but can run"),
                (_, Err(e)) => panic!("{name}: {e}"),
                (_, Ok(_)) => {}
            }
        }
    }

    /// The SOC 2 pack does what its comments say.
    #[test]
    fn the_soc2_pack_allows_inspection_and_refuses_scans_and_writes() {
        let p = super::load_named("soc2-audit").unwrap();
        let intent = |action: &str, params: serde_json::Value| crate::intent::ProposedIntent {
            action: action.into(),
            params,
            justification: "test".into(),
            reasoning: "test".into(),
        };
        let cmd = |c: &str| intent("run_command", serde_json::json!({ "command": c }));
        assert!(p.engine.validate_intent(&cmd("ls -la /etc"), 1).is_ok());
        assert!(
            p.engine
                .validate_intent(&cmd("nmap -sV 10.0.0.1"), 1)
                .is_err()
        );
        assert!(p.engine.validate_intent(&cmd("rm -rf /tmp/x"), 1).is_err());
        assert!(p.engine.validate_intent(&cmd("python3 -c 1"), 1).is_err());
        let write = intent(
            "write_file",
            serde_json::json!({ "path": "/tmp/x", "content": "" }),
        );
        assert!(p.engine.validate_intent(&write, 1).is_err());
    }

    /// The agent is told which programs it may run: the host's allowlist
    /// narrowed by the pack, and on every host at least one listing command.
    #[test]
    fn the_prompt_names_runnable_programs_for_each_rule_pack() {
        for name in ["soc2-audit", "pci-dss-audit", "owasp-top10"] {
            let p = super::load_named(name).unwrap();
            let programs = crate::executor::programs_for_prompt(Some(&p.engine));
            let lister = if cfg!(windows) { "dir" } else { "ls" };
            assert!(programs.iter().any(|x| x == lister), "{name}: {programs:?}");
            assert!(
                !programs.iter().any(|x| x == "nmap"),
                "{name}: {programs:?}"
            );
        }
    }

    /// The short form means the same as the tables.
    #[test]
    fn a_bare_action_name_is_the_table_with_that_action() {
        let short: crate::policy::AuditPolicy =
            toml::from_str("forbidden_actions = [\"http_get\"]\nallowed_actions = [\"read_file\"]")
                .unwrap();
        let long: crate::policy::AuditPolicy = toml::from_str(
            "[[forbidden_actions]]\naction = \"http_get\"\n[[allowed_actions]]\naction = \"read_file\"",
        )
        .unwrap();
        assert_eq!(
            format!("{:?}{:?}", short.forbidden_actions, short.allowed_actions),
            format!("{:?}{:?}", long.forbidden_actions, long.allowed_actions)
        );
    }
}
