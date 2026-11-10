//! The policy shown in the desktop app's screenshots and demo videos comes from
//! `gui/tests/visual/tauri-mock.ts`. It must be a policy the engine actually
//! parses and enforces, or the published media would advertise a format that
//! checks nothing.

#[test]
fn the_policy_in_the_published_screenshots_is_enforceable() {
    let mock = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../gui/tests/visual/tauri-mock.ts"
    ))
    .expect("gui/tests/visual/tauri-mock.ts");
    let start = mock
        .find("const POLICY_TOML = `")
        .expect("POLICY_TOML in tauri-mock.ts")
        + "const POLICY_TOML = `".len();
    let end = start + mock[start..].find('`').expect("closing backtick");
    let policy: ectoledger_core::policy::AuditPolicy =
        toml::from_str(&mock[start..end]).expect("POLICY_TOML parses as an AuditPolicy");
    assert!(
        policy.has_enforceable_rules(),
        "POLICY_TOML enforces nothing"
    );
    assert!(!policy.command_rules.is_empty());
}
