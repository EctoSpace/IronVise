use std::collections::BTreeSet;

/// Repo root, from this crate's manifest directory.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

fn to_snake(ident: &str) -> String {
    let mut out = String::new();
    for (i, ch) in ident.char_indices() {
        if ch.is_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Variant names of a `#[serde(rename_all = "snake_case")]` enum, read out of
/// the source text. Parsing the source keeps this honest: a derive macro or a
/// hand-maintained constant would drift in exactly the way being guarded
/// against.
fn variants_of(source: &str, decl: &str) -> BTreeSet<String> {
    let start = source
        .find(decl)
        .unwrap_or_else(|| panic!("{decl} not found"));
    let body = &source[start..];
    let end = body.find("\n}").expect("end of enum");
    body[..end]
        .lines()
        .skip(1)
        .filter_map(|line| {
            // Variants sit at exactly one level of indentation; their fields
            // are deeper, and comments and attributes are skipped.
            let stripped = line.strip_prefix("    ")?;
            if stripped.starts_with(char::is_whitespace) {
                return None;
            }
            let ident: String = stripped
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let first = ident.chars().next()?;
            first.is_uppercase().then(|| to_snake(&ident))
        })
        .collect()
}

fn event_kinds() -> BTreeSet<String> {
    variants_of(include_str!("../schema.rs"), "pub enum EventPayload {")
}

fn egress_kinds() -> BTreeSet<String> {
    // Read the string literals rather than the variant names: the literals
    // are what the server compares `filter_kinds` against.
    read("crates/host/src/webhook.rs")
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("EgressKind::")?;
            let lit = rest.split('"').nth(1)?;
            Some(lit.to_string())
        })
        .collect()
}

/// The desktop app gives every kind its own view, not the raw-JSON
/// fallback; its views once drifted behind the schema.
#[test]
fn the_desktop_app_describes_every_event_kind() {
    let gui = read("gui/src/lib/events.ts");
    let missing: Vec<String> = event_kinds()
        .into_iter()
        .filter(|k| !gui.contains(&format!("case \"{k}\"")))
        .collect();
    assert!(
        missing.is_empty(),
        "no view in gui/src/lib/events.ts for {missing:?}"
    );
}

/// Kinds listed between the markers in docs/reference/schema.md.
fn documented_kinds() -> BTreeSet<String> {
    let md = read("docs/reference/schema.md");
    let start = md
        .find("<!-- BEGIN:event-kinds -->")
        .expect("BEGIN:event-kinds marker missing from docs/reference/schema.md");
    let end = md
        .find("<!-- END:event-kinds -->")
        .expect("END:event-kinds marker missing from docs/reference/schema.md");
    md[start..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let row = l.strip_prefix("| `")?;
            Some(row.split('`').next()?.to_string())
        })
        .collect()
}

/// Kinds offered by the GUI's webhook filter picker.
fn gui_filter_kinds() -> BTreeSet<String> {
    let src = read("gui/src/lib/WebhooksView.svelte");
    let start = src.find("const ALL_KINDS").expect("ALL_KINDS missing");
    let body = &src[start..];
    let end = body.find("];").expect("end of ALL_KINDS");
    body[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

#[test]
fn sanity_the_source_parses() {
    let kinds = event_kinds();
    assert!(
        kinds.contains("genesis") && kinds.contains("guard_denial"),
        "variant parsing produced nothing usable: {kinds:?}"
    );
    assert!(
        egress_kinds().contains("guard_denial"),
        "egress-kind parsing produced nothing usable"
    );
}

#[test]
fn docs_event_kinds_match_enum() {
    let from_code = event_kinds();
    let from_docs = documented_kinds();
    assert_eq!(
        from_code,
        from_docs,
        "\ndocs/reference/schema.md is out of sync with EventPayload.\
             \n  in code but undocumented: {:?}\
             \n  documented but not in code: {:?}\
             \nUpdate the table between the BEGIN/END:event-kinds markers.",
        from_code.difference(&from_docs).collect::<Vec<_>>(),
        from_docs.difference(&from_code).collect::<Vec<_>>(),
    );
}

#[test]
fn gui_webhook_filters_match_egress_kinds() {
    let from_code = egress_kinds();
    let from_gui = gui_filter_kinds();
    assert_eq!(
        from_code,
        from_gui,
        "\ngui/src/lib/WebhooksView.svelte offers filter kinds the server never emits.\
             \nThe server does an exact string match, so a name not in EgressKind\
             \nsilently forwards nothing.\
             \n  emitted but not offered: {:?}\
             \n  offered but never emitted: {:?}",
        from_code.difference(&from_gui).collect::<Vec<_>>(),
        from_gui.difference(&from_code).collect::<Vec<_>>(),
    );
}

#[test]
fn every_egress_kind_is_also_an_event_kind_or_deliberately_not() {
    // `observation`, `guard_denial` and `tripwire_rejection` are all ledger
    // event kinds too. That is not required, but if it stops being true the
    // overlap should be a decision rather than an accident.
    let events = event_kinds();
    let unmatched: Vec<_> = egress_kinds()
        .into_iter()
        .filter(|k| !events.contains(k))
        .collect();
    assert!(
        unmatched.is_empty(),
        "egress kinds with no corresponding event kind: {unmatched:?}"
    );
}
