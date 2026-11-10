use super::*;
use serde_json::json;

fn parts(p: &EventPayload) -> (&str, Option<&str>, &str, &[String], u64) {
    let EventPayload::DataReceipt {
        tool,
        source,
        response_sha256,
        text_sha256,
        text_bytes,
        ..
    } = p
    else {
        panic!("not a receipt: {p:?}");
    };
    (
        tool,
        source.as_deref(),
        response_sha256,
        text_sha256,
        *text_bytes,
    )
}

#[test]
fn a_read_file_is_hashed_as_its_bytes() {
    let content = "db_password=example\n";
    let r = receipt(
        "Read",
        &json!({ "file_path": "/p/config.ini" }),
        &json!({ "type": "text", "file": { "filePath": "/p/config.ini", "content": content, "numLines": 1 } }),
        Some("toolu_1"),
    );
    let (tool, source, _, texts, bytes) = parts(&r);
    assert_eq!((tool, source), ("Read", Some("/p/config.ini")));
    assert_eq!(texts, [sha256_hex(content.as_bytes())]);
    assert_eq!(bytes, content.len() as u64);
    assert!(!serde_json::to_string(&r).unwrap().contains("db_password"));
}

#[test]
fn mcp_blocks_are_hashed_one_by_one_in_both_shapes() {
    let blocks = json!([{ "type": "text", "text": "one" }, { "type": "image", "data": "…" },
                            { "type": "resource", "resource": { "uri": "f", "text": "two" } }]);
    let want = [sha256_hex(b"one"), sha256_hex(b"two")];
    for response in [
        blocks.clone(),
        json!({ "content": blocks, "isError": false }),
    ] {
        let r = receipt(
            "mcp__files__read_text_file",
            &json!({ "path": "/d/a" }),
            &response,
            None,
        );
        let (tool, source, _, texts, _) = parts(&r);
        assert_eq!((tool, source), ("mcp:files/read_text_file", Some("/d/a")));
        assert_eq!(texts, want);
    }
}

#[test]
fn command_output_and_plain_strings_are_hashed() {
    let r = receipt(
        "Bash",
        &json!({ "command": "ls" }),
        &json!({ "stdout": "a\nb\n", "stderr": "", "interrupted": false }),
        None,
    );
    assert_eq!(parts(&r).3, [sha256_hex(b"a\nb\n")]);
    let r = receipt(
        "WebFetch",
        &json!({ "url": "https://x" }),
        &json!("page"),
        None,
    );
    assert_eq!(parts(&r).3, [sha256_hex(b"page")]);
}

#[test]
fn a_well_formed_receipt_is_accepted_and_bound_to_its_tool_use() {
    let made = receipt(
        "Read",
        &json!({ "file_path": "/p/a" }),
        &json!({ "file": { "content": "x" } }),
        Some("client-chose-this"),
    );
    let EventPayload::DataReceipt { call_id, .. } = accept(made.clone(), Some("toolu_9")).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(call_id.as_deref(), Some("toolu_9"));
    let EventPayload::DataReceipt { call_id, .. } = accept(made, None).unwrap() else {
        unreachable!()
    };
    assert_eq!(call_id, None);
}

/// A receipt with these fields, as a client might send it.
fn claim(
    tool: &str,
    source: Option<String>,
    response: &str,
    texts: &[&str],
    bytes: u64,
) -> EventPayload {
    EventPayload::DataReceipt {
        tool: tool.into(),
        source,
        call_id: None,
        response_sha256: response.into(),
        text_sha256: texts.iter().map(|t| t.to_string()).collect(),
        text_bytes: bytes,
    }
}

#[test]
fn a_receipt_that_is_not_hashes_is_refused() {
    let h = sha256_hex(b"x");
    let ok = |p| accept(p, None).is_ok();
    assert!(ok(claim("Read", None, &h, &[&h], 1)));
    assert!(ok(claim("Read", Some("s".repeat(MAX_SOURCE)), &h, &[], 0)));
    // The data itself where a hash belongs.
    assert!(!ok(claim("Read", None, &h, &["db_password=example"], 1)));
    assert!(!ok(claim("Read", None, "db_password=example", &[], 0)));
    // Uppercase, short, and non-hex digests.
    assert!(!ok(claim("Read", None, &h.to_uppercase(), &[], 0)));
    assert!(!ok(claim("Read", None, &h[..63], &[], 0)));
    assert!(!ok(claim("Read", None, &h, &[&format!("g{}", &h[1..])], 1)));
    // No tool, or names too long to be names.
    assert!(!ok(claim(" ", None, &h, &[], 0)));
    assert!(ok(claim(&"t".repeat(MAX_TOOL), None, &h, &[], 0)));
    assert!(!ok(claim(&"t".repeat(MAX_TOOL + 1), None, &h, &[], 0)));
    assert!(!ok(claim(
        "Read",
        Some("s".repeat(MAX_SOURCE + 1)),
        &h,
        &[],
        0
    )));
    // Bytes counted for texts it does not list.
    assert!(!ok(claim("Read", None, &h, &[], 7)));
    // Not a receipt at all.
    assert!(!ok(EventPayload::Thought {
        content: "hi".into()
    }));
}

#[test]
fn the_response_hash_does_not_depend_on_key_order() {
    let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3}}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"a":{"x":3,"y":2},"b":1}"#).unwrap();
    let hash = |v| parts(&receipt("T", &json!({}), &v, None)).2.to_string();
    assert_eq!(hash(a), hash(b));
    assert_eq!(
        hash(json!({ "a": 1 })),
        sha256_hex(br#"{"a":1}"#),
        "canonical JSON, compact"
    );
}
