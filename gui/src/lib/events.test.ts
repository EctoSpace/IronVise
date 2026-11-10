import { describe, it, expect } from "vitest";
import { describeEvent, formatEventType, isRefusal, parsePayload } from "./events";

describe("parsePayload", () => {
  it("parses a JSON-encoded string payload into an object", () => {
    expect(parsePayload('{"type":"genesis","message":"hi"}')).toEqual({
      type: "genesis",
      message: "hi",
    });
  });

  it("wraps a malformed JSON string as an unknown payload carrying the raw text", () => {
    expect(parsePayload("not json")).toEqual({ type: "unknown", content: "not json" });
  });

  it("wraps a JSON array string as unknown (arrays are not payload objects)", () => {
    expect(parsePayload("[1,2,3]")).toEqual({ type: "unknown", content: "[1,2,3]" });
  });

  it("passes a plain object payload through unchanged", () => {
    const obj = { type: "action", name: "run" };
    expect(parsePayload(obj)).toBe(obj);
  });

  it("wraps non-object, non-string payloads as unknown", () => {
    expect(parsePayload(42)).toEqual({ type: "unknown", content: "42" });
    expect(parsePayload(null)).toEqual({ type: "unknown", content: "null" });
  });
});

describe("formatEventType", () => {
  it("replaces underscores with spaces and title-cases each word", () => {
    expect(formatEventType("guard_denial")).toBe("Guard Denial");
    expect(formatEventType("tripwire_rejection")).toBe("Tripwire Rejection");
  });
});

describe("isRefusal", () => {
  it("is true only for the blocked tone", () => {
    expect(isRefusal({ type: "x", label: "x", text: "x", tone: "blocked" })).toBe(true);
    expect(isRefusal({ type: "x", label: "x", text: "x", tone: "warning" })).toBe(false);
  });
});

describe("describeEvent", () => {
  it("renders genesis with its message", () => {
    const v = describeEvent({ type: "genesis", message: "Ledger initialised." });
    expect(v).toEqual({ type: "genesis", label: "Ledger opened", text: "Ledger initialised.", tone: "neutral" });
  });

  it("falls back to a default message when genesis has none", () => {
    const v = describeEvent({ type: "genesis" });
    expect(v.text).toBe("Ledger initialised.");
  });

  it("renders prompt_input as the Goal", () => {
    const v = describeEvent({ type: "prompt_input", content: "audit this repo" });
    expect(v).toEqual({ type: "prompt_input", label: "Goal", text: "audit this repo", tone: "info" });
  });

  it("renders a plain thought as info", () => {
    const v = describeEvent({ type: "thought", content: "considering next step" });
    expect(v.label).toBe("Thought");
    expect(v.tone).toBe("info");
  });

  it("recognises a legacy prose refusal embedded in a thought", () => {
    const v = describeEvent({ type: "thought", content: "Guard denied: rm -rf /" });
    expect(v.label).toBe("Refused");
    expect(v.tone).toBe("blocked");
  });

  it("recognises every legacy refusal prefix variant", () => {
    for (const prefix of ["Guard denied:", "Tripwire rejected:", "Policy rejected:", "Security:"]) {
      const v = describeEvent({ type: "thought", content: `${prefix} something` });
      expect(v.tone).toBe("blocked");
    }
  });

  it("recognises a schema-error thought", () => {
    const v = describeEvent({ type: "thought", content: "SCHEMA ERROR: bad field" });
    expect(v.label).toBe("Invalid model output");
    expect(v.tone).toBe("error");
  });

  it("renders schema_error with attempt counters", () => {
    const v = describeEvent({ type: "schema_error", attempt: 2, max_attempts: 3, message: "missing field" });
    expect(v.text).toBe("Attempt 2 of 3: missing field");
    expect(v.tone).toBe("error");
  });

  it("renders circuit_breaker with the failure count", () => {
    const v = describeEvent({ type: "circuit_breaker", reason: "too many errors", consecutive_failures: 5 });
    expect(v.text).toBe("too many errors (5 consecutive failures)");
  });

  it("renders a completed action with findings", () => {
    const v = describeEvent({
      type: "action",
      name: "complete",
      params: { findings: [{ title: "SQL injection" }, { title: "XSS" }] },
    });
    expect(v.label).toBe("Finished");
    expect(v.text).toBe("2 findings: SQL injection, XSS");
    expect(v.tone).toBe("success");
  });

  it("uses singular 'finding' for exactly one", () => {
    const v = describeEvent({ type: "action", name: "complete", params: { findings: [{ title: "XSS" }] } });
    expect(v.text).toBe("1 finding: XSS");
  });

  it("renders a completed action with no findings array as a plain success", () => {
    const v = describeEvent({ type: "action", name: "complete", params: {} });
    expect(v.text).toBe("Agent finished.");
  });

  it("renders a non-complete action with its first recognised param as the target", () => {
    const v = describeEvent({ type: "action", name: "run_command", params: { command: "ls -la" } });
    expect(v.text).toBe("run_command: ls -la");
    expect(v.tone).toBe("action");
  });

  it("falls back to a JSON dump of the params when none match a known target key", () => {
    const v = describeEvent({ type: "action", name: "noop", params: { other: 1 } });
    expect(v.text).toBe(`noop: ${JSON.stringify({ other: 1 }, null, 2)}`);
  });

  it("falls back to the raw name when an action has no params at all", () => {
    const v = describeEvent({ type: "action", name: "noop" });
    expect(v.text).toBe("noop");
  });

  it("stringifies non-object action params", () => {
    const v = describeEvent({ type: "action", name: "run", params: "literal" });
    expect(v.text).toBe("run: literal");
  });

  it("renders observation content, stringifying non-string content", () => {
    expect(describeEvent({ type: "observation", content: "ok" }).text).toBe("ok");
    expect(describeEvent({ type: "observation", content: { code: 1 } }).text).toBe('{"code":1}');
  });

  it("renders approval_required with and without a params summary", () => {
    expect(describeEvent({ type: "approval_required", action_name: "delete_file" }).text).toBe("delete_file");
    expect(
      describeEvent({ type: "approval_required", action_name: "delete_file", action_params_summary: "foo.txt" })
        .text,
    ).toBe("delete_file: foo.txt");
  });

  it("renders approval_decision as approved or rejected", () => {
    const approved = describeEvent({ type: "approval_decision", approved: true, reason: "looks safe" });
    expect(approved).toMatchObject({ label: "Approved", tone: "success", text: "looks safe" });
    const rejected = describeEvent({ type: "approval_decision", approved: false, reason: "too risky" });
    expect(rejected).toMatchObject({ label: "Rejected by reviewer", tone: "blocked", text: "too risky" });
  });

  it("renders a guard_denial that was enforced as blocked", () => {
    const v = describeEvent({ type: "guard_denial", action: "rm -rf", reason: "banned command" });
    expect(v).toMatchObject({ label: "Blocked by guard", tone: "blocked", text: "rm -rf: banned command" });
  });

  it("renders a guard_denial with enforced: false as a warning, not blocked", () => {
    const v = describeEvent({ type: "guard_denial", action: "rm -rf", reason: "banned command", enforced: false });
    expect(v).toMatchObject({ label: "Flagged by guard, not enforced", tone: "warning" });
  });

  it("renders tripwire_rejection with the known stage label", () => {
    const v = describeEvent({ type: "tripwire_rejection", stage: "prompt_scan", reason: "suspicious prompt" });
    expect(v.label).toBe("Blocked at prompt scan");
    expect(v.text).toBe("Prompt: suspicious prompt");
  });

  it("falls back to the raw stage name when it is not in STAGE_LABELS", () => {
    const v = describeEvent({ type: "tripwire_rejection", stage: "custom_stage", action: "x", reason: "y" });
    expect(v.label).toBe("Blocked at custom_stage");
  });

  it("renders an unenforced tripwire_rejection as a warning", () => {
    const v = describeEvent({ type: "tripwire_rejection", stage: "policy", reason: "flag", enforced: false });
    expect(v.label).toBe("Flagged at policy, not enforced");
    expect(v.tone).toBe("warning");
  });

  it("renders cross_ledger_seal, anchor (confirmed and unconfirmed), key_rotation, key_revocation, and verifiable_credential", () => {
    expect(describeEvent({ type: "cross_ledger_seal", seal_hash: "abcdefabcdefabcdef" }).text).toContain("Seal ab");
    expect(
      describeEvent({ type: "anchor", bitcoin_block_height: 900000, ledger_tip_hash: "deadbeefdeadbeef" }).text,
    ).toContain("Bitcoin block 900000");
    expect(describeEvent({ type: "anchor", ledger_tip_hash: "deadbeefdeadbeef" }).text).toContain(
      "not yet confirmed",
    );
    expect(describeEvent({ type: "key_rotation", rotation_index: 1, new_public_key: "abcdefabcdefabcdef" }).text).toBe(
      "Rotation 1: new key abcdefabcdef…",
    );
    expect(
      describeEvent({ type: "key_revocation", revoked_public_key: "abcdefabcdefabcdef", reason: "compromised" }).text,
    ).toBe("abcdefabcdef…: compromised");
    expect(describeEvent({ type: "verifiable_credential", vc_jwt: "a".repeat(60) }).text).toContain("JWT");
  });

  it("renders data_receipt with hash and byte counts", () => {
    const v = describeEvent({
      type: "data_receipt",
      tool: "read_file",
      source: "main.rs",
      text_sha256: ["aaaaaaaaaaaaaaaaaaaa"],
      text_bytes: 1024,
    });
    expect(v.label).toBe("Data received");
    expect(v.text).toContain("read_file: main.rs");
    expect(v.text).toContain("1 text(s), 1024 bytes");
    expect(v.text).toContain("SHA-256 aaaaaaaaaaaa…");
  });

  it("renders chat_message from the user as 'You' and from a model with backend/model", () => {
    expect(describeEvent({ type: "chat_message", role: "user", content: "hi" })).toMatchObject({
      label: "You",
      tone: "chat",
    });
    expect(
      describeEvent({ type: "chat_message", role: "assistant", backend: "anthropic", model: "claude", content: "hi" }),
    ).toMatchObject({ label: "anthropic / claude" });
  });

  it("falls back to a JSON dump of unrecognised extra fields for an unknown type", () => {
    const v = describeEvent({ type: "something_new", foo: "bar" });
    expect(v.label).toBe("Something New");
    expect(v.text).toBe(JSON.stringify({ foo: "bar" }, null, 2));
    expect(v.tone).toBe("neutral");
  });

  it("treats a missing type as 'unknown'", () => {
    const v = describeEvent({});
    expect(v.type).toBe("unknown");
  });
});
