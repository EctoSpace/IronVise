import { describe, it, expect } from "vitest";
import { normaliseEvents, toEventRow, getFindings, filterSessions, shortHash, fmtTime, sevClass } from "./eventRows";
import type { SessionSummary } from "../backend";

describe("toEventRow / normaliseEvents", () => {
  it("parses a JSON-string payload", () => {
    const [row] = normaliseEvents([
      { sequence: 1, previous_hash: "a", content_hash: "b", payload: '{"type":"thought"}', created_at: "t" },
    ]);
    expect(row.payload).toEqual({ type: "thought" });
  });

  it("keeps an unparsable string payload as-is rather than discarding it", () => {
    const [row] = normaliseEvents([{ sequence: 1, payload: "not json" }]);
    expect(row.payload).toBe("not json");
  });

  it("passes an object payload through unchanged", () => {
    const [row] = normaliseEvents([{ sequence: 1, payload: { type: "action" } }]);
    expect(row.payload).toEqual({ type: "action" });
  });

  it("defaults missing fields", () => {
    const [row] = normaliseEvents([{}]);
    expect(row).toMatchObject({ sequence: 0, previous_hash: "", content_hash: "", created_at: "" });
  });

  it("returns no rows for a non-array answer", () => {
    expect(normaliseEvents(null)).toEqual([]);
    expect(normaliseEvents({ not: "an array" })).toEqual([]);
  });

  it("falls back to the given created_at when the row has none (the SSE path)", () => {
    const row = toEventRow({ sequence: 2 }, "2026-01-01T00:00:00Z");
    expect(row.created_at).toBe("2026-01-01T00:00:00Z");
  });
});

describe("getFindings", () => {
  it("extracts findings from a complete action", () => {
    const findings = getFindings({
      sequence: 1,
      previous_hash: "",
      content_hash: "",
      created_at: "",
      payload: { type: "action", name: "complete", params: { findings: [{ title: "X" }] } },
    });
    expect(findings).toEqual([{ title: "X" }]);
  });

  it("returns null for a non-complete action", () => {
    const findings = getFindings({
      sequence: 1,
      previous_hash: "",
      content_hash: "",
      created_at: "",
      payload: { type: "action", name: "run_command" },
    });
    expect(findings).toBeNull();
  });

  it("returns null when complete has no findings array", () => {
    const findings = getFindings({
      sequence: 1,
      previous_hash: "",
      content_hash: "",
      created_at: "",
      payload: { type: "action", name: "complete", params: {} },
    });
    expect(findings).toBeNull();
  });
});

describe("filterSessions", () => {
  const sessions: SessionSummary[] = [
    { id: "aaa111", goal: "Audit server config", status: "completed", created_at: "", finished_at: null },
    { id: "bbb222", goal: "Review network policy", status: "completed", created_at: "", finished_at: null },
  ];

  it("returns every session for a blank query", () => {
    expect(filterSessions(sessions, "  ")).toEqual(sessions);
  });

  it("matches by goal, case-insensitively", () => {
    expect(filterSessions(sessions, "SERVER")).toEqual([sessions[0]]);
  });

  it("matches by id", () => {
    expect(filterSessions(sessions, "bbb")).toEqual([sessions[1]]);
  });

  it("matches nothing when nothing fits", () => {
    expect(filterSessions(sessions, "zzz")).toEqual([]);
  });
});

describe("shortHash / fmtTime / sevClass", () => {
  it("shortens a hash to 8 characters", () => {
    expect(shortHash("abcdef1234567890")).toBe("abcdef12");
  });

  it("renders a dash for a missing hash", () => {
    expect(shortHash(undefined)).toBe("-");
    expect(shortHash("")).toBe("-");
  });

  it("falls back to the raw string on an unparsable timestamp", () => {
    expect(fmtTime("not-a-date")).toBe("Invalid Date");
  });

  it("classes severities by colour and weight", () => {
    expect(sevClass("critical")).toContain("font-bold");
    expect(sevClass("HIGH")).toContain("font-semibold");
    // High and medium differ in colour, not only weight.
    expect(sevClass("high")).toContain("text-caution");
    expect(sevClass("medium")).toBe("text-warning");
    expect(sevClass("low")).toBe("text-text-secondary");
  });
});
