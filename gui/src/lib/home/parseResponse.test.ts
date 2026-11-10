import { describe, it, expect } from "vitest";
import { parseResponse } from "./parseResponse";

describe("parseResponse", () => {
  it("passes a string straight through", () => {
    expect(parseResponse("hello")).toBe("hello");
  });

  it("is blank for null/undefined", () => {
    expect(parseResponse(null)).toBe("");
    expect(parseResponse(undefined)).toBe("");
  });

  it("pretty-prints an array", () => {
    expect(parseResponse([1, 2])).toBe(JSON.stringify([1, 2], null, 2));
  });

  it("stringifies a non-object primitive", () => {
    expect(parseResponse(42)).toBe("42");
  });

  it("prefers the first matching schema field, in priority order", () => {
    expect(parseResponse({ thought: "T", message: "M" })).toBe("T");
    expect(parseResponse({ message: "M", content: "C" })).toBe("M");
  });

  it("skips an empty-string schema field for the next one", () => {
    expect(parseResponse({ justification: "", observation: "O" })).toBe("O");
  });

  it("summarises a session-creation response with its id", () => {
    const text = parseResponse({ goal: "Audit it", status: "running", id: "abcdef1234567890" });
    expect(text).toBe("Session started.\nGoal: Audit it\nStatus: running\nSession ID: abcdef12…");
  });

  it("summarises a session-creation response without an id", () => {
    const text = parseResponse({ goal: "Audit it", status: "running" });
    expect(text).toBe("Session started.\nGoal: Audit it\nStatus: running");
  });

  it("falls back to key: value lines for scalar-only objects", () => {
    const text = parseResponse({ count: 3, ok: true });
    expect(text).toBe("count: 3\nok: true");
  });

  it("falls back to pretty JSON when nothing else matches", () => {
    const obj = { nested: { a: 1 } };
    expect(parseResponse(obj)).toBe(JSON.stringify(obj, null, 2));
  });
});
