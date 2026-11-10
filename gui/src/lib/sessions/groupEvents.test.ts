import { describe, it, expect } from "vitest";
import { groupEvents, rawPayloadJson } from "./groupEvents";

describe("groupEvents", () => {
  it("keeps distinct events separate", () => {
    const groups = groupEvents([
      { sequence: 1, payload: { type: "prompt_input", content: "Do X" }, created_at: "t1" },
      { sequence: 2, payload: { type: "thought", content: "Thinking" }, created_at: "t2" },
    ]);
    expect(groups).toHaveLength(2);
    expect(groups[0].count).toBe(1);
  });

  it("folds repeated events with the same label and body into one, counting occurrences", () => {
    const groups = groupEvents([
      { sequence: 1, payload: { type: "action", name: "run_command", params: { command: "ls" } }, created_at: "t1" },
      { sequence: 2, payload: { type: "action", name: "run_command", params: { command: "ls" } }, created_at: "t2" },
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].count).toBe(2);
    expect(groups[0].occurrences.map((o) => o.seq)).toEqual([1, 2]);
  });

  it("carries the tone from describeEvent", () => {
    const [group] = groupEvents([
      { sequence: 1, payload: { type: "guard_denial", action: "run_command", reason: "blocked" }, created_at: "t1" },
    ]);
    expect(group.tone).toBe("blocked");
  });

  it("defaults the occurrence type to 'event' when the payload has none", () => {
    const [group] = groupEvents([{ sequence: 1, payload: "not an object", created_at: "t1" }]);
    expect(group.occurrences[0].type).toBe("event");
  });
});

describe("rawPayloadJson", () => {
  it("pretty-prints a JSON-string payload", () => {
    const json = rawPayloadJson({ payload: '{"a":1}' });
    expect(json).toBe(JSON.stringify({ a: 1 }, null, 2));
  });

  it("falls back to the raw string when it does not parse", () => {
    expect(rawPayloadJson({ payload: "not json" })).toBe("not json");
  });

  it("pretty-prints an object payload", () => {
    const json = rawPayloadJson({ payload: { a: 1 } });
    expect(json).toBe(JSON.stringify({ a: 1 }, null, 2));
  });

  it("falls back to the whole event when payload is missing", () => {
    const ev = { sequence: 1 };
    expect(rawPayloadJson(ev)).toBe(JSON.stringify(ev, null, 2));
  });
});
