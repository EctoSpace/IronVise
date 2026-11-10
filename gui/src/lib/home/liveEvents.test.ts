import { describe, it, expect } from "vitest";
import { parseLiveEventItem } from "./liveEvents";

describe("parseLiveEventItem", () => {
  it("returns null for a non-object", () => {
    expect(parseLiveEventItem(null)).toBeNull();
    expect(parseLiveEventItem("x")).toBeNull();
  });

  it("returns null when the payload is missing", () => {
    expect(parseLiveEventItem({})).toBeNull();
  });

  it("returns null for an unparsable string payload", () => {
    expect(parseLiveEventItem({ payload: "not json" })).toBeNull();
  });

  it("parses a JSON-string payload", () => {
    const ev = parseLiveEventItem({ payload: JSON.stringify({ type: "thought", content: "Thinking" }) });
    expect(ev).toEqual({ typeLabel: "Thought", content: "Thinking", isError: false, isComplete: false, colorHint: null });
  });

  it("flags a completed 'complete' action, with no colour hint (success is the default feed colour)", () => {
    const ev = parseLiveEventItem({ payload: { type: "action", name: "complete" } });
    expect(ev?.isComplete).toBe(true);
    expect(ev?.colorHint).toBeNull();
  });

  it("colours a non-complete action", () => {
    const ev = parseLiveEventItem({ payload: { type: "action", name: "run_command", params: { command: "ls" } } });
    expect(ev?.isComplete).toBe(false);
    expect(ev?.colorHint).toBe("action");
  });

  it("flags a guard denial as an error with the tripwire colour", () => {
    const ev = parseLiveEventItem({ payload: { type: "guard_denial", action: "run_command", reason: "no" } });
    expect(ev?.isError).toBe(true);
    expect(ev?.colorHint).toBe("tripwire");
  });

  it("colours a chat message without marking it an error", () => {
    const ev = parseLiveEventItem({ payload: { type: "chat_message", role: "user", content: "hi" } });
    expect(ev?.isError).toBe(false);
    expect(ev?.colorHint).toBe("chat");
  });
});
