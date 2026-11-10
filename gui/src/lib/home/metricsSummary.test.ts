import { describe, it, expect } from "vitest";
import { summarizeMetrics } from "./metricsSummary";

describe("summarizeMetrics", () => {
  it("is null without metrics", () => {
    expect(summarizeMetrics(null)).toBeNull();
  });

  it("sums guard denials and tripwire rejections into one denials count", () => {
    const s = summarizeMetrics({ total_sessions: 3, guard_denials: 2, tripwire_rejections: 1, total_events: 40 });
    expect(s).toEqual({ sessions: 3, denials: 3, events: 40 });
  });

  it("treats a missing or non-numeric field as zero", () => {
    const s = summarizeMetrics({ total_sessions: "not a number" });
    expect(s).toEqual({ sessions: 0, denials: 0, events: 0 });
  });

  it("coerces a numeric string", () => {
    const s = summarizeMetrics({ total_sessions: "5" });
    expect(s?.sessions).toBe(5);
  });
});
