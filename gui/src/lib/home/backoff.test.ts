import { describe, it, expect } from "vitest";
import { metricsPollDelay, sessionPollDelay } from "./backoff";

describe("metricsPollDelay", () => {
  it("stays at 10s under three consecutive errors", () => {
    expect(metricsPollDelay(0)).toBe(10_000);
    expect(metricsPollDelay(1)).toBe(10_000);
    expect(metricsPollDelay(2)).toBe(10_000);
  });

  it("doubles from the 3rd error", () => {
    expect(metricsPollDelay(3)).toBe(20_000);
    expect(metricsPollDelay(4)).toBe(40_000);
  });

  it("caps at 60s", () => {
    expect(metricsPollDelay(5)).toBe(60_000);
    expect(metricsPollDelay(10)).toBe(60_000);
  });
});

describe("sessionPollDelay", () => {
  it("starts at 2s", () => {
    expect(sessionPollDelay(0)).toBe(2000);
  });

  it("doubles with each empty response", () => {
    expect(sessionPollDelay(1)).toBe(4000);
    expect(sessionPollDelay(2)).toBe(8000);
    expect(sessionPollDelay(3)).toBe(16000);
  });

  it("caps at 16s", () => {
    expect(sessionPollDelay(4)).toBe(16000);
    expect(sessionPollDelay(10)).toBe(16000);
  });
});
