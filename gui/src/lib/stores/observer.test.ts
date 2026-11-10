import { describe, it, expect } from "vitest";
import { get } from "svelte/store";
import { observerPoppedOut } from "./observer";

describe("observerPoppedOut", () => {
  it("defaults to false", () => {
    expect(get(observerPoppedOut)).toBe(false);
  });

  it("is a writable store that reflects set() calls", () => {
    observerPoppedOut.set(true);
    expect(get(observerPoppedOut)).toBe(true);
    observerPoppedOut.set(false);
    expect(get(observerPoppedOut)).toBe(false);
  });
});
