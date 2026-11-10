import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const STORAGE_KEY = "ectoledger:theme";

/** Installs a `matchMedia` that reports "light" iff `light` is true, and
 *  returns the `change` listener spies so a test can assert on them. */
function stubMatchMedia(light: boolean) {
  const addEventListener = vi.fn();
  const removeEventListener = vi.fn();
  const mql = {
    matches: light,
    media: "(prefers-color-scheme: light)",
    addEventListener,
    removeEventListener,
  };
  const matchMedia = vi.fn().mockReturnValue(mql);
  vi.stubGlobal("matchMedia", matchMedia);
  window.matchMedia = matchMedia as unknown as typeof window.matchMedia;
  return { matchMedia, addEventListener, removeEventListener };
}

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("loadPreference", () => {
  it("defaults to \"system\" when nothing is stored", async () => {
    const { loadPreference } = await import("./theme");
    expect(loadPreference()).toBe("system");
  });

  it("returns a validly stored preference", async () => {
    localStorage.setItem(STORAGE_KEY, "light");
    const { loadPreference } = await import("./theme");
    expect(loadPreference()).toBe("light");
  });

  it("falls back to \"system\" for an invalid stored value", async () => {
    localStorage.setItem(STORAGE_KEY, "solarized");
    const { loadPreference } = await import("./theme");
    expect(loadPreference()).toBe("system");
  });

  it("falls back to \"system\" when localStorage throws", async () => {
    const getItem = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const { loadPreference } = await import("./theme");
    expect(loadPreference()).toBe("system");
    getItem.mockRestore();
  });
});

describe("resolveTheme", () => {
  it("passes \"dark\" and \"light\" through unchanged", async () => {
    stubMatchMedia(true);
    const { resolveTheme } = await import("./theme");
    expect(resolveTheme("dark")).toBe("dark");
    expect(resolveTheme("light")).toBe("light");
  });

  it("resolves \"system\" to the OS preference", async () => {
    const { resolveTheme } = await import("./theme");

    stubMatchMedia(true);
    expect(resolveTheme("system")).toBe("light");

    stubMatchMedia(false);
    expect(resolveTheme("system")).toBe("dark");
  });

  it("resolves \"system\" to \"dark\" when matchMedia is unavailable", async () => {
    const { resolveTheme } = await import("./theme");
    vi.stubGlobal("matchMedia", undefined);
    // @ts-expect-error -- simulating a webview with no matchMedia at all
    delete window.matchMedia;
    expect(resolveTheme("system")).toBe("dark");
  });
});

describe("themePreference / initTheme", () => {
  it("initial store value reflects the persisted preference", async () => {
    localStorage.setItem(STORAGE_KEY, "light");
    const { themePreference } = await import("./theme");
    const { get } = await import("svelte/store");
    expect(get(themePreference)).toBe("light");
  });

  it("applies the resolved theme to <html data-theme> and persists changes", async () => {
    stubMatchMedia(false);
    const { themePreference, initTheme } = await import("./theme");
    const stop = initTheme();

    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");

    themePreference.set("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(localStorage.getItem(STORAGE_KEY)).toBe("light");

    stop();
  });

  it("only listens for OS changes while the preference is \"system\"", async () => {
    const { addEventListener, removeEventListener } = stubMatchMedia(false);
    const { themePreference, initTheme } = await import("./theme");
    const stop = initTheme();

    // Initial preference defaults to "system": one listener attached.
    expect(addEventListener).toHaveBeenCalledTimes(1);

    themePreference.set("dark");
    expect(removeEventListener).toHaveBeenCalledTimes(1);

    themePreference.set("system");
    expect(addEventListener).toHaveBeenCalledTimes(2);

    stop();
  });
});
