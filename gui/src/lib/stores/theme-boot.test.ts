/**
 * `public/theme-boot.js` duplicates `resolveTheme()` from `./theme` on
 * purpose -- it has to run before any module, including this app's, as a
 * plain blocking script (see index.html and the file's own header comment).
 * This test is what keeps that duplication honest: it runs the real shipped
 * file, not a copy of its logic, against the same inputs `theme.test.ts`
 * exercises against the TS resolver, and checks they agree.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../../../public/theme-boot.js"),
  "utf8",
);
const STORAGE_KEY = "ectoledger:theme";

function run(stored: string | null, systemPrefersLight: boolean): string | null {
  localStorage.clear();
  if (stored !== null) localStorage.setItem(STORAGE_KEY, stored);
  document.documentElement.removeAttribute("data-theme");
  window.matchMedia = vi.fn().mockReturnValue({ matches: systemPrefersLight }) as unknown as typeof window.matchMedia;

  // eslint-disable-next-line no-eval -- executing the real shipped file, see header comment.
  eval(SCRIPT);

  return document.documentElement.getAttribute("data-theme");
}

describe("public/theme-boot.js", () => {
  it("resolves a stored \"light\"/\"dark\" preference directly", () => {
    expect(run("light", false)).toBe("light");
    expect(run("dark", true)).toBe("dark");
  });

  it("resolves \"system\" (and anything invalid) from matchMedia", () => {
    expect(run("system", true)).toBe("light");
    expect(run("system", false)).toBe("dark");
    expect(run("not-a-theme", true)).toBe("light");
    expect(run(null, false)).toBe("dark");
  });

  it("leaves data-theme unset (dark palette by default) when storage throws", () => {
    const getItem = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    document.documentElement.removeAttribute("data-theme");

    // eslint-disable-next-line no-eval
    eval(SCRIPT);

    expect(document.documentElement.getAttribute("data-theme")).toBeNull();
    getItem.mockRestore();
  });

  it("agrees with the TS resolver for every preference and OS state", async () => {
    const { resolveTheme } = await import("./theme");
    for (const pref of ["dark", "light", "system"] as const) {
      for (const light of [true, false]) {
        expect(run(pref, light)).toBe(resolveTheme(pref));
      }
    }
  });
});
