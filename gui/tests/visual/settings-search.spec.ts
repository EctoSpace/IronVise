/**
 * The Settings search field filters sections, and individual fields within
 * a section, as you type. Matching logic is unit tested in
 * src/lib/settingsSearch.test.ts; this file covers the field wired into the
 * real screen.
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

type Call = { cmd: string; args: Record<string, unknown> };

async function openSettings(page: import("@playwright/test").Page, trackCalls = false) {
  await installTauriMock(page);
  if (trackCalls) {
    await page.addInitScript(() => {
      const w = window as unknown as { __TAURI_INTERNALS__: { invoke: Function }; __calls: unknown[] };
      const inner = w.__TAURI_INTERNALS__.invoke;
      w.__calls = [];
      w.__TAURI_INTERNALS__.invoke = async (cmd: string, args: unknown) => {
        w.__calls.push({ cmd, args });
        return inner(cmd, args);
      };
    });
  }
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.waitForLoadState("networkidle");
}

const calls = (page: import("@playwright/test").Page) =>
  page.evaluate(() => (window as unknown as { __calls: Call[] }).__calls);

test("filters whole sections by name as you type", async ({ page }) => {
  await openSettings(page);
  await expect(page.locator("#settings-ledger")).toBeVisible();
  await expect(page.locator("#settings-desktop")).toBeVisible();

  await page.getByLabel("Search settings").fill("ledger");
  await expect(page.locator("#settings-ledger")).toBeVisible();
  // Hidden via the `hidden` attribute, not unmounted: ModelSection and
  // GuardSection refetch their provider's model list in an effect on mount,
  // so a filtered-out section stays in the DOM rather than being torn down
  // and rebuilt on every keystroke.
  await expect(page.locator("#settings-desktop")).toBeHidden();
});

test("filters to just the matching field within a section", async ({ page }) => {
  await openSettings(page);
  await page.getByLabel("Search settings").fill("appearance");

  await expect(page.locator("#settings-desktop")).toBeVisible();
  await expect(page.getByLabel("Appearance")).toBeVisible();
  // "Show developer tools" is a different field in the same section.
  await expect(page.getByText("Show developer tools")).toHaveCount(0);
});

test("matches a field by keyword, not just its visible label", async ({ page }) => {
  await openSettings(page);
  // "Max steps per session" never says "loop", but that is one of its keywords.
  await page.getByLabel("Search settings").fill("loop");
  await expect(page.locator("#settings-agent")).toBeVisible();
  await expect(page.getByLabel("Max steps per session")).toBeVisible();
});

test("shows a clear no-match state and recovers from it", async ({ page }) => {
  await openSettings(page);
  await page.getByLabel("Search settings").fill("xyznosuchsetting");
  await expect(page.getByText(/No settings match/)).toBeVisible();

  await page.getByRole("button", { name: "Clear search" }).click();
  await expect(page.getByText(/No settings match/)).toHaveCount(0);
  await expect(page.locator("#settings-ledger")).toBeVisible();
});

test("Escape clears the query", async ({ page }) => {
  await openSettings(page);
  const search = page.getByLabel("Search settings");
  await search.fill("ledger");
  await expect(page.locator("#settings-desktop")).toBeHidden();

  await search.press("Escape");
  await expect(search).toHaveValue("");
  await expect(page.locator("#settings-desktop")).toBeVisible();
});

test("hiding and reshowing Model via search does not refetch the provider's model list", async ({ page }) => {
  await openSettings(page, true);
  const before = (await calls(page)).filter((c) => c.cmd === "get_provider_models").length;
  expect(before).toBeGreaterThan(0);

  const search = page.getByLabel("Search settings");
  // Types through several states that hide Model, then clears it back out -
  // each hide/show used to unmount and remount ModelSection, which refetches
  // the model list in a mount effect.
  await search.fill("ledger");
  await expect(page.locator("#settings-model")).toBeHidden();
  await search.fill("");
  await expect(page.locator("#settings-model")).toBeVisible();

  const after = (await calls(page)).filter((c) => c.cmd === "get_provider_models").length;
  expect(after).toBe(before);
});

test("the on-page index only links to visible sections", async ({ page }) => {
  await openSettings(page);
  await page.getByLabel("Search settings").fill("ledger");
  const nav = page.getByRole("navigation", { name: "On this page" });
  await expect(nav.getByRole("link", { name: "Ledger" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Desktop" })).toHaveCount(0);
});
