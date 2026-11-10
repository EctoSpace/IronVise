/**
 * Light-mode visual baseline for the 2026-10-23 Appearance control.
 *
 * `baseline.spec.ts` covers the dark palette (the project's default) across
 * every screen; this file is deliberately narrow -- two screens -- to prove
 * the light palette renders correctly without duplicating the whole suite.
 * An explicit stored "light" preference is set before the app boots (the
 * same mechanism `public/theme-boot.js` reads), so this holds regardless of
 * Playwright's own `colorScheme: "dark"` emulation in playwright.config.ts.
 *
 * Update deliberately after an intentional palette change:
 *
 *     npx playwright test theme-light
 *     npx playwright test theme-light --update-snapshots
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("ectoledger:theme", "light");
  });
});

test("screen: dashboard (light)", async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");

  await expect(page.getByRole("button", { name: "Home", exact: true })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

  await page.waitForLoadState("networkidle");
  await expect(page.locator("main").first()).toBeVisible();

  await expect(page).toHaveScreenshot("dashboard-light.png", { fullPage: true });
});

test("screen: settings (light)", async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");

  const navButton = page.getByRole("button", { name: "Settings", exact: true });
  await expect(navButton).toBeVisible();
  await navButton.click();

  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.waitForLoadState("networkidle");
  await expect(page.locator("main").first()).toBeVisible();

  await expect(page).toHaveScreenshot("settings-light.png", { fullPage: true });
});
