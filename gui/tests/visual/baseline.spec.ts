/*
 * The `-chromium-darwin` baselines are recorded on macOS (Apple Silicon);
 * refresh them only after looking at each diff. `sessions-open` and
 * `sessions-receipt` show History with a session open, its verdict and
 * signature count, and a data receipt shown as "Data received".
 *
 * Refresh with `npm run test:visual:update` on macOS, and look at the diffs
 * before accepting them. Baselines accepted without being looked at are how a
 * gate becomes a rubber stamp.
 */
/**
 * Visual baseline for primary and developer screens.
 *
 * Update deliberately after intentional UI changes:
 *
 *     npx playwright test
 *     npx playwright test --update-snapshots
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

/** Default short sidebar - what a first-time evaluator sees. */
const PRIMARY: Array<{ tab: string; name: string }> = [
  { tab: "Home", name: "dashboard" },
  { tab: "History", name: "sessions" },
  { tab: "Policy", name: "policy-editor" },
  { tab: "Tripwire", name: "tripwire" },
  { tab: "Access", name: "access" },
  { tab: "Settings", name: "settings" },
];

/** Only present when show_developer_tools is on. */
const DEVELOPER: Array<{ tab: string; name: string }> = [
  { tab: "Testing", name: "testing" },
  { tab: "Prometheus", name: "metrics" },
  { tab: "Live Feed", name: "live-dashboard" },
  { tab: "Dev Hub", name: "devhub" },
];

test.describe("visual baseline - primary", () => {
  for (const { tab, name } of PRIMARY) {
    test(`screen: ${name}`, async ({ page }) => {
      await installTauriMock(page);
      await page.goto("/");

      const navButton = page.getByRole("button", { name: tab, exact: true });
      await expect(navButton).toBeVisible();
      await navButton.click();

      await page.waitForLoadState("networkidle");
      await expect(page.locator("main").first()).toBeVisible();

      await expect(page).toHaveScreenshot(`${name}.png`, { fullPage: true });
    });
  }

  test("screen: setup-wizard", async ({ page }) => {
    await installTauriMock(page, {
      overrides: { check_setup_complete: false },
    });
    await page.goto("/");

    await page.waitForLoadState("networkidle");
    // Wizard copy mentions "Home → Run"; require an exact nav label, not a substring.
    await expect(page.getByRole("button", { name: "Home", exact: true })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Welcome to IronVise" })).toBeVisible();

    await expect(page).toHaveScreenshot("setup-wizard.png", { fullPage: true });
  });

  test("screen: sessions-open", async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/");
    await page.getByRole("button", { name: "History", exact: true }).click();
    await page.getByRole("button", { name: /Audit server_config\.txt/ }).click();
    // A data receipt reads as what the agent received, by hash, not raw JSON.
    await expect(page.getByText("Data received")).toBeVisible();
    await page.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(page.getByRole("status")).toBeVisible();
    await page.waitForLoadState("networkidle");

    await expect(page).toHaveScreenshot("sessions-open.png", { fullPage: true });

    // The event list scrolls inside its panel: bring the receipt into view.
    await page.getByText("Data received").scrollIntoViewIfNeeded();
    await expect(page).toHaveScreenshot("sessions-receipt.png", { fullPage: true });
  });

  test("developer tools are hidden by default", async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/");
    await expect(page.getByRole("button", { name: "Home", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Dev Hub", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Testing", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Prometheus", exact: true })).toHaveCount(0);
  });
});

test.describe("visual baseline - developer", () => {
  for (const { tab, name } of DEVELOPER) {
    test(`screen: ${name}`, async ({ page }) => {
      await installTauriMock(page, {
        config: { show_developer_tools: true },
      });
      await page.goto("/");

      const navButton = page.getByRole("button", { name: tab, exact: true });
      await expect(navButton).toBeVisible();
      await navButton.click();

      await page.waitForLoadState("networkidle");
      await expect(page.locator("main").first()).toBeVisible();

      await expect(page).toHaveScreenshot(`${name}.png`, { fullPage: true });
    });
  }
});

/**
 * The provider picker must offer the whole preset table.
 */
test("settings offers every provider preset", async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();

  const options = await page.locator("select").first().locator("option").allTextContents();
  for (const label of [
    "Ollama",
    "LM Studio",
    "llama.cpp server",
    "vLLM",
    "MLX-LM",
    "LocalAI",
    "OpenAI",
    "Anthropic",
    "Custom (OpenAI-compatible)",
  ]) {
    expect(options, `provider picker should offer ${label}`).toContain(label);
  }
  expect(options.join(" ")).not.toContain("Jan");
});
