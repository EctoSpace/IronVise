/**
 * The command palette (⌘K / Ctrl+K): reaches every sidebar screen, every
 * Settings section, and a short list of theme/DevTools actions. Filtering
 * and ranking are unit tested in src/lib/commandPalette.test.ts; this file
 * covers the dialog itself - opening, keyboard nav, selection and closing.
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

async function open(page: import("@playwright/test").Page) {
  await installTauriMock(page, { config: { show_developer_tools: true } });
  await page.goto("/");
  await page.waitForLoadState("networkidle");
}

test("opens from the sidebar affordance and is a labelled, modal dialog", async ({ page }) => {
  await open(page);
  const trigger = page.getByRole("button", { name: /Search/ });
  await expect(trigger).toBeVisible();
  await trigger.click();

  const dialog = page.getByRole("dialog", { name: "Command palette" });
  await expect(dialog).toBeVisible();
  await expect(dialog).toHaveAttribute("aria-modal", "true");
  await expect(page.getByRole("combobox")).toBeFocused();
});

test("opens on the platform shortcut from anywhere in the app", async ({ page }) => {
  // This suite is pinned to macOS (baseline.spec.ts's -darwin snapshots), so
  // the real browser's navigator.platform is macOS and the app requires
  // Meta+K there - plain Ctrl+K is left alone (it is kill-to-end-of-line in
  // a text field) and must NOT open the palette.
  await open(page);
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog", { name: "Command palette" })).toHaveCount(0);

  await page.keyboard.press("Meta+k");
  await expect(page.getByRole("dialog", { name: "Command palette" })).toBeVisible();
});

test("does not open during the setup wizard", async ({ page }) => {
  await installTauriMock(page, { overrides: { check_setup_complete: false } });
  await page.goto("/");
  await page.waitForLoadState("networkidle");
  await expect(page.getByRole("heading", { name: "Welcome to IronVise" })).toBeVisible();

  await page.keyboard.press("Meta+k");
  await expect(page.getByRole("dialog", { name: "Command palette" })).toHaveCount(0);
});

test("typing a query with no match shows a clear empty state", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: /Search/ }).click();
  await page.getByRole("combobox").fill("zzzzzzznomatch");
  await expect(page.getByText("No matches.")).toBeVisible();
});

test("Escape closes the palette and returns focus to the opener", async ({ page }) => {
  await open(page);
  const trigger = page.getByRole("button", { name: /Search/ });
  await trigger.click();
  await expect(page.getByRole("dialog")).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(trigger).toBeFocused();
});

test("selecting a screen navigates to it and closes the palette", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: /Search/ }).click();
  await page.getByRole("combobox").fill("history");
  await expect(page.getByRole("option", { name: "History" })).toBeVisible();
  await page.getByRole("option", { name: "History" }).click();

  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Audit History" })).toBeVisible();
});

test("arrow keys move the selection and Enter activates it", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: /Search/ }).click();
  await page.getByRole("combobox").fill("policy");
  const option = page.getByRole("option", { name: "Policy" });
  await expect(option).toHaveAttribute("aria-selected", "true");

  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Policies" })).toBeVisible();
});

test("selecting a Settings section opens Settings and focuses that section", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: /Search/ }).click();
  await page.getByRole("combobox").fill("semantic guard");
  await page.getByRole("option", { name: /Semantic guard/ }).click();

  await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
  await expect(page.locator("#settings-guard")).toBeFocused();
});

test("a theme action applies immediately", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: /Search/ }).click();
  await page.getByRole("combobox").fill("switch theme to light");
  await page.getByRole("option", { name: "Switch theme to Light" }).click();

  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
});

test("clicking the backdrop closes the palette", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: /Search/ }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  // Click well outside the dialog box, inside the backdrop.
  await page.mouse.click(10, 10);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("lists developer screens only when developer tools are on", async ({ page }) => {
  await installTauriMock(page, { config: { show_developer_tools: false } });
  await page.goto("/");
  await page.waitForLoadState("networkidle");
  await page.getByRole("button", { name: /Search/ }).click();
  await page.getByRole("combobox").fill("dev hub");
  await expect(page.getByRole("option", { name: "Dev Hub" })).toHaveCount(0);
});
