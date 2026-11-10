/**
 * The Policy screen chooses the policy Home → Run uses. Before, it edited
 * files no run read (runs used ECTO_POLICY_PATH only), and built-in packs
 * looked editable but could not be saved.
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

type Call = { cmd: string; args: Record<string, unknown> };

async function open(page: import("@playwright/test").Page, config: Record<string, unknown> = {}) {
  await installTauriMock(page, {
    config,
    overrides: { get_policies: ["iso42001", "my-policy"] },
  });
  await page.addInitScript(() => {
    const w = window as unknown as { __TAURI_INTERNALS__: { invoke: Function }; __calls: unknown[] };
    const inner = w.__TAURI_INTERNALS__.invoke;
    w.__calls = [];
    w.__TAURI_INTERNALS__.invoke = async (cmd: string, args: unknown) => {
      w.__calls.push({ cmd, args });
      return inner(cmd, args);
    };
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Policy", exact: true }).click();
}

const calls = (page: import("@playwright/test").Page) =>
  page.evaluate(() => (window as unknown as { __calls: Call[] }).__calls);

test("Use for new runs saves the choice and says so", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: "my-policy" }).click();
  await expect(page.getByText("New runs from Home use no policy")).toBeVisible();
  await page.getByRole("button", { name: "Use for new runs" }).click();
  await expect(page.getByText("Used for new runs")).toBeVisible();
  await expect(page.getByText("checked against my-policy")).toBeVisible();
  const saved = (await calls(page)).filter((c) => c.cmd === "save_config");
  expect(saved.at(-1)?.args).toEqual({ payload: { active_policy: "my-policy" } });
  await page.getByRole("button", { name: "Stop using" }).click();
  await expect(page.getByText("New runs from Home use no policy")).toBeVisible();
});

test("a built-in pack is read only but can be used for runs", async ({ page }) => {
  await open(page);
  await page.getByRole("button", { name: "iso42001" }).click();
  await expect(page.getByText("Built-in, read only")).toBeVisible();
  await expect(page.getByLabel("Policy file contents (TOML)")).toHaveAttribute("readonly", "");
  await expect(page.getByRole("button", { name: "Save", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Use for new runs" })).toBeVisible();
});

test("ECTO_POLICY_PATH in the environment wins and is shown", async ({ page }) => {
  await open(page, { policy_from_environment: "/etc/ectoledger/policy.toml" });
  await page.getByRole("button", { name: "my-policy" }).click();
  await expect(page.getByText("/etc/ectoledger/policy.toml")).toBeVisible();
  await expect(page.getByRole("button", { name: "Use for new runs" })).toHaveCount(0);
});
