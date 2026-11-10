/**
 * The API key field for hosted providers. The key goes to the OS credential
 * store through set_api_key and nowhere else: not into the Settings payload,
 * not back into the page.
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

type Call = { cmd: string; args: Record<string, unknown> };

async function open(page: import("@playwright/test").Page, provider: string) {
  await installTauriMock(page);
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
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.locator("#settings-llm-provider").selectOption(provider);
}

const calls = (page: import("@playwright/test").Page) =>
  page.evaluate(() => (window as unknown as { __calls: Call[] }).__calls);

test("a hosted provider has a key field; saving sends the key to the store only", async ({ page }) => {
  await open(page, "anthropic");
  const field = page.getByLabel("Anthropic API key");
  await expect(field).toHaveAttribute("type", "password");
  await expect(page.getByText("No key yet. Anthropic needs one")).toBeVisible();

  await field.fill("sk-ant-test-123");
  await page.getByRole("button", { name: "Save key" }).click();
  await expect(page.getByText("A key is saved in the macOS Keychain")).toBeVisible();
  await expect(field).toHaveValue("");
  await expect(page.getByRole("button", { name: "Remove" })).toBeVisible();

  const set = (await calls(page)).filter((c) => c.cmd === "set_api_key");
  expect(set.at(-1)?.args).toEqual({ name: "ANTHROPIC_API_KEY", key: "sk-ant-test-123" });

  await page.getByRole("button", { name: "Save", exact: true }).click();
  const saved = (await calls(page)).filter((c) => c.cmd === "save_config");
  expect(JSON.stringify(saved)).not.toContain("sk-ant-test-123");
});

test("OpenAI reads OPENAI_API_KEY", async ({ page }) => {
  await open(page, "openai");
  await expect(page.getByLabel("OpenAI API key")).toBeVisible();
  const status = (await calls(page)).filter((c) => c.cmd === "api_key_status");
  expect(status.at(-1)?.args).toEqual({ name: "OPENAI_API_KEY" });
});

test("local providers have no key field", async ({ page }) => {
  await open(page, "lmstudio");
  await expect(page.locator("#settings-api-key")).toHaveCount(0);
  await page.locator("#settings-llm-provider").selectOption("ollama");
  await expect(page.locator("#settings-api-key")).toHaveCount(0);
});
