/**
 * The setup wizard's provider step. Anthropic was missing (the cloud choice
 * always saved "openai"), the step's Continue jumped to the Ollama model step
 * even on the cloud path, and the URL field sat inside the option button.
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

type Call = { cmd: string; args: Record<string, unknown> };

async function toProviderStep(page: import("@playwright/test").Page) {
  await installTauriMock(page, { overrides: { check_setup_complete: false } });
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
  await expect(page.getByRole("heading", { name: "Welcome to IronVise" })).toBeVisible();
  // Step 0 -> 1 -> Custom -> 2 (database) -> 3 (provider)
  const go = page.getByRole("button", { name: /Get Started|Continue/ }).first();
  if (await go.isVisible()) await go.click();
  await page.getByText("Custom Setup").click();
  await page.getByRole("button", { name: "Continue →" }).click();
  await page.getByText("SQLite (Embedded)").click();
  await page.getByRole("button", { name: "Continue →" }).click();
  await expect(page.getByText("LLM Provider")).toBeVisible();
}

test("Anthropic is offered, with the key field and a model list", async ({ page }) => {
  await toProviderStep(page);
  await page.getByRole("button", { name: /^Anthropic/ }).click();
  await expect(page.getByLabel("Anthropic API key")).toHaveAttribute("type", "password");
  const model = page.getByLabel("Model", { exact: true });
  await expect(model.locator("option")).toHaveText(["Choose a model", "mistral:latest", "qwen2.5:0.5b", "llama3.2:3b"]);
  await expect(page.getByRole("button", { name: "Continue →" })).toBeDisabled();
  await model.selectOption("qwen2.5:0.5b");
  await page.getByRole("button", { name: "Continue →" }).click();
  // Straight to provisioning: no Ollama model step on the cloud path.
  await expect(page.getByText("Select a model", { exact: false })).toHaveCount(0);
  await expect
    .poll(async () =>
      (await page.evaluate(() => (window as unknown as { __calls: Call[] }).__calls))
        .filter((c) => c.cmd === "save_config")
        .map((c) => c.args.payload),
    )
    .toContainEqual(expect.objectContaining({ llm_backend: "anthropic", ollama_model: "qwen2.5:0.5b" }));
});

test("the Ollama host field is outside the option button", async ({ page }) => {
  await toProviderStep(page);
  await page.getByRole("button", { name: /Connect Existing Local LLM/ }).click();
  // The mock reports Ollama running, so no host field; the field, when shown,
  // is labelled and not nested in a button.
  await expect(page.locator("button input")).toHaveCount(0);
});
