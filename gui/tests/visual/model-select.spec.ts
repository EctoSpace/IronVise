/**
 * Settings' model control. When the selected provider lists models, the
 * model is chosen from that list and nothing else: the preset's default name
 * is not offered unless the provider has it, and there is no free-text
 * escape. Only when the provider lists nothing is the model typed. A
 * <datalist> would hide the list (it only suggests names matching the text in
 * the field), and an "Other" entry would offer a model the provider lacks.
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

async function openSettings(page: import("@playwright/test").Page, options = {}) {
  await installTauriMock(page, options);
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
}

const LISTED = ["mistral:latest", "qwen2.5:0.5b", "llama3.2:3b"];

test("the control is labelled Model and offers exactly the listed models", async ({ page }) => {
  await openSettings(page);
  const select = page.getByLabel("Model", { exact: true });
  await expect(select).toHaveJSProperty("tagName", "SELECT");
  await expect(select.locator("option")).toHaveText(LISTED);
  await expect(page.getByText("Other", { exact: false })).toHaveCount(0);
});

test("a saved name the provider does not have is not shown", async ({ page }) => {
  await openSettings(page, { config: { ollama_model: "phi3" } });
  const select = page.getByLabel("Model", { exact: true });
  await expect(select).toHaveValue("");
  await expect(select.locator("option:checked")).toHaveText("Choose a model");
  await expect(select.locator("option", { hasText: "phi3" })).toHaveCount(0);
  await expect(page.getByText("The saved model is not among the ones this provider has")).toBeVisible();
});

test("a bare name is the listed name:latest", async ({ page }) => {
  await openSettings(page); // the fixture's model is "mistral"
  await expect(page.getByLabel("Model", { exact: true })).toHaveValue("mistral:latest");
});

test("choosing a model selects it", async ({ page }) => {
  await openSettings(page);
  const select = page.getByLabel("Model", { exact: true });
  await select.selectOption("qwen2.5:0.5b");
  await expect(select).toHaveValue("qwen2.5:0.5b");
});

test("a provider that lists nothing leaves the select empty, with no default name", async ({ page }) => {
  await openSettings(page, { overrides: { get_provider_models: [] } });
  const select = page.getByLabel("Model", { exact: true });
  await expect(select).toHaveJSProperty("tagName", "SELECT");
  await expect(select).toBeDisabled();
  await expect(select.locator("option")).toHaveText(["No models listed"]);
  await expect(page.locator("input#settings-llm-model")).toHaveCount(0);
});

test("Refresh asks the provider again", async ({ page }) => {
  await installTauriMock(page, { overrides: { get_provider_models: [] } });
  await page.addInitScript(() => {
    const w = window as unknown as { __TAURI_INTERNALS__: { invoke: Function } };
    const inner = w.__TAURI_INTERNALS__.invoke;
    let calls = 0;
    w.__TAURI_INTERNALS__.invoke = async (cmd: string, args: unknown) =>
      cmd === "get_provider_models" ? (++calls > 2 ? ["qwen2.5:0.5b"] : []) : inner(cmd, args);
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const select = page.getByLabel("Model", { exact: true });
  await expect(select).toBeDisabled();
  await page.locator("#settings-model").getByRole("button", { name: "Refresh the model list" }).click();
  await expect(select.locator("option")).toHaveText(["Choose a model", "qwen2.5:0.5b"]);
});

test("the guard's provider and model are selects fed like Model, with no inherit option", async ({ page }) => {
  await openSettings(page); // guard on, backend ollama, model qwen2.5:0.5b
  const provider = page.getByLabel("Guard provider");
  await expect(provider).toHaveJSProperty("tagName", "SELECT");
  await expect(provider).toHaveValue("ollama");
  await expect(provider.locator("option", { hasText: "Same as" })).toHaveCount(0);
  const model = page.getByLabel("Guard model", { exact: true });
  await expect(model).toHaveValue("qwen2.5:0.5b");
  await expect(model.locator("option")).toHaveText(LISTED);
});

test("turning the guard on starts from the agent's provider and Save needs a guard model", async ({ page }) => {
  await openSettings(page, {
    config: { guard_required: false, guard_llm_backend: null, guard_llm_model: null },
  });
  await page.locator("#settings-guard-required").click();
  await expect(page.getByLabel("Guard provider")).toHaveValue("ollama");
  const model = page.getByLabel("Guard model", { exact: true });
  await expect(model.locator("option:checked")).toHaveText("Choose a model");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("The semantic guard is on but has no model")).toBeVisible();
  await model.selectOption("llama3.2:3b");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("The semantic guard is on but has no model")).toHaveCount(0);
});

test("the guard selects are hidden while the guard is off", async ({ page }) => {
  await openSettings(page, { config: { guard_required: false } });
  await expect(page.getByLabel("Guard model", { exact: true })).toHaveCount(0);
});

test("the list follows the provider", async ({ page }) => {
  await installTauriMock(page);
  // LM Studio's list, served for any provider that is not Ollama.
  await page.addInitScript(() => {
    const w = window as unknown as { __TAURI_INTERNALS__: { invoke: Function } };
    const inner = w.__TAURI_INTERNALS__.invoke;
    w.__TAURI_INTERNALS__.invoke = async (cmd: string, args: { args?: { provider?: string } }) =>
      cmd === "get_provider_models" && args?.args?.provider !== "ollama"
        ? ["qwen2.5-7b-instruct"]
        : inner(cmd, args);
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.locator("#settings-llm-provider").selectOption({ label: "LM Studio" });
  await expect(page.getByLabel("Model", { exact: true }).locator("option")).toHaveText([
    "Choose a model",
    "qwen2.5-7b-instruct",
  ]);
});

/** Records each invoke's command and arguments in window.__calls. */
async function recordCalls(page: import("@playwright/test").Page) {
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

test("Save sends an emptied setting as \"\" so the server clears it", async ({ page }) => {
  await installTauriMock(page);
  await recordCalls(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByLabel("Model", { exact: true }).selectOption("llama3.2:3b");
  await page.locator("#settings-llm-endpoint").fill("");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  const saved = await page.evaluate(() =>
    (window as unknown as { __calls: { cmd: string; args: { payload: Record<string, unknown> } }[] }).__calls
      .filter((c) => c.cmd === "save_config")
      .map((c) => c.args.payload),
  );
  expect(saved.at(-1)).toMatchObject({ ollama_base_url: "", ollama_model: "llama3.2:3b" });
});

test("Anthropic has no address field; its list is asked of its own host", async ({ page }) => {
  await installTauriMock(page);
  await recordCalls(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.locator("#settings-llm-provider").selectOption("anthropic");
  await expect(page.locator("#settings-llm-endpoint")).toHaveCount(0);
  await expect(page.locator("#settings-model").getByRole("button", { name: "Test connection" })).toBeVisible();
  const probe = await page.evaluate(() =>
    (window as unknown as { __calls: { cmd: string; args: { args: { provider: string; baseUrl?: string } } }[] }).__calls
      .filter((c) => c.cmd === "get_provider_models" && c.args.args.provider === "anthropic")
      .at(-1)?.args.args,
  );
  expect(probe?.baseUrl).toBe("https://api.anthropic.com");
});

test("switching provider clears the model instead of filling in a default name", async ({ page }) => {
  await openSettings(page);
  await page.locator("#settings-llm-provider").selectOption("anthropic");
  const select = page.getByLabel("Model", { exact: true });
  await expect(select.locator("option:checked")).toHaveText("Choose a model");
  await expect(page.locator("#settings-model")).not.toContainText("claude-sonnet");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  // Nothing chosen: the model is saved empty, not as a name Anthropic may not have.
});
