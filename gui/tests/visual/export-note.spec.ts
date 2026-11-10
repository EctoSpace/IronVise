/**
 * History's Certificate export says how the file is signed. An audit run's
 * certificate is unsigned unless the installation has an issuer key, and the
 * message used to be only "Certificate saved to …".
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

const bytes = (cert: Record<string, unknown>) =>
  Array.from(new TextEncoder().encode(JSON.stringify(cert)));

const PLUMBING = {
  "plugin:dialog|save": "/tmp/audit.elc",
  "plugin:fs|write_file": null,
  "plugin:path|resolve_directory": "/Users/me/Library/Application Support/io.ectoledger.agent-ledger",
};

async function exportFor(page: import("@playwright/test").Page, cert: Record<string, unknown>) {
  await installTauriMock(page, {
    overrides: { ...PLUMBING, export_certificate: bytes(cert) },
  });
  await page.goto("/");
  await page.getByRole("button", { name: "History", exact: true }).click();
  await page.getByRole("button", { name: /Audit server_config\.txt/ }).click();
  await page.getByRole("button", { name: "Certificate", exact: true }).click();
}

test("an unsigned certificate says so and how to get it countersigned", async ({ page }) => {
  await exportFor(page, { version: 1, session_id: "x" });
  const note = page.getByText(/Certificate saved to \/tmp\/audit\.elc\. It is unsigned/);
  await expect(note).toBeVisible();
  await expect(note).toContainText("verify-cert --strict refuses it");
  await expect(note).toContainText(
    'ECTO_DATA_DIR="/Users/me/Library/Application Support/io.ectoledger.agent-ledger" ironvise issuer-key init',
  );
});

test("a signed certificate says it is signed", async ({ page }) => {
  await exportFor(page, { version: 1, session_id: "x", signature: "ab" });
  await expect(page.getByText("Signed with the session's key.")).toBeVisible();
});

test("an issuer-countersigned certificate says so", async ({ page }) => {
  await exportFor(page, { version: 1, session_id: "x", issuer: { key: "cd" } });
  await expect(page.getByText("Countersigned by this installation's issuer key.")).toBeVisible();
});


for (const [command, button] of [["export_certificate", "Certificate"], ["download_report", "Report"]]) {
  test(`${button} export cannot open a dialog for a different selected session`, async ({page}) => {
    await installTauriMock(page);
    await page.goto("/");
    await page.getByRole("button", {name: "History", exact: true}).click();
    await page.getByRole("button", {name: /Audit server_config\.txt/}).click();
    await page.evaluate((command) => {
      const win = window as any;
      const original = win.__TAURI_INTERNALS__.invoke;
      win.savedDialogs = [];
      win.__TAURI_INTERNALS__.invoke = (cmd: string, args: any) => {
        if (cmd === command) return new Promise((resolve) => {win.finishExport = () => resolve([123,125]);});
        if (cmd === "plugin:dialog|save") {win.savedDialogs.push(args);return Promise.resolve(null);}
        return original(cmd, args);
      };
    }, command);
    await page.getByRole("button", {name: button, exact: true}).click();
    await page.waitForFunction(() => typeof (window as any).finishExport === "function");
    await page.getByRole("button", {name: /Enumerate listening services/}).click();
    await page.evaluate(() => (window as any).finishExport());
    await expect(page.getByRole("button", {name: button, exact: true})).toBeEnabled();
    expect(await page.evaluate(() => (window as any).savedDialogs)).toEqual([]);
  });
}

test("a stale History filter result cannot replace the current filter", async ({page}) => {
  await installTauriMock(page);
  await page.goto("/");
  await page.getByRole("button", {name: "History", exact: true}).click();
  await page.getByRole("button", {name: /Audit server_config\.txt/}).waitFor();
  await page.evaluate(() => {
    const win = window as any;
    const original = win.__TAURI_INTERNALS__.invoke;
    win.releaseHistory = {};
    win.__TAURI_INTERNALS__.invoke = (cmd: string, args: any) => {
      if (cmd === "get_sessions" && args.status) return new Promise((resolve) => {
        win.releaseHistory[args.status] = () => resolve([{id: args.status, goal: `${args.status} result`, status: args.status, created_at: "2026-01-01T00:00:00Z", finished_at: null}]);
      });
      return original(cmd, args);
    };
  });
  await page.getByLabel("Status", {exact: true}).selectOption("running");
  await page.getByLabel("Status", {exact: true}).selectOption("completed");
  await page.evaluate(() => (window as any).releaseHistory.completed());
  await expect(page.getByRole("button", {name: /completed result/})).toBeVisible();
  await page.evaluate(async () => {
    (window as any).releaseHistory.running();
    await new Promise(requestAnimationFrame);
    await new Promise(requestAnimationFrame);
  });
  await expect(page.getByRole("button", {name: /completed result/})).toBeVisible();
  await expect(page.getByRole("button", {name: /running result/})).toHaveCount(0);
});
