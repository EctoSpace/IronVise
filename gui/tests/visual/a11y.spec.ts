/**
 * Accessibility gate for primary and developer screens.
 *
 * This is a **no-regression** gate, not a clean-bill-of-health gate, and the
 * difference is deliberate.
 *
 * 6b fixed the token it named: `--color-text-muted` measured 2.28:1 against the
 * background while carrying body copy, and now clears AA on all three surfaces.
 * Running axe afterwards revealed the rest of the palette has the same problem
 * in a dozen other places - several greys remain after the 0.8.0 polish fixed
 * white-on-accent / white-on-success / white-on-danger button fills and
 * accent-as-text for links/nav (`--color-accent-text`).
 *
 * Fixing the remaining greys means retuning brand colours across every screen,
 * which is a visual redesign out of scope for this gate. So rather than assert
 * zero violations - a gate that fails on day one is a gate somebody disables in
 * week one - this pins the *known* set in `a11y-known-violations.json` and fails
 * on anything new.
 *
 * The backlog is therefore counted and visible rather than absent, and 6b's fix
 * cannot silently regress. Shrinking that file is the remaining work; growing it
 * should take a deliberate decision.
 *
 * **Colour is not the whole of accessibility, and pinning only colour hid the
 * rest.** Eleven Settings controls had no accessible name, the Audit History
 * refresh button was a bare `↻`, and `TestingView` nested a button inside a
 * button - none of which a contrast rule can see, so the gate was green
 * throughout. The rules below are the structural ones, and unlike contrast they
 * are asserted at **zero**: there is no backlog to pin, because the backlog was
 * fixed rather than recorded.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

/** Default short sidebar - what a first-time evaluator sees. */
const PRIMARY = [
  "Home",
  "History",
  "Policy",
  "Tripwire",
  "Access",
  "Settings",
];

/** Only present when show_developer_tools is on. */
const DEVELOPER = ["Testing", "Prometheus", "Live Feed", "Dev Hub"];

/** `fg-on-bg` identifies a colour pair independently of which node showed it. */
function signature(node: { failureSummary?: string }): string {
  const m = /foreground color: (#[0-9a-f]+), background color: (#[0-9a-f]+)/.exec(
    node.failureSummary ?? "",
  );
  return m ? `${m[1]}-on-${m[2]}` : "unparsed";
}

const KNOWN: string[] = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "a11y-known-violations.json"),
    "utf8",
  ),
).known;

/**
 * Rules about names, roles and structure rather than colour.
 *
 * Every one of these is either a violation of HTML's own content model or a
 * control a screen reader cannot announce. None is a matter of taste, which is
 * why they are required to be empty rather than pinned to a known set.
 */
const STRUCTURAL_RULES = [
  "button-name",
  "link-name",
  "label",
  "select-name",
  "input-button-name",
  "aria-required-attr",
  "aria-valid-attr-value",
  "nested-interactive",
  "duplicate-id-active",
];

async function assertNoStructuralViolations(
  page: import("@playwright/test").Page,
  label: string,
) {
  const results = await new AxeBuilder({ page }).withRules(STRUCTURAL_RULES).analyze();
  const found = results.violations.flatMap((v) =>
    v.nodes.map((n) => `${v.id}: ${n.target.join(" ")}`),
  );
  expect(
    found,
    `\n${label}: controls a screen reader cannot announce, or invalid ` +
      `interactive nesting:\n` +
      found.map((f) => `  ${f}`).join("\n") +
      `\n\nUnlike the contrast backlog these are not pinned. Give the control ` +
      `a name (a <label for>, an aria-label, or visible text), or stop nesting ` +
      `interactive elements.\n`,
  ).toEqual([]);
}

async function assertNoNovelContrast(page: import("@playwright/test").Page, label: string) {
  const results = await new AxeBuilder({ page }).withRules(["color-contrast"]).analyze();
  const seen = results.violations.flatMap((v) => v.nodes.map(signature));
  const novel = [...new Set(seen)].filter((sig) => !KNOWN.includes(sig));

  expect(
    novel,
    `\n${label}: contrast pairs not in the known backlog:\n` +
      novel.map((s) => `  ${s}`).join("\n") +
      `\n\nEither fix the colour, or - if it is a deliberate trade - add it to ` +
      `tests/visual/a11y-known-violations.json with a reason. Do not add it ` +
      `silently: that file is this project's record of what it knows is wrong.\n`,
  ).toEqual([]);
}

for (const tab of PRIMARY) {
  test(`no NEW contrast violations: ${tab}`, async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/");
    await page.getByRole("button", { name: tab, exact: true }).click();
    await page.waitForLoadState("networkidle");
    await assertNoNovelContrast(page, tab);
  });

  test(`every control has a name: ${tab}`, async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/");
    await page.getByRole("button", { name: tab, exact: true }).click();
    await page.waitForLoadState("networkidle");
    await assertNoStructuralViolations(page, tab);
  });
}

for (const tab of DEVELOPER) {
  test(`no NEW contrast violations (developer): ${tab}`, async ({ page }) => {
    await installTauriMock(page, {
      config: { show_developer_tools: true },
    });
    await page.goto("/");
    await page.getByRole("button", { name: tab, exact: true }).click();
    await page.waitForLoadState("networkidle");
    await assertNoNovelContrast(page, tab);
  });

  test(`every control has a name (developer): ${tab}`, async ({ page }) => {
    await installTauriMock(page, {
      config: { show_developer_tools: true },
    });
    await page.goto("/");
    await page.getByRole("button", { name: tab, exact: true }).click();
    await page.waitForLoadState("networkidle");
    await assertNoStructuralViolations(page, tab);
  });
}

test("the Audit History status filter shows a value on first load", async ({ page }) => {
  // It bound to `null` while the "All" option's value was `""`, so no option
  // matched and the control rendered blank. A filter that shows nothing tells
  // you nothing about what you are looking at.
  await installTauriMock(page);
  await page.goto("/");
  await page.getByRole("button", { name: "History", exact: true }).click();
  await page.waitForLoadState("networkidle");
  const filter = page.locator("#status-filter");
  await expect(filter).toHaveValue("");
  await expect(filter.locator("option:checked")).toHaveText("All");
});

test("no NEW contrast violations: command palette (open)", async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Search/ }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await assertNoNovelContrast(page, "Command palette");
});

test("every control has a name: command palette (open)", async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Search/ }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await assertNoStructuralViolations(page, "Command palette");
});

test("the known-violation list has not grown", () => {
  // A cap, so the backlog cannot quietly expand one entry at a time. Lowering
  // this number as colours are fixed is the point.
  expect(KNOWN.length, "known contrast violation pairs").toBeLessThanOrEqual(20);
});
