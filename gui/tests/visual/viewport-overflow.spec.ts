/**
 * The window's minimum size is 1024×640. Nothing on the screens a first-time
 * evaluator reaches may force horizontal scrolling at that width.
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

test.use({ viewport: { width: 1024, height: 640 } });

async function expectNoHorizontalOverflow(page: import("@playwright/test").Page, label: string) {
  const overflow = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }));
  expect(overflow.scrollWidth, `${label}: scrollWidth vs clientWidth (${JSON.stringify(overflow)})`).toBeLessThanOrEqual(
    overflow.clientWidth,
  );

  // The `documentElement` check above passes even when a pane overflows,
  // because `<main>` and the split-pane screens wrap themselves in
  // `overflow-hidden` - the excess is clipped there and never reaches
  // `documentElement`'s own scrollWidth. Walk the DOM for the place that
  // clip actually happens: an element whose own content (scrollWidth) is
  // wider than its box, where that element is not deliberately horizontally
  // scrollable (overflow-x: auto/scroll - the content stays reachable) and
  // is not a single-line ellipsis truncation (also deliberate).
  const clipped = await page.evaluate(() => {
    const found: Array<{ tag: string; id: string | null; cls: string | null; scrollWidth: number; clientWidth: number }> = [];
    document.querySelectorAll("body *").forEach((el) => {
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") return;
      if (style.textOverflow === "ellipsis") return;
      const sw = el.scrollWidth;
      const cw = el.clientWidth;
      // `.sr-only` (and similar visually-hidden patterns): 1px boxes holding
      // screen-reader text, clipped by design and never meant to be seen.
      if (cw <= 1) return;
      if (sw > cw + 2 && style.overflowX !== "auto" && style.overflowX !== "scroll") {
        found.push({
          tag: el.tagName,
          id: el.id || null,
          cls: typeof el.className === "string" ? el.className.slice(0, 120) : null,
          scrollWidth: sw,
          clientWidth: cw,
        });
      }
    });
    return found;
  });
  expect(clipped, `${label}: elements whose content is wider than their (non-scrollable) box`).toEqual([]);
}

const SCREENS: Array<{ tab: string; label: string }> = [
  { tab: "Home", label: "Dashboard" },
  { tab: "History", label: "Sessions" },
  { tab: "Policy", label: "Policies" },
  { tab: "Settings", label: "Settings" },
];

for (const { tab, label } of SCREENS) {
  test(`no horizontal overflow at 1024x640: ${label}`, async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/");
    await page.getByRole("button", { name: tab, exact: true }).click();
    await page.waitForLoadState("networkidle");
    await expectNoHorizontalOverflow(page, label);
  });
}

test("no horizontal overflow at 1024x640: command palette", async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Search/ }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expectNoHorizontalOverflow(page, "Command palette");
});

test("the sidebar stays usable at 1024x640 on every screen", async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");
  for (const { tab } of SCREENS) {
    await page.getByRole("button", { name: tab, exact: true }).click();
    await expect(page.getByRole("button", { name: tab, exact: true })).toBeVisible();
  }
});
