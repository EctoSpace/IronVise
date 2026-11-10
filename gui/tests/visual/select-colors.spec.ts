/**
 * Drop-down lists are readable. On Windows (WebView2) a native <select>'s
 * open list kept the system's light-grey background while its options
 * inherited the app's light text: white on light grey.
 * The OS draws the open list, so this checks the computed colours it uses.
 */
import { expect, test } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

const SURFACE = "rgb(27, 34, 43)"; // --color-surface-elevated
const TEXT = "rgb(232, 237, 242)"; // --color-text-primary

test("every select and its options are light text on the dark surface", async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.locator("#settings-llm-model option").first()).toBeAttached();
  const styles = await page.evaluate(() =>
    [...document.querySelectorAll("select, select option")].map((el) => {
      const cs = getComputedStyle(el);
      return {
        what: `${el.tagName} ${(el as HTMLElement).id || (el as HTMLOptionElement).value}`,
        bg: cs.backgroundColor,
        color: cs.color,
        disabled: (el as HTMLOptionElement).disabled,
        checked: el.tagName === "OPTION" && (el as HTMLOptionElement).selected,
      };
    }),
  );
  expect(styles.length).toBeGreaterThan(5);
  for (const s of styles) {
    if (s.disabled || s.checked) continue;
    expect(s, s.what).toMatchObject({ bg: SURFACE, color: TEXT });
  }
});
