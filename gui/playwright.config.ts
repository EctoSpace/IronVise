/**
 * Playwright config for the GUI visual baseline.
 *
 * Scope is deliberately narrow: screenshot regression for the twelve screens,
 * nothing else. It drives the Vite dev server directly rather than a built
 * Tauri bundle - the app is a webview, so the rendering under test is the same,
 * and the alternative (tauri-driver) does not support macOS.
 */
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/visual",

  // Screenshot comparison is order- and resource-sensitive; keep it serial so
  // a baseline captured on a loaded machine matches one captured on an idle one.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],

  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://localhost:1420",
    // Fixed after the device spread, which carries its own viewport.
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1,
    colorScheme: "dark",
    timezoneId: "UTC",
    locale: "en-GB",
  },

  projects: [{ name: "chromium" }],

  expect: {
    toHaveScreenshot: {
      // An absolute budget, not a ratio. The original 1% ratio was 12,960px on
      // a 1440x900 viewport, and the design-token changes, restoring the whole
      // radius scale and raising muted-text contrast on every screen, moved
      // only ~1,700px each. A tolerance three times larger than a change that
      // touches all twelve screens is not a tolerance, it is a blindfold.
      //
      // 200px absorbs antialiasing jitter while still failing on a single
      // component losing its corner radius. The baseline is macOS-pinned
      // (-darwin suffix) and reproduces exactly on the same machine, so the
      // headroom does not need to cover cross-platform rasterisation.
      maxDiffPixels: 200,
      animations: "disabled",
      caret: "hide",
      scale: "css",
    },
  },

  webServer: {
    command: "npm run dev",
    url: "http://localhost:1420",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
