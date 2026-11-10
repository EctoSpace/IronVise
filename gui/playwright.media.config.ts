import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

// Explicit local recording command; never part of the regular test suite.
export default defineConfig({
  ...base,
  testDir: "./scripts",
  testMatch: "record-site-media.spec.ts",
  timeout: 90_000,
  outputDir: process.env.IRONVISE_MEDIA_OUTPUT ?? "/tmp/ironvise-site-media",
  use: { ...base.use, video: { mode: "on", size: { width: 1440, height: 900 } } },
});
