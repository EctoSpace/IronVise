import { defineConfig } from "vitest/config";

// Standalone from vite.config.ts on purpose: that config wires up the Svelte
// and Tailwind plugins (and the Tauri dev-server proxy), none of which these
// unit tests need. Keeping this file separate also makes it trivial to steer
// clear of the Playwright specs under tests/visual, which are a different
// test runner entirely and must never be picked up here.
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
    exclude: ["tests/**", "node_modules/**"],
    globals: false,
  },
});
