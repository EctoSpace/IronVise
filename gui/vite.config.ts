import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";
import { readFileSync } from "fs";

const pkg = JSON.parse(readFileSync("package.json", "utf-8"));

// https://vitejs.dev/config/
export default defineConfig(() => ({
  plugins: [tailwindcss(), svelte()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  // 3. never auto-open a browser - `make start` is the desktop window; opening
  //    http://localhost:1420 shows a fake "Connection Error" because isTauri()
  //    is false in Chrome/Safari.
  server: {
    port: 1420,
    strictPort: true,
    open: false,
    // Proxy /api and /metrics to the backend so requests that accidentally
    // reach the Vite dev server get forwarded instead of returning an HTML 404.
    proxy: {
      '/api': {
        target: process.env.ECTO_HOST || 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
      '/metrics': {
        target: process.env.ECTO_HOST || 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
    },
    watch: {
      // 4. tell vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
  // 5. Explicitly set the build output directory so tauri.conf.json frontendDist
  //    ("../dist") always points to the correct location regardless of Vite version
  //    defaults.  Without this, Vite could resolve to a different directory and the
  //    Tauri production bundle would fail to find the frontend assets.
  build: {
    outDir: "dist",
    // WebView2 on Windows; on macOS the WebKit of the oldest supported
    // release, macOS 11 (tauri.conf.json minimumSystemVersion), which is
    // Safari 14: the first with BigInt literals, which tailwind-variants uses.
    target: process.env.TAURI_ENV_PLATFORM === "windows" ? "chrome105" : "safari14",
    minify: !process.env.TAURI_ENV_DEBUG,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
  },
}));
