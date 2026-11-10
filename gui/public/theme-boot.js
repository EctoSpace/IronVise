// Pre-paint theme resolver. Loaded as a classic, blocking <script src> from
// index.html's <head> (not inlined: the Tauri CSP is `script-src 'self'`,
// with no `'unsafe-inline'`) so `data-theme` is on <html> before the first
// paint and before app.css's `:root[data-theme="light"]` rule or any Svelte
// code runs. src/lib/stores/theme.ts re-applies the same resolution once the
// app mounts (and keeps it live for "system" while the window stays open);
// theme-boot.test.ts checks the two resolvers agree for every stored value.
(function () {
  try {
    var KEY = "ectoledger:theme";
    var stored = localStorage.getItem(KEY);
    var pref = stored === "light" || stored === "dark" || stored === "system" ? stored : "system";
    var theme = pref;
    if (pref === "system") {
      theme =
        window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
          ? "light"
          : "dark";
    }
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) {
    // localStorage/matchMedia unavailable (private mode, a very old webview):
    // leave the default dark palette the critical CSS below already paints.
  }
})();
