// Appearance preference (Dark / Light / System), persisted per-device.
//
// This is a UI preference, not server config: it never goes through
// `Config`/`save_config` (settings.json), so it lives in localStorage instead
// -- wrapped in try/catch, since storage can be unavailable (private
// browsing, a locked-down profile) and that must not break the app.
//
// `public/theme-boot.js` resolves the same preference before this module (or
// any Svelte code) runs, so the right palette paints first frame with no
// flash. `initTheme()` here re-applies it once the app mounts and, for
// "system", keeps it live if the OS theme changes while the window is open.
// theme-boot.test.ts checks the two resolvers produce the same `data-theme`
// for every input so the duplication between them stays honest.
import { invoke, isTauri } from "@tauri-apps/api/core";
import { writable } from "svelte/store";

export type ThemePreference = "dark" | "light" | "system";
type ResolvedTheme = "dark" | "light";

const STORAGE_KEY = "ectoledger:theme";

function isThemePreference(value: unknown): value is ThemePreference {
  return value === "dark" || value === "light" || value === "system";
}

/** Reads the stored preference. Missing, unreadable or invalid (an old
 *  build's value, hand-edited storage) all fall back to "system". */
export function loadPreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return isThemePreference(stored) ? stored : "system";
  } catch {
    return "system";
  }
}

function persistPreference(pref: ThemePreference): void {
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // Private browsing or blocked storage: the choice just does not survive reload.
  }
}

/** True when the OS reports a light colour scheme. Guarded for environments
 *  (jsdom, a very old WebView) with no `matchMedia`. */
export function systemPrefersLight(): boolean {
  return typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: light)").matches;
}

/** "system" resolves to the OS preference; "dark"/"light" pass through
 *  unchanged. Mirrors the resolver in `public/theme-boot.js`. */
export function resolveTheme(pref: ThemePreference): ResolvedTheme {
  return pref === "system" ? (systemPrefersLight() ? "light" : "dark") : pref;
}

function applyTheme(theme: ResolvedTheme): void {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", theme);
  }
}

/** The native title bar follows the same choice; "system" hands it back to
 *  the OS. Outside the desktop app there is no window to tell. */
function syncWindowTheme(pref: ThemePreference): void {
  if (isTauri()) {
    invoke("set_window_theme", { theme: pref }).catch(() => {});
  }
}

/** The persisted preference. Settings binds its Appearance control to this
 *  directly; setting it applies immediately (no Save button involved). */
export const themePreference = writable<ThemePreference>(loadPreference());

let stopSystemListener: (() => void) | null = null;

function syncSystemListener(pref: ThemePreference): void {
  stopSystemListener?.();
  stopSystemListener = null;
  if (pref !== "system" || typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return;
  }
  const media = window.matchMedia("(prefers-color-scheme: light)");
  const onChange = () => applyTheme(resolveTheme("system"));
  media.addEventListener("change", onChange);
  stopSystemListener = () => media.removeEventListener("change", onChange);
}

/** Wires persistence, DOM application and the live "system" listener. Call
 *  once from main.ts after the DOM exists. Returns an unsubscribe for tests;
 *  the running app never needs to call it. */
export function initTheme(): () => void {
  return themePreference.subscribe((pref) => {
    persistPreference(pref);
    applyTheme(resolveTheme(pref));
    syncWindowTheme(pref);
    syncSystemListener(pref);
  });
}
