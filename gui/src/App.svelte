<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onDestroy, onMount } from "svelte";
  import Sidebar from "./lib/Sidebar.svelte";
  import Dashboard from "./lib/Dashboard.svelte";
  import Sessions from "./lib/Sessions.svelte";
  import PolicyEditor from "./lib/PolicyEditor.svelte";
  import TripwireView from "./lib/TripwireView.svelte";
  import MetricsView from "./lib/MetricsView.svelte";
  import Settings from "./lib/Settings.svelte";
  import AccessView from "./lib/AccessView.svelte";
  import SetupWizard from "./lib/SetupWizard.svelte";
  import TestingView from "./lib/TestingView.svelte";
  import DevHub from "./lib/DevHub.svelte";
  import LiveDashboard from "./lib/LiveDashboard.svelte";
  import CommandPalette from "./lib/CommandPalette.svelte";
  import { visibleTabs } from "./lib/navigation";
  import { SETTINGS_SECTIONS } from "./lib/settingsSearch";
  import { themePreference } from "./lib/stores/theme";
  import { isPaletteShortcut, type PaletteItem } from "./lib/commandPalette";

  let activeTab = $state("dashboard");
  /** Screens laid out as panes that fill the window rather than a long form. */
  const FILL_TABS = new Set(["dashboard", "sessions", "policies"]);
  let serverUrl = $state("");
  let initialized = $state(false);
  let initError = $state("");
  let needsSetup = $state(false);
  let backendCrash = $state("");
  let showDeveloperTools = $state(false);
  let unlistenCrash: (() => void) | null = null;
  let paletteOpen = $state(false);
  /** Set when the palette picks a Settings section; Settings scrolls/focuses
   *  it, then clears this through onSectionFocused. */
  let focusSettingsSection = $state<string | null>(null);

  /** Rebuilt on every open from live state (showDeveloperTools, the current
   *  tab list), so the palette never lists a screen the sidebar would not. */
  function paletteItems(): PaletteItem[] {
    const screens: PaletteItem[] = visibleTabs(showDeveloperTools).map((t) => ({
      id: `screen:${t.id}`,
      label: t.label,
      group: "Screens",
      hint: "Screen",
    }));
    const settings: PaletteItem[] = SETTINGS_SECTIONS.map((s) => ({
      id: `settings:${s.id}`,
      label: `Settings → ${s.label}`,
      group: "Settings",
      // Every field's label and keywords, so "postgres" or "theme" reach
      // the section that holds that field, not just its own name.
      keywords: s.fields.flatMap((f) => [f.label, ...(f.keywords ?? [])]),
      hint: "Settings",
    }));
    const actions: PaletteItem[] = [
      { id: "action:theme-dark", label: "Switch theme to Dark", group: "Actions", keywords: ["appearance", "dark mode"] },
      { id: "action:theme-light", label: "Switch theme to Light", group: "Actions", keywords: ["appearance", "light mode"] },
      { id: "action:theme-system", label: "Switch theme to System", group: "Actions", keywords: ["appearance", "match system"] },
    ];
    if (isTauri() && showDeveloperTools) {
      actions.push({ id: "action:open-devtools", label: "Open Developer Console", group: "Actions", keywords: ["devtools", "inspector"] });
    }
    return [...screens, ...settings, ...actions];
  }

  function onPaletteSelect(item: PaletteItem) {
    if (item.id.startsWith("screen:")) {
      activeTab = item.id.slice("screen:".length);
    } else if (item.id.startsWith("settings:")) {
      activeTab = "settings";
      focusSettingsSection = item.id.slice("settings:".length);
    } else if (item.id === "action:theme-dark") {
      themePreference.set("dark");
    } else if (item.id === "action:theme-light") {
      themePreference.set("light");
    } else if (item.id === "action:theme-system") {
      themePreference.set("system");
    } else if (item.id === "action:open-devtools") {
      invoke("open_devtools").catch(console.error);
    }
  }

  function onGlobalKeydown(e: KeyboardEvent) {
    // Not during the wizard (nothing to show it over) or before init (the
    // tab list it would build from is not ready yet).
    if (!initialized || needsSetup) return;
    if (isPaletteShortcut(e)) {
      e.preventDefault();
      paletteOpen = true;
    }
  }

  /**
   * Initialization routine: the embedded server is started by Tauri's setup
   * hook, so we just read the URL from the Rust backend. (There is no probe
   * fallback: without the bootstrap token every API call would 401 anyway.)
   */
  async function initializeServerUrl(): Promise<string> {
    if (!isTauri()) {
      throw new Error(
        "This page is the Vite dev server (http://localhost:1420), not the app. " +
          "Use the IronVise desktop window from `make start` - ignore this browser tab."
      );
    }
    try {
      return await invoke<string>("server_url");
    } catch {
      throw new Error(
        "Could not determine backend server URL. Ensure the IronVise backend is running."
      );
    }
  }

  async function refreshDeveloperToolsFlag() {
    try {
      const data = await invoke<Record<string, unknown>>("get_config");
      showDeveloperTools = Boolean(data?.show_developer_tools);
    } catch {
      // Non-fatal: sidebar stays in the short default layout.
    }
  }

  onMount(async () => {
    try {
      serverUrl = await initializeServerUrl();
      // Fatal-error banner: embedded.rs emits "backend-crash" when the Axum
      // server task exits or panics - without this the GUI looks functional
      // while every API call silently fails.
      try {
        unlistenCrash = await listen<string>("backend-crash", (ev) => {
          backendCrash = ev.payload || "The embedded backend exited unexpectedly.";
        });
      } catch {
        // Not running under Tauri - no event system.
      }
      // Check if first launch - if no LLM config is set, show wizard
      try {
        const complete = await invoke<boolean>("check_setup_complete");
        if (!complete) needsSetup = true;
      } catch {
        // Tauri command unavailable in browser preview - show dashboard anyway
      }
      await refreshDeveloperToolsFlag();
      initialized = true;
    } catch (e) {
      initError = e instanceof Error ? e.message : String(e);
    }
    window.addEventListener("keydown", onGlobalKeydown);
  });

  onDestroy(() => {
    unlistenCrash?.();
    window.removeEventListener("keydown", onGlobalKeydown);
  });

  function handleSetupComplete() {
    needsSetup = false;
    activeTab = "dashboard";
    refreshDeveloperToolsFlag();
  }

  function handleSettingsSaved() {
    refreshDeveloperToolsFlag();
  }
</script>

{#if backendCrash}
  <div class="fixed top-0 inset-x-0 z-50 bg-danger text-text-inverse text-sm font-medium px-4 py-3 text-center shadow-md" role="alert">
    Fatal: the embedded backend stopped - {backendCrash}. Restart IronVise to continue.
  </div>
{/if}

{#if initError}
  <div class="flex items-center justify-center h-screen w-screen bg-background">
    <div class="max-w-md p-12 bg-surface rounded-2xl shadow-md text-center animate-fade-in">
      <h2 class="text-text-primary font-semibold text-lg mb-5">Desktop app only</h2>
      <p class="text-text-primary text-sm leading-relaxed">{initError}</p>
      <p class="text-text-muted text-xs mt-5">Close this browser tab and use the IronVise window.</p>
    </div>
  </div>
{:else if !initialized}
  <div class="flex flex-col items-center justify-center gap-6 h-screen w-screen bg-background">
    <div class="text-center animate-pulse-gentle">
      <div class="h-10 w-10 mx-auto mb-6 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
      <p class="text-accent-text text-sm">Connecting to backend…</p>
    </div>
  </div>
{:else if needsSetup}
  <SetupWizard {serverUrl} onComplete={handleSetupComplete} />
{:else}
  <div class="flex h-screen w-screen bg-background overflow-hidden">
    <Sidebar bind:activeTab {serverUrl} {showDeveloperTools} onOpenPalette={() => (paletteOpen = true)} />

    <main class="flex-1 min-w-0 min-h-0 overflow-y-auto overflow-x-hidden max-w-full">
    <!-- Split-pane screens size themselves with h-full and scroll inside their
         panes. With no height here, h-full resolved to auto and the Policy
         editor collapsed to a handful of lines; give those screens the
         window's height and let the long forms scroll the page as before. -->
    <div class="p-6 md:p-8 lg:p-10 min-w-0 {FILL_TABS.has(activeTab) ? 'h-full' : 'pb-16'}">
      {#if activeTab === "dashboard"}
        <Dashboard {serverUrl} onNavigateToTab={(t: string) => (activeTab = t)} />
      {:else if activeTab === "sessions"}
        <Sessions />
      {:else if activeTab === "policies"}
        <PolicyEditor />
      {:else if activeTab === "tripwire"}
        <TripwireView />
      {:else if activeTab === "access"}
        <AccessView />
      {:else if activeTab === "settings"}
        <Settings
          onSaved={handleSettingsSaved}
          focusSection={focusSettingsSection}
          onSectionFocused={() => (focusSettingsSection = null)}
        />
      {:else if activeTab === "metrics"}
        <MetricsView />
      {:else if activeTab === "testing"}
        <TestingView {serverUrl} />
      {:else if activeTab === "devhub"}
        <DevHub {serverUrl} />
      {:else if activeTab === "livedashboard"}
        <LiveDashboard {serverUrl} />
      {/if}
    </div>
    </main>
  </div>
  <CommandPalette items={paletteItems()} bind:open={paletteOpen} onselect={onPaletteSelect} />
{/if}
