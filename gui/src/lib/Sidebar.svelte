<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { getVersion } from "@tauri-apps/api/app";
  import { onMount } from "svelte";
  import { detectDemoMode } from "./backend";
  import { DEVELOPER_TABS, visibleTabs } from "./navigation";
  import { paletteShortcutLabel } from "./commandPalette";

  let {
    activeTab = $bindable(),
    serverUrl = "",
    showDeveloperTools = false,
    onOpenPalette,
  }: {
    activeTab: string;
    serverUrl?: string;
    showDeveloperTools?: boolean;
    onOpenPalette?: () => void;
  } = $props();

  let appVersion = $state("…");
  let demoMode = $state(false);

  if (isTauri()) {
    getVersion().then((v) => (appVersion = `v${v}`)).catch(() => { appVersion = "v?.?.?"; });
  } else {
    appVersion = `v${__APP_VERSION__}`;
  }

  onMount(() => {
    detectDemoMode(serverUrl).then((v) => { if (v) demoMode = true; });
  });

  /* lucide icon paths, stroke-only, viewBox 0 0 24 24 */
  const icons: Record<string, string> = {
    dashboard: `<path stroke-linecap="round" stroke-linejoin="round" d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline stroke-linecap="round" stroke-linejoin="round" points="9 22 9 12 15 12 15 22"/>`,
    sessions:  `<path stroke-linecap="round" stroke-linejoin="round" d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4" stroke-linecap="round"/><path stroke-linecap="round" stroke-linejoin="round" d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>`,
    policies:  `<path stroke-linecap="round" stroke-linejoin="round" d="M9 11l3 3L22 4"/><path stroke-linecap="round" stroke-linejoin="round" d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>`,
    tripwire:  `<path stroke-linecap="round" stroke-linejoin="round" d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line stroke-linecap="round" x1="12" y1="9" x2="12" y2="13"/><line stroke-linecap="round" x1="12" y1="17" x2="12.01" y2="17"/>`,
    access:    `<rect stroke-linecap="round" stroke-linejoin="round" x="3" y="11" width="18" height="11" rx="2" ry="2"/><path stroke-linecap="round" stroke-linejoin="round" d="M7 11V7a5 5 0 0 1 10 0v4"/>`,
    settings:  `<circle cx="12" cy="12" r="3"/><path stroke-linecap="round" stroke-linejoin="round" d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>`,
    testing:   `<polygon stroke-linecap="round" stroke-linejoin="round" points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>`,
    metrics:   `<line stroke-linecap="round" x1="18" y1="20" x2="18" y2="10"/><line stroke-linecap="round" x1="12" y1="20" x2="12" y2="4"/><line stroke-linecap="round" x1="6"  y1="20" x2="6"  y2="14"/>`,
    livedashboard: `<polyline stroke-linecap="round" stroke-linejoin="round" points="22 12 18 12 15 21 9 3 6 12 2 12"/>`,
    devhub:    `<polyline stroke-linecap="round" stroke-linejoin="round" points="16 18 22 12 16 6"/><polyline stroke-linecap="round" stroke-linejoin="round" points="8 6 2 12 8 18"/>`,
  };

  let tabs = $derived(visibleTabs(showDeveloperTools));
  const shortcut = paletteShortcutLabel();

  // If developer tools were turned off while on a developer tab, leave.
  $effect(() => {
    if (!showDeveloperTools && DEVELOPER_TABS.some((t) => t.id === activeTab)) {
      activeTab = "dashboard";
    }
  });
</script>

<nav class="w-64 min-w-64 flex flex-col bg-surface border-r border-border-muted/40 shadow-sm py-6 px-4 overflow-y-auto overflow-x-hidden">
  <div class="flex items-center gap-3.5 px-3 mb-6 pb-5 border-b border-border-muted/40">
    <img src="/ironvise-mark.webp" alt="" class="w-9 h-9 object-contain shrink-0" />
    <span class="text-lg font-semibold tracking-tight text-text-primary">IronVise</span>
    {#if demoMode}
      <span class="ml-auto text-[10px] font-bold uppercase tracking-widest text-warning bg-warning/10 border border-warning/25 rounded-md px-2 py-0.5 select-none">Demo</span>
    {/if}
  </div>

  <button
    type="button"
    class="flex items-center gap-2.5 w-full px-3.5 py-2.5 mb-5 border border-border-muted/40 rounded-xl bg-surface-elevated/40 text-text-secondary text-sm cursor-pointer hover:bg-surface-elevated hover:text-text-primary transition-all duration-200"
    onclick={() => onOpenPalette?.()}
  >
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="shrink-0 text-text-muted">
      <circle cx="11" cy="11" r="7" stroke-linecap="round" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" stroke-linecap="round" />
    </svg>
    <span class="flex-1 text-left truncate">Search…</span>
    <kbd class="text-[11px] font-mono text-text-muted border border-border-muted/40 rounded-md px-1.5 py-0.5 shrink-0">{shortcut}</kbd>
  </button>

  <ul class="flex-1 space-y-px list-none">
    {#each tabs as t}
      {#if t.section}
        <li class="pt-8 pb-3 px-3 first:pt-0">
          <span class="text-[11px] uppercase tracking-[0.12em] text-text-secondary font-semibold">{t.section}</span>
        </li>
      {/if}
      <li>
        <button
          class="flex items-center gap-3 w-full px-4 py-2.5 border-none rounded-xl cursor-pointer text-sm transition-all duration-200
            {activeTab === t.id
              ? 'bg-accent/12 text-accent-text font-medium'
              : 'bg-transparent text-text-secondary hover:bg-surface-elevated hover:text-text-primary'}"
          onclick={() => (activeTab = t.id)}
        >
          <svg
            width="16" height="16" viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.75"
            class="shrink-0 {activeTab === t.id ? 'text-accent-text' : 'text-text-muted'}"
          >
            {@html icons[t.id] ?? ""}
          </svg>
          <span class="truncate">{t.label}</span>
        </button>
      </li>
    {/each}
  </ul>

  <div class="flex flex-col items-center gap-2.5 pt-6 mt-4">
    {#if isTauri() && showDeveloperTools}
      <button
        class="bg-transparent border border-border-muted/30 rounded-xl text-text-secondary px-4 py-2 text-xs cursor-pointer hover:text-text-primary hover:bg-surface-elevated transition-all duration-200 w-full mx-1"
        onclick={() => invoke("open_devtools").catch(console.error)}
        title="Open Developer Console"
      >
        DevTools
      </button>
    {/if}
    <span class="text-text-muted text-[10px]">{appVersion}</span>
  </div>
</nav>
