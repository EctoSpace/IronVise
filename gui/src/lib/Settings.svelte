<!--
  Settings: loads the config, hands it to one component per section
  (settings/*Section.svelte) and saves it. Saving goes through
  `save_config` → `PUT /api/config` → settings.json. API keys are not part of
  it: they go to the OS credential store from ApiKeyField. See docs/guides/desktop-app.md.
-->
<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import { detectDemoMode } from "./backend";
  import { InlineCode, Input, SaveBar } from "./ui";
  import type { Config, ProviderPreset } from "./settings/types";
  import LedgerSection from "./settings/LedgerSection.svelte";
  import ModelSection from "./settings/ModelSection.svelte";
  import GuardSection from "./settings/GuardSection.svelte";
  import AgentSection from "./settings/AgentSection.svelte";
  import DesktopSection from "./settings/DesktopSection.svelte";
  import EnvironmentSection from "./settings/EnvironmentSection.svelte";
  import DangerZone from "./settings/DangerZone.svelte";
  import { filterSettingsSections, SETTINGS_SECTIONS } from "./settingsSearch";

  interface Props {
    onSaved?: () => void;
    /** Set by the command palette to land on and focus a section. */
    focusSection?: string | null;
    onSectionFocused?: () => void;
  }

  let { onSaved, focusSection = null, onSectionFocused }: Props = $props();

  let config = $state<Config | null>(null);
  let presets = $state<ProviderPreset[]>([]);
  let error = $state("");
  let saveError = $state("");
  let saveSuccess = $state("");
  let saving = $state(false);
  let demoMode = $state(false);
  /** Bumped on load so the sections start again from the loaded config. */
  let generation = $state(0);
  /** Tracks the database URL at load so Save can warn only when it changed. */
  let loadedDatabaseUrl = $state("");
  /** The payload as last loaded or saved: `dirty` is "the payload differs". */
  let snapshot = $state("");
  const dirty = $derived(!!config && JSON.stringify(payloadOf(config)) !== snapshot);
  const dbChanged = $derived(!!config && (config.database_url ?? "") !== loadedDatabaseUrl);

  onMount(() => {
    loadPresets();
    load();
    detectDemoMode().then((v) => {
      if (v) demoMode = true;
    });
  });

  async function loadPresets() {
    try {
      presets = await invoke<ProviderPreset[]>("get_provider_presets");
    } catch (e) {
      error = `Could not load the provider list: ${e}`;
    }
  }

  async function load() {
    if (!isTauri()) return;
    try {
      const data = await invoke<unknown>("get_config");
      const loaded =
        data && typeof data === "object" && !Array.isArray(data) ? (data as Config) : null;
      if (loaded) {
        // null -> "" so text fields bind directly; Save sends "" to clear.
        loaded.guard_llm_backend = loaded.guard_llm_backend ?? "";
        loaded.guard_llm_model = loaded.guard_llm_model ?? "";
        loaded.show_developer_tools = loaded.show_developer_tools ?? false;
        loaded.ollama_base_url = loaded.ollama_base_url ?? "";
        loaded.openai_base_url = loaded.openai_base_url ?? "";
        loaded.ollama_model = loaded.ollama_model ?? "";
        loadedDatabaseUrl = loaded.database_url ?? "";
        snapshot = JSON.stringify(payloadOf(loaded));
      }
      config = loaded;
      generation++;
      error = "";
      saveError = "";
    } catch (e) {
      error = String(e);
    }
  }

  /** What Save sends. Text settings go as "" when emptied: the server then
   *  removes them (back to the environment or default); undefined would keep
   *  the old value. `agent_allowed_domains` is carried through unchanged: the
   *  field left this screen in 0.8 (Tripwire's list is the one enforced), but
   *  a value an older build saved must not be dropped by a save here. */
  function payloadOf(c: Config) {
    return {
      database_url: c.database_url ?? "",
      llm_backend: c.llm_backend || undefined,
      ollama_base_url: c.ollama_base_url ?? "",
      openai_base_url: c.openai_base_url ?? "",
      ollama_model: c.ollama_model ?? "",
      guard_required: c.guard_required ?? undefined,
      guard_llm_backend: c.guard_llm_backend ?? "",
      guard_llm_model: c.guard_llm_model ?? "",
      max_steps: c.max_steps ?? undefined,
      agent_allowed_domains: c.agent_allowed_domains?.length ? c.agent_allowed_domains : undefined,
      show_developer_tools: c.show_developer_tools ?? false,
    };
  }

  function discard() {
    saveError = "";
    saveSuccess = "";
    load();
  }

  async function save() {
    if (!isTauri() || !config) return;
    saving = true;
    saveError = "";
    saveSuccess = "";
    try {
      if (config.guard_required && (!config.guard_llm_backend || !config.guard_llm_model)) {
        throw new Error(
          "The semantic guard is on but has no model. Choose the guard's provider and model, or turn the guard off.",
        );
      }
      const payload = payloadOf(config);
      const needsRestart = dbChanged;
      await invoke("save_config", { payload });
      saveSuccess = needsRestart
        ? "Saved. Restart the app for the new database URL to take effect."
        : "Saved. New sessions use this.";
      loadedDatabaseUrl = config.database_url ?? "";
      snapshot = JSON.stringify(payload);
      onSaved?.();
      setTimeout(() => {
        saveSuccess = "";
      }, 5000);
    } catch (e) {
      saveError = e instanceof Error ? e.message : String(e);
    } finally {
      saving = false;
    }
  }

  function jump(id: string) {
    const el = document.getElementById(id);
    el?.scrollIntoView({ behavior: "smooth", block: "start" });
    el?.focus({ preventScroll: true });
  }

  // The on-page index, derived from settingsSearch's section list rather
  // than its own copy: a second list of the same six ids is exactly the kind
  // of drift the comment at the top of ui/index.ts warns about, and it had
  // already happened ("Environment" here vs. "From the environment" there).
  const NAV_LABEL_OVERRIDES: Record<string, string> = { "settings-environment": "Environment" };
  const SECTIONS = SETTINGS_SECTIONS.map((s) => ({ id: s.id, label: NAV_LABEL_OVERRIDES[s.id] ?? s.label }));

  let searchQuery = $state("");
  const filtered = $derived(filterSettingsSections(SETTINGS_SECTIONS, searchQuery));
  const filterById = $derived(new Map(filtered.map((f) => [f.id, f])));
  const anyVisible = $derived(filtered.some((f) => f.visible));

  function isVisible(id: string): boolean {
    return filterById.get(id)?.visible ?? true;
  }
  function fieldsFor(id: string): Set<string> | null {
    return filterById.get(id)?.visibleFields ?? null;
  }

  function clearSearch() {
    searchQuery = "";
  }

  // The palette lands here with a section id; once that section's element
  // exists (config loaded, search not hiding it), scroll to and focus it.
  $effect(() => {
    if (!focusSection || !config) return;
    if (searchQuery) searchQuery = "";
    const id = focusSection;
    queueMicrotask(() => jump(id));
    onSectionFocused?.();
  });
</script>

<div class="grid grid-cols-1 lg:grid-cols-[180px_minmax(0,760px)] gap-8 min-w-0 pb-6">
  <!-- In-page index: six sections in one scroll had no way in but the top. -->
  <nav class="hidden lg:flex flex-col gap-0.5 sticky top-0 self-start" aria-label="On this page">
    {#each SECTIONS as sct}
      {#if isVisible(sct.id)}
        <a
          href="#{sct.id}"
          class="block px-3 py-1.5 rounded-lg text-sm text-text-secondary hover:bg-surface-elevated hover:text-text-primary no-underline"
          onclick={(e) => { e.preventDefault(); jump(sct.id); }}
        >{sct.label}</a>
      {/if}
    {/each}
    {#if demoMode}
      <a href="#settings-danger" class="block px-3 py-1.5 rounded-lg text-sm text-danger-text hover:bg-danger-muted/30 no-underline" onclick={(e) => { e.preventDefault(); jump("settings-danger"); }}>Danger zone</a>
    {/if}
  </nav>

  <div class="flex flex-col gap-5 min-w-0">
    <div>
      <h2 class="text-xl font-semibold text-text-primary tracking-tight m-0">Settings</h2>
      <p class="text-sm text-text-secondary leading-relaxed mt-1 mb-0 break-words">
        Saved to <InlineCode>settings.json</InlineCode> in the app data directory. Model and guard changes apply to new sessions at once; a database change takes effect after a restart.
      </p>
    </div>

    <div class="relative min-w-0 max-w-sm">
      <label for="settings-search" class="sr-only">Search settings</label>
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" aria-hidden="true">
        <circle cx="11" cy="11" r="7" stroke-linecap="round" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" stroke-linecap="round" />
      </svg>
      <Input
        id="settings-search"
        bind:value={searchQuery}
        placeholder="Search settings…"
        suggestions={false}
        class="pl-9"
        onkeydown={(e) => { if (e.key === "Escape" && searchQuery) { e.preventDefault(); clearSearch(); } }}
      />
    </div>

    {#if error}
      <p class="text-danger-text text-sm break-words">{error}</p>
    {:else if config}
      {#if searchQuery && !anyVisible}
        <p class="text-sm text-text-secondary leading-relaxed">
          No settings match "{searchQuery}".
          <button type="button" class="text-accent-text hover:underline bg-transparent border-none cursor-pointer p-0 text-sm" onclick={clearSearch}>Clear search</button>
        </p>
      {/if}
      <!-- `hidden`, not `{#if}`: unmounting ModelSection/GuardSection on every
           keystroke re-ran their $effects and refetched the model list from
           the provider each time a search toggled them back into view. -->
      <form class="flex flex-col gap-5 min-w-0" onsubmit={(e) => { e.preventDefault(); save(); }}>
        {#key generation}
          <div hidden={!isVisible("settings-ledger")}>
            <LedgerSection bind:config={config!} visibleFields={fieldsFor("settings-ledger")} />
          </div>
          <div hidden={!isVisible("settings-model")}>
            <ModelSection bind:config={config!} {presets} visibleFields={fieldsFor("settings-model")} />
          </div>
          <div hidden={!isVisible("settings-guard")}>
            <GuardSection bind:config={config!} {presets} visibleFields={fieldsFor("settings-guard")} />
          </div>
          <div hidden={!isVisible("settings-agent")}>
            <AgentSection bind:config={config!} visibleFields={fieldsFor("settings-agent")} />
          </div>
          <div hidden={!isVisible("settings-desktop")}>
            <DesktopSection bind:config={config!} visibleFields={fieldsFor("settings-desktop")} />
          </div>
          <div hidden={!isVisible("settings-environment")}>
            <EnvironmentSection config={config!} visibleFields={fieldsFor("settings-environment")} />
          </div>
        {/key}

        {#if saveError}
          <p class="text-danger-text text-sm m-0 break-words" role="alert">{saveError}</p>
        {:else if saveSuccess}
          <p class="text-success text-sm m-0 break-words" role="status">{saveSuccess}</p>
        {/if}
        <button type="submit" class="sr-only" tabindex="-1" aria-hidden="true">Save</button>
      </form>
    {:else}
      <p class="text-text-secondary text-sm">Loading…</p>
    {/if}

    {#if demoMode}
      <DangerZone />
    {/if}

    <SaveBar
      {dirty}
      {saving}
      warn={dbChanged}
      message={dbChanged ? "Database for the next start changed. Saving keeps the current ledger running until you restart." : "Changes apply to new sessions once saved."}
      onsave={save}
      ondiscard={discard}
    />
  </div>
</div>
