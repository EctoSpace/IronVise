<!--
  GuardSection: the semantic guard switch, its provider and its model.

  The server requires the guard's provider and model explicitly: a guard is a
  deliberate, separate choice, not the agent's model by default. So there is
  no "same as the agent" option; turning the guard on fills in the agent's
  provider as a starting point, and Settings refuses to save a guard with no
  model. The desktop app runs the guard worker itself (`<app> --guard-worker`).
-->
<script lang="ts">
  import { untrack } from "svelte";
  import { InlineCode, Switch } from "../ui";
  import ModelSelect from "./ModelSelect.svelte";
  import { SELECT_CLASS } from "./selectClass";
  import { listModels } from "./providers";
  import { type Config, type ProviderPreset, LABEL_CLASS, SECTION_CLASS, SECTION_TITLE_CLASS } from "./types";

  interface Props {
    config: Config;
    presets: ProviderPreset[];
    visibleFields?: Set<string> | null;
  }

  let { config = $bindable(), presets, visibleFields = null }: Props = $props();

  function shows(field: string): boolean {
    return !visibleFields || visibleFields.has(field);
  }

  let models = $state<string[]>([]);
  let loading = $state(false);
  let error = $state("");
  let request = 0;

  async function loadModels() {
    error = "";
    const mine = ++request;
    models = [];
    if (!config.guard_llm_backend) return;
    loading = true;
    try {
      const listed = await listModels(config, presets, config.guard_llm_backend);
      if (mine === request) models = listed;
    } catch (e) {
      if (mine === request) error = String(e);
    } finally {
      if (mine === request) loading = false;
    }
  }

  // Turning the guard on with no provider chosen starts from the agent's.
  $effect(() => {
    if (config.guard_required && !config.guard_llm_backend && config.llm_backend) {
      untrack(() => {
        config.guard_llm_backend = config.llm_backend;
      });
    }
  });

  // The list follows the switch and the guard's provider.
  $effect(() => {
    const on = config.guard_required;
    const provider = config.guard_llm_backend;
    const ready = presets.length > 0;
    untrack(() => {
      if (on && provider && ready) void loadModels();
    });
  });
</script>

<section id="settings-guard" tabindex="-1" class={SECTION_CLASS}>
  <div class="flex items-start justify-between gap-4 min-w-0">
    <div class="min-w-0">
      <h3 class={SECTION_TITLE_CLASS}>Semantic guard</h3>
      <p id="settings-guard-label" class="text-base font-semibold text-text-primary mt-1.5 mb-0">Judge each tool call with a model before it runs</p>
    </div>
    <Switch id="settings-guard-required" bind:checked={config.guard_required} labelledby="settings-guard-label" />
  </div>
  <p class="text-sm text-text-secondary leading-relaxed m-0 break-words">
    On top of tripwire and policy rules, a second model reads each proposed action against the session goal and can refuse it. Cost: one model call per tool call. It runs in a separate process, and it fails closed: while it is on, every action is refused if its model cannot be reached. A small model also refuses harmless commands now and then; tripwire and policy rules do not.
  </p>
  {#if config.guard_required_source}
    <p class="text-xs text-text-muted leading-relaxed m-0 break-words">
      Effective value from: {config.guard_required_source}.
      {#if config.guard_required_source.startsWith("environment and settings file disagreed")}
        <span class="text-warning">
          This machine's environment sets <InlineCode>GUARD_REQUIRED</InlineCode>, and a security control is resolved most-restrictive-wins, so turning this off here will not turn the guard off. Unset the environment variable if this switch should decide.
        </span>
      {/if}
    </p>
  {/if}
  {#if config.guard_required}
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 min-w-0">
      {#if shows("Guard provider")}
        <div class="min-w-0">
          <label for="settings-guard-backend" class={LABEL_CLASS}>Guard provider</label>
          <select id="settings-guard-backend" class={SELECT_CLASS} bind:value={config.guard_llm_backend}>
            {#if !config.guard_llm_backend}
              <option value="" disabled>Choose a provider</option>
            {/if}
            {#each presets as p}
              <option value={p.id}>{p.label}</option>
            {/each}
            {#if config.guard_llm_backend && !presets.find((p) => p.id === config.guard_llm_backend)}
              <option value={config.guard_llm_backend}>{config.guard_llm_backend} (custom)</option>
            {/if}
          </select>
        </div>
      {/if}
      {#if shows("Guard model")}
        <div class="min-w-0">
          <label for="settings-guard-model" class={LABEL_CLASS}>Guard model</label>
          <ModelSelect id="settings-guard-model" {models} bind:value={config.guard_llm_model} {loading} onrefresh={loadModels} />
          <p class="text-xs leading-relaxed mt-2 mb-0 break-words {error ? 'text-danger-text' : 'text-text-muted'}">
            {#if error}{error}{:else if !config.guard_llm_model}The guard needs its own model; choose one. A small, fast model is enough; it answers allow or deny.{:else}A small, fast model is enough; it answers allow or deny.{/if}
          </p>
        </div>
      {/if}
    </div>
  {/if}
</section>
