<!--
  ModelSection: the agent's provider, model, API key and address.

  The model is chosen from what the provider lists (ModelSelect); switching
  provider clears it rather than filling in a default name the provider may
  not have. Hosted providers get an API key field (ApiKeyField, OS credential
  store). Anthropic has no address field: its backend reads only
  ANTHROPIC_BASE_URL.
-->
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { untrack } from "svelte";
  import { InlineCode, Input, Button } from "../ui";
  import ApiKeyField from "./ApiKeyField.svelte";
  import ModelSelect, { listedName } from "./ModelSelect.svelte";
  import { SELECT_CLASS } from "./selectClass";
  import { baseUrlFor, listModels } from "./providers";
  import {
    type Config,
    type ProviderPreset,
    HINT_CLASS,
    LABEL_CLASS,
    SECTION_CLASS,
    SECTION_TITLE_CLASS,
  } from "./types";

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
  let providerErr = $state("");
  let testMsg = $state("");
  let testing = $state(false);
  /** Ignores a slow list for a provider that is no longer selected. */
  let request = 0;
  /** The provider as loaded, so only a real switch resets address and model. */
  let previousProviderId: string | undefined = config.llm_backend;

  const preset = $derived(presets.find((p) => p.id === config.llm_backend) ?? null);
  const isOllama = $derived(config.llm_backend === "ollama");
  const isAnthropic = $derived(config.llm_backend === "anthropic");
  const isOpenAiCloud = $derived(config.llm_backend === "openai");

  const endpointLabel = $derived.by(() => {
    if (isOllama) return "Ollama host";
    if (isOpenAiCloud) return "OpenAI API base";
    if (config.llm_backend === "openai-compatible") return "Custom API base URL";
    if (preset?.transport === "openai-compatible") return `${preset.label} URL`;
    return "API base URL";
  });

  const endpointHint = $derived.by(() => {
    if (isOllama) {
      return "Native Ollama HTTP API (no /v1). Default is http://127.0.0.1:11434. Prefer 127.0.0.1 to localhost: on Windows with WSL, localhost can reach a different Ollama.";
    }
    if (isOpenAiCloud) return "OpenAI Chat Completions base. Leave the default unless you use a proxy.";
    if (preset?.transport === "openai-compatible") {
      return "OpenAI-compatible server. With or without a trailing /v1 - both work.";
    }
    return "";
  });

  const endpointPlaceholder = $derived(
    isOllama ? "http://127.0.0.1:11434" : (preset?.default_base_url ?? "https://…"),
  );

  export async function loadModels() {
    providerErr = "";
    const mine = ++request;
    models = [];
    if (!config.llm_backend || presets.length === 0) return;
    loading = true;
    try {
      const listed = await listModels(config, presets, config.llm_backend);
      if (mine === request) models = listed;
    } catch (e) {
      if (mine === request) providerErr = String(e);
    } finally {
      if (mine === request) loading = false;
    }
  }

  // The list follows the provider, and arrives once the presets have. Only
  // those two are tracked: typing an address does not refetch (Refresh does).
  $effect(() => {
    const provider = config.llm_backend;
    const ready = presets.length > 0;
    untrack(() => {
      if (provider && ready) void loadModels();
    });
  });

  /** A switch puts the new preset's address in place (a leftover Ollama URL
   *  must not sit under LM Studio) and clears the model: it is chosen again
   *  from the new provider's list. */
  function onProviderChange() {
    testMsg = "";
    const nextId = config.llm_backend;
    const next = presets.find((p) => p.id === nextId);
    if (next && nextId !== previousProviderId) {
      if (nextId === "ollama") {
        if (!(config.ollama_base_url ?? "").trim()) {
          config.ollama_base_url = next.default_base_url ?? "http://127.0.0.1:11434";
        }
      } else if (nextId !== "anthropic") {
        config.openai_base_url = next.default_base_url ?? "";
      }
      config.ollama_model = "";
    }
    previousProviderId = nextId;
  }

  async function testConnection() {
    testing = true;
    testMsg = "";
    providerErr = "";
    try {
      testMsg = await invoke<string>("test_provider_connection", {
        args: {
          provider: config.llm_backend ?? "",
          baseUrl: baseUrlFor(config, presets, config.llm_backend ?? ""),
          apiKey: null,
        },
      });
      await loadModels();
    } catch (e) {
      providerErr = String(e);
    } finally {
      testing = false;
    }
  }
</script>

<section id="settings-model" tabindex="-1" class={SECTION_CLASS}>
  <h3 class={SECTION_TITLE_CLASS}>Model</h3>
  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 min-w-0">
    {#if shows("Provider")}
      <div class="min-w-0">
        <label for="settings-llm-provider" class={LABEL_CLASS}>Provider</label>
        <select id="settings-llm-provider" class={SELECT_CLASS} bind:value={config.llm_backend} onchange={onProviderChange}>
          {#each presets as p}
            <option value={p.id}>{p.label}</option>
          {/each}
          {#if config.llm_backend && !presets.find((p) => p.id === config.llm_backend)}
            <option value={config.llm_backend}>{config.llm_backend} (custom)</option>
          {/if}
        </select>
        {#if preset}
          <p class={HINT_CLASS}>
            {#if isOllama}
              Talks to a local Ollama daemon over its native API. No API key for local access.
            {:else if isAnthropic}
              Anthropic's API at api.anthropic.com, with the API key below. Does not connect to Claude Code or the Claude desktop app.
            {:else if isOpenAiCloud}
              OpenAI's API, with the API key below.
            {:else if preset.transport === "openai-compatible"}
              OpenAI-compatible HTTP (LM Studio, llama.cpp, vLLM, …).
            {:else}
              Transport: <InlineCode>{preset.transport}</InlineCode>
            {/if}
          </p>
        {/if}
      </div>
    {/if}
    {#if shows("Model")}
      <div class="min-w-0">
        <label for="settings-llm-model" class={LABEL_CLASS}>Model</label>
        <ModelSelect id="settings-llm-model" {models} bind:value={config.ollama_model} {loading} onrefresh={loadModels} />
        <p class={HINT_CLASS}>
          {#if loading}Asking the provider for its models…{:else if models.length > 0 && !config.ollama_model}Choose the model the agent runs on.{:else if models.length > 0 && !listedName(models, config.ollama_model)}The saved model is not among the ones this provider has. Choose one.{:else if models.length > 0}The chat models this provider has. Embedding models are left out.{:else}This provider listed no models. Start it (and load a model), check the address below, then Refresh.{/if}
        </p>
      </div>
    {/if}
  </div>
  {#if shows("API key") && preset?.api_key_env && preset.api_key_required}
    {#key preset.id}
      <ApiKeyField envName={preset.api_key_env} provider={preset.label} onchange={loadModels} />
    {/key}
  {/if}
  {#if shows("Address")}
    <div class="min-w-0">
      {#if !isAnthropic}
        <label for="settings-llm-endpoint" class={LABEL_CLASS}>{endpointLabel}</label>
      {/if}
      <div class="flex items-stretch gap-2 min-w-0">
        {#if isOllama}
          <Input id="settings-llm-endpoint" class="font-mono text-xs flex-1 min-w-0 sm:max-w-[520px]" bind:value={config.ollama_base_url} placeholder={endpointPlaceholder} />
        {:else if !isAnthropic}
          <Input id="settings-llm-endpoint" class="font-mono text-xs flex-1 min-w-0 sm:max-w-[520px]" bind:value={config.openai_base_url} placeholder={endpointPlaceholder} />
        {/if}
        <Button variant="secondary" size="sm" class={isAnthropic ? "shrink-0" : "shrink-0 self-stretch h-auto"} onclick={testConnection} disabled={testing} loading={testing}>
          {testing ? "Testing…" : "Test connection"}
        </Button>
      </div>
      {#if testMsg}
        <p class="text-xs text-success leading-relaxed mt-2 mb-0 break-words">{testMsg}</p>
      {:else if endpointHint}
        <p class={HINT_CLASS}>{endpointHint}</p>
      {/if}
    </div>
  {/if}
  {#if providerErr}
    <p class="text-xs text-danger-text leading-relaxed m-0 break-words">{providerErr}</p>
  {/if}
</section>
