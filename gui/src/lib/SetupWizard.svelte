<!--
  SetupWizard - the first-launch wizard (six steps).
  Step 0: Auto-detection  Step 1: Express vs Custom
  Step 2: Database        Step 3: LLM Provider
  Step 4: Model Selection Step 5: Provisioning

  Each step's markup lives in `./setup/`; the express/custom/cloud branching
  that decides what the next step is and what gets saved lives in
  `./setup/wizardFlow.ts`, which is unit tested on its own.
-->
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onDestroy, onMount } from "svelte";
  import type { DbMode, LlmProvider, SetupPath, SystemState } from "./setup/types";
  import { usesLocalOllama, osLabel as osLabelFor, buildSetupConfig } from "./setup/wizardFlow";
  import StepProgress from "./setup/StepProgress.svelte";
  import DetectingStep from "./setup/DetectingStep.svelte";
  import PathStep from "./setup/PathStep.svelte";
  import DatabaseStep from "./setup/DatabaseStep.svelte";
  import ProviderStep from "./setup/ProviderStep.svelte";
  import ModelStep from "./setup/ModelStep.svelte";
  import ProvisioningStep from "./setup/ProvisioningStep.svelte";

  interface Props {
    serverUrl: string;
    onComplete: () => void;
  }

  let { serverUrl, onComplete }: Props = $props();

  let step = $state(0);                          // 0..5
  let path = $state<SetupPath>("express");
  let dbMode = $state<DbMode>("postgres");
  let llmProvider = $state<LlmProvider>("ollama_existing");
  let pgUrl = $state("postgres://ectoledger:ectoledger@localhost:5432/ectoledger");
  let ollamaHost = $state("http://127.0.0.1:11434");
  // Hosted providers: the key goes to the OS credential store (ApiKeyField),
  // the model is chosen from what the provider lists once the key is saved.
  let cloudModels = $state<string[]>([]);
  let cloudModel = $state("");
  let cloudModelsLoading = $state(false);
  let cloudModelsError = $state("");
  const isCloud = $derived(llmProvider === "anthropic" || llmProvider === "openai");
  let selectedModel = $state("");

  let systemState = $state<SystemState | null>(null);
  let detectionError = $state("");

  let provisioning = $state(false);
  let provisionLog = $state<string[]>([]);
  let provisionError = $state("");
  let done = $state(false);

  let models = $state<string[]>([]);

  // Track active Tauri event listeners for cleanup on component destroy.
  let _activeUnlisteners: Array<() => void> = [];
  let _alive = true;

  onDestroy(() => {
    _alive = false;
    for (const fn of _activeUnlisteners) fn();
    _activeUnlisteners = [];
  });

  onMount(() => {
    runDetection();
  });

  async function runDetection() {
    detectionError = "";
    try {
      const state = await invoke<SystemState>("detect_system_state");
      systemState = state;
      selectedModel = state.recommended_model;
      step = 1;
    } catch (e) {
      detectionError = e instanceof Error ? e.message : String(e);
    }
  }

  // Called explicitly whenever navigation lands on step 3 (see next/prev).
  function maybeLoadOllamaModels() {
    if (step === 3 && systemState?.ollama_running) loadOllamaModels();
  }

  async function loadOllamaModels() {
    try {
      const raw = await invoke<{ models?: Array<{ name?: string }> }>("get_ollama_models", {
        args: {},
      });
      const ms: string[] = (raw?.models ?? []).map((m) => m.name ?? "").filter(Boolean);
      if (ms.length > 0) {
        models = ms;
        if (!selectedModel || !ms.includes(selectedModel)) selectedModel = ms[0];
      }
    } catch { /* ignore */ }
  }

  async function loadCloudModels() {
    if (!isCloud) return;
    cloudModelsLoading = true;
    cloudModelsError = "";
    try {
      cloudModels = await invoke<string[]>("get_provider_models", {
        args: { provider: llmProvider, baseUrl: null, apiKey: null },
      });
    } catch (e) {
      cloudModels = [];
      cloudModelsError = String(e);
    } finally {
      cloudModelsLoading = false;
    }
  }

  // A hosted provider's list needs its key; try when it is chosen (the key
  // may already be stored or in the environment).
  $effect(() => {
    if (isCloud) {
      cloudModel = "";
      void loadCloudModels();
    }
  });

  function selectPath(p: SetupPath) {
    path = p;
  }

  function selectDbMode(m: DbMode) {
    dbMode = m;
  }

  function selectProvider(p: LlmProvider) {
    llmProvider = p;
  }

  function selectModel(id: string) {
    selectedModel = id;
  }

  function next() {
    if (path === "express") {
      if (step === 1) { step = 5; runProvisioning(); }
    } else {
      if (step < 5) step++;
      // Step 4 is Ollama model selection. Skipped on the cloud path, mirroring
      // `prev()`, which already skipped it going backwards - so the step was
      // shown on the way in and hidden on the way out.
      if (step === 4 && !usesLocalOllama(path, systemState, llmProvider)) step++;
      if (step === 5) runProvisioning();
    }
    maybeLoadOllamaModels();
  }

  function prev() {
    if (step <= 1) return;
    if (path === "express" && step === 5) { step = 1; return; }
    step--;
    if (step === 4 && !usesLocalOllama(path, systemState, llmProvider)) step--;
    maybeLoadOllamaModels();
  }

  async function runProvisioning() {
    step = 5;
    provisioning = true;
    provisionLog = [];
    provisionError = "";

    if (path === "custom" && llmProvider === "ollama_install") {
      provisionLog = [...provisionLog, "Starting Ollama installation…"];
      const unlisten = await listen<{ line: string }>("install_ollama_progress", (ev) => {
        if (!_alive) return;
        provisionLog = [...provisionLog, ev.payload.line];
      });
      _activeUnlisteners.push(unlisten);
      try {
        await invoke("install_ollama");
        provisionLog = [...provisionLog, "✓ Ollama installed."];
      } catch (e) {
        provisionError = `Ollama install failed: ${e}`;
        provisioning = false;
        unlisten();
        return;
      }
      unlisten();
    }

    // Only when a local model will actually be loaded: `selectedModel` is
    // pre-filled before the provider is chosen.
    if (usesLocalOllama(path, systemState, llmProvider) && selectedModel) {
      provisionLog = [...provisionLog, `Pulling model ${selectedModel}…`];
      const unlisten2 = await listen<{ line: string }>("pull_model_progress", (ev) => {
        if (!_alive) return;
        provisionLog = [...provisionLog, ev.payload.line];
      });
      _activeUnlisteners.push(unlisten2);
      try {
        await invoke("pull_model", { modelName: selectedModel });
        provisionLog = [...provisionLog, `✓ Model ${selectedModel} ready.`];
      } catch (e) {
        provisionLog = [...provisionLog, `Warning: pull failed - ${e}`];
      }
      unlisten2();
    }

    try {
      const { config, logLines } = buildSetupConfig({
        path,
        dbMode,
        llmProvider,
        pgUrl,
        ollamaHost,
        selectedModel,
        cloudModel,
        isCloud,
        usesLocalOllama: usesLocalOllama(path, systemState, llmProvider),
      });
      provisionLog = [...provisionLog, ...logLines];
      await invoke("save_config", { payload: config });
      provisionLog = [...provisionLog, "✓ Configuration saved."];
    } catch (e: unknown) {
      const msg = typeof e === "string" ? e : (e instanceof Error ? e.message : String(e));
      provisionError = msg || "Configuration could not be saved.";
      provisioning = false;
      return;
    }

    try { await invoke("mark_setup_complete"); } catch { /* non-fatal */ }
    provisionLog = [...provisionLog, "✓ Setup complete."];
    provisioning = false;
    done = true;
  }

  const osLabel = $derived(osLabelFor(systemState));
</script>

<div class="flex items-center justify-center min-h-screen w-screen bg-background p-6">
  <div class="w-full max-w-2xl mx-auto animate-fade-in">

    {#if step > 0}
      <StepProgress {step} />
    {/if}

    {#if step === 0}
      <DetectingStep {detectionError} onRetry={runDetection} />
    {:else if step === 1}
      <PathStep {systemState} {osLabel} {path} onSelectPath={selectPath} onNext={next} />
    {:else if step === 2}
      <DatabaseStep {dbMode} bind:pgUrl onSelectMode={selectDbMode} onNext={next} onBack={prev} />
    {:else if step === 3}
      <ProviderStep
        {llmProvider}
        {systemState}
        bind:ollamaHost
        {isCloud}
        bind:cloudModel
        {cloudModels}
        {cloudModelsLoading}
        {cloudModelsError}
        onSelectProvider={selectProvider}
        onLoadCloudModels={loadCloudModels}
        onNext={next}
        onBack={prev}
      />
    {:else if step === 4}
      <ModelStep {models} {selectedModel} {systemState} {llmProvider} onSelect={selectModel} onNext={next} onBack={prev} />
    {:else if step === 5}
      <ProvisioningStep {done} {provisioning} {provisionError} {provisionLog} {path} {dbMode} {pgUrl} onBack={prev} onRetry={runProvisioning} {onComplete} />
    {/if}

  </div>
</div>
