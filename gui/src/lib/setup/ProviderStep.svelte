<!-- ProviderStep (3, Custom): local Ollama, or a hosted provider with its key and model. -->
<script lang="ts">
  import { Button, Card, Badge, Input } from "../ui";
  import ApiKeyField from "../settings/ApiKeyField.svelte";
  import ModelSelect from "../settings/ModelSelect.svelte";
  import type { LlmProvider, SystemState } from "./types";

  interface Props {
    llmProvider: LlmProvider;
    systemState: SystemState | null;
    ollamaHost: string;
    isCloud: boolean;
    cloudModel: string;
    cloudModels: string[];
    cloudModelsLoading: boolean;
    cloudModelsError: string;
    onSelectProvider: (provider: LlmProvider) => void;
    onLoadCloudModels: () => void;
    onNext: () => void;
    onBack: () => void;
  }

  let {
    llmProvider,
    systemState,
    ollamaHost = $bindable(""),
    isCloud,
    cloudModel = $bindable(""),
    cloudModels,
    cloudModelsLoading,
    cloudModelsError,
    onSelectProvider,
    onLoadCloudModels,
    onNext,
    onBack,
  }: Props = $props();
</script>

<Card title="LLM Provider" subtitle="How will IronVise access a language model?">
  {#snippet children()}
    <div class="space-y-3 mb-6">
      {#each [
        { id: "ollama_install",  label: "Install Ollama Locally",    desc: "Download and install Ollama, then pull a model." },
        { id: "ollama_existing", label: "Connect Existing Local LLM", desc: systemState?.ollama_running ? "Ollama detected at http://127.0.0.1:11434" : "Provide the Ollama base URL." },
        { id: "anthropic",       label: "Anthropic",                  desc: "Anthropic's API, with your API key." },
        { id: "openai",          label: "OpenAI",                     desc: "OpenAI's API, with your API key. Other OpenAI-compatible servers are in Settings." },
      ] as opt}
        <button
          class="w-full text-left p-6 rounded-2xl border transition-all duration-200 cursor-pointer
            {llmProvider === opt.id ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
          aria-pressed={llmProvider === opt.id}
          onclick={() => onSelectProvider(opt.id as LlmProvider)}
        >
          <div class="flex items-center gap-2 mb-1">
            <span class="font-medium text-text-primary text-sm">{opt.label}</span>
            {#if opt.id === "ollama_existing" && systemState?.ollama_running}
              <Badge variant="success">{#snippet children()}Running{/snippet}</Badge>
            {/if}
          </div>
          <p class="text-xs text-text-secondary">{opt.desc}</p>
        </button>
      {/each}
    </div>
    <!-- Fields sit outside the option buttons: a field inside a button is
         not valid HTML and a screen reader cannot reach it. -->
    {#if llmProvider === "ollama_existing" && !systemState?.ollama_running}
      <div class="mb-6">
        <label for="wizard-ollama-host" class="block text-sm font-medium text-text-primary mb-1.5">Ollama host</label>
        <Input id="wizard-ollama-host" bind:value={ollamaHost} placeholder="http://127.0.0.1:11434" />
      </div>
    {:else if isCloud}
      <div class="mb-6 space-y-4">
        {#key llmProvider}
          <ApiKeyField
            envName={llmProvider === "anthropic" ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY"}
            provider={llmProvider === "anthropic" ? "Anthropic" : "OpenAI"}
            onchange={onLoadCloudModels}
          />
        {/key}
        <div>
          <label for="wizard-cloud-model" class="block text-sm font-medium text-text-primary mb-1.5">Model</label>
          <ModelSelect id="wizard-cloud-model" models={cloudModels} bind:value={cloudModel} loading={cloudModelsLoading} onrefresh={onLoadCloudModels} />
          <p class="text-xs leading-relaxed mt-2 mb-0 {cloudModelsError ? 'text-danger-text' : 'text-text-muted'}">
            {#if cloudModelsError}{cloudModelsError}{:else if cloudModels.length === 0}Save the API key to list the models.{:else}Choose the model the agent runs on.{/if}
          </p>
        </div>
      </div>
    {/if}
    <div class="flex justify-between">
      <Button variant="ghost" onclick={onBack}>{#snippet children()}Back{/snippet}</Button>
      <!-- onNext, not a direct step change: the hosted providers skip the Ollama model step. -->
      <Button variant="primary" onclick={onNext} disabled={isCloud && !cloudModel}>{#snippet children()}Continue →{/snippet}</Button>
    </div>
  {/snippet}
</Card>
