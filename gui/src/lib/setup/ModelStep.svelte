<!-- ModelStep (4): choose the local Ollama model to pull. -->
<script lang="ts">
  import { Button, Card, Badge } from "../ui";
  import type { LlmProvider, SystemState } from "./types";

  interface Props {
    models: string[];
    selectedModel: string;
    systemState: SystemState | null;
    llmProvider: LlmProvider;
    onSelect: (id: string) => void;
    onNext: () => void;
    onBack: () => void;
  }

  let { models, selectedModel, systemState, llmProvider, onSelect, onNext, onBack }: Props = $props();

  const modelCards = $derived(
    models.length > 0
      ? models.map((m) => ({ id: m, label: m }))
      : [
          { id: "llama3.2:3b", label: "Llama 3.2 3B - lightweight, fast" },
          { id: "llama3.1:8b", label: "Llama 3.1 8B - balanced" },
          { id: "llama3.3:70b-instruct-q4_K_M", label: "Llama 3.3 70B - highest quality" },
        ],
  );
</script>

<Card title="Model Selection" subtitle="Choose the model IronVise will use.">
  {#snippet children()}
    <div class="space-y-2 mb-6">
      {#each modelCards as m}
        <button
          class="w-full text-left p-5 rounded-2xl border transition-all duration-200 cursor-pointer
            {selectedModel === m.id ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
          onclick={() => onSelect(m.id)}
        >
          <div class="flex items-center gap-2">
            <span class="font-mono text-sm text-text-primary">{m.label}</span>
            {#if m.id === systemState?.recommended_model}
              <Badge variant="accent">{#snippet children()}Recommended{/snippet}</Badge>
            {/if}
          </div>
        </button>
      {/each}
    </div>
    <div class="flex justify-between">
      <Button variant="ghost" onclick={onBack}>{#snippet children()}Back{/snippet}</Button>
      <Button variant="primary" onclick={onNext}>
        {#snippet children()}{llmProvider === "ollama_install" ? "Install & Pull Model" : "Pull Model"}{/snippet}
      </Button>
    </div>
  {/snippet}
</Card>
