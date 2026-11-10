<!-- PathStep (1): Express vs Custom setup. -->
<script lang="ts">
  import { Button, Card, Badge } from "../ui";
  import type { SetupPath, SystemState } from "./types";

  interface Props {
    systemState: SystemState | null;
    osLabel: string;
    path: SetupPath;
    onSelectPath: (path: SetupPath) => void;
    onNext: () => void;
  }

  let { systemState, osLabel, path, onSelectPath, onNext }: Props = $props();
</script>

<Card title="Welcome to IronVise" subtitle="How would you like to set up?">
  {#snippet children()}
    {#if systemState}
      <p class="inline-flex items-center gap-2 text-xs text-text-secondary font-mono bg-background border border-border-muted/40 rounded-lg px-3 py-1.5 mb-5">Detected <span class="text-text-primary">{osLabel}</span></p>
    {/if}
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-10">
      <button
        class="text-left p-7 rounded-2xl border transition-all duration-200 cursor-pointer
          {path === 'express' ? 'border-accent bg-accent-muted shadow-md ring-2 ring-accent/20' : 'border-border-muted/40 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
        onclick={() => onSelectPath("express")}
      >
        <div class="flex items-center gap-2 mb-2">
          <span class="font-semibold text-text-primary">Express</span>
          <Badge variant="success">{#snippet children()}Recommended{/snippet}</Badge>
        </div>
        <p class="text-xs text-text-secondary leading-relaxed">
          Local SQLite + {systemState?.recommended_model ?? "a local model"}.
          Run audits from Home, configure Policy and Tripwire, export certificates - no database server required.
        </p>
      </button>
      <button
        class="text-left p-7 rounded-2xl border transition-all duration-200 cursor-pointer
          {path === 'custom' ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
        onclick={() => onSelectPath("custom")}
      >
        <div class="flex items-center gap-2 mb-2">
          <span class="font-semibold text-text-primary">Custom Setup</span>
        </div>
        <p class="text-xs text-text-secondary leading-relaxed">
          Choose SQLite or PostgreSQL, LLM provider, and model. SQLite is enough for single-machine audits; pick PostgreSQL for multi-agent orchestration at scale.
        </p>
      </button>
    </div>
    <div class="flex justify-end mt-6">
      <Button variant="primary" onclick={onNext}>
        {#snippet children()}{path === "express" ? "Launch Express Setup" : "Continue →"}{/snippet}
      </Button>
    </div>
  {/snippet}
</Card>
