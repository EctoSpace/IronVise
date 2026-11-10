<!-- ProvisioningStep (5): saving the configuration, with Ollama's install/pull
     progress streamed in above it when those ran. -->
<script lang="ts">
  import { Button, Card } from "../ui";
  import type { DbMode, SetupPath } from "./types";

  interface Props {
    done: boolean;
    provisioning: boolean;
    provisionError: string;
    provisionLog: string[];
    path: SetupPath;
    dbMode: DbMode;
    pgUrl: string;
    onBack: () => void;
    onRetry: () => void;
    onComplete: () => void;
  }

  let { done, provisioning, provisionError, provisionLog, path, dbMode, pgUrl, onBack, onRetry, onComplete }: Props = $props();
</script>

<Card title="Setting Up IronVise" subtitle={done ? "All done!" : provisioning ? "Working…" : provisionError ? "Error" : "Provisioning"}>
  {#snippet children()}
    <div class="bg-background rounded-xl border border-border-muted/30 p-5 font-mono text-xs text-text-secondary h-48 overflow-y-auto flex flex-col gap-1.5 mb-5">
      {#if provisionLog.length === 0 && provisioning}
        <span class="text-text-muted animate-pulse">Starting provisioning…</span>
      {:else}
        {#each provisionLog as line}
          <span class="{line.startsWith('✓') ? 'text-success' : line.startsWith('Warning') ? 'text-warning' : 'text-text-secondary'}">{line}</span>
        {/each}
        {#if provisioning}<span class="text-accent-text animate-pulse">▌</span>{/if}
      {/if}
    </div>
    {#if provisionError}
      <div class="p-3 rounded-lg bg-danger-muted border border-danger/30 text-sm text-danger mb-4">
        <p class="font-medium mb-1">Something went wrong</p>
        <p class="text-text-secondary">{provisionError}</p>
        <p class="mt-2 text-text-muted text-xs">You can retry below or open Settings after setup to try again.</p>
      </div>
      <div class="flex justify-between">
        <Button variant="ghost" onclick={onBack}>{#snippet children()}Back{/snippet}</Button>
        <Button variant="primary" onclick={onRetry}>{#snippet children()}Retry{/snippet}</Button>
      </div>
    {:else if done}
      <div class="p-3 rounded-lg bg-success-muted border border-success/30 text-sm text-success mb-4">
        <p class="font-medium m-0">IronVise is ready</p>
        <p class="text-text-secondary text-xs mt-2 mb-0 leading-relaxed">
          {#if path === "custom" && dbMode === "postgres" && pgUrl}
            Restart the app so the Postgres URL takes effect, then on Home enter a goal and press Run.
          {:else}
            On Home enter a goal and press Run. Policy, Tripwire, History, and certificate export work on the embedded SQLite ledger.
            Use PostgreSQL when you need multi-agent orchestration at scale.
          {/if}
        </p>
      </div>
      <div class="flex justify-end">
        <Button variant="success" onclick={onComplete}>{#snippet children()}Go to Home →{/snippet}</Button>
      </div>
    {:else if provisioning}
      <div class="flex justify-center">
        <div class="h-5 w-5 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
      </div>
    {/if}
  {/snippet}
</Card>
