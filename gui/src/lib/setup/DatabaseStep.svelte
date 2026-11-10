<!-- DatabaseStep (2, Custom): where the ledger is stored. -->
<script lang="ts">
  import { Button, Card, Badge, Input } from "../ui";
  import type { DbMode } from "./types";

  interface Props {
    dbMode: DbMode;
    pgUrl: string;
    onSelectMode: (mode: DbMode) => void;
    onNext: () => void;
    onBack: () => void;
  }

  let { dbMode, pgUrl = $bindable(""), onSelectMode, onNext, onBack }: Props = $props();
</script>

<Card title="Database Backend" subtitle="Where should IronVise store its ledger?">
  {#snippet children()}
    <div class="space-y-3 mb-6">
      {#each [
        { id: "postgres", label: "PostgreSQL", desc: "Production scale and multi-agent orchestration (orchestrate / diff-audit / red-team). Provide a connection URL (or let the CLI start embedded Postgres).", badge: "Production", badgeVariant: "success" },
        { id: "sqlite",   label: "SQLite (Embedded)", desc: "File-based, zero config. Audits, History, Policy, Tripwire, and certificate export - no database server required.", badge: null, badgeVariant: "" },
        { id: "memory",   label: "In-Memory", desc: "Data is lost on restart. For testing only.", badge: "Testing only", badgeVariant: "warning" },
      ] as opt}
        <button
          class="w-full text-left p-6 rounded-2xl border transition-all duration-200 cursor-pointer
            {dbMode === opt.id ? 'border-accent bg-accent-muted shadow-md' : 'border-border-muted/30 bg-surface-elevated hover:border-border-muted/60 shadow-sm'}"
          onclick={() => onSelectMode(opt.id as DbMode)}
        >
          <div class="flex items-center gap-2 mb-1">
            <span class="font-medium text-text-primary text-sm">{opt.label}</span>
            {#if opt.badge}
              <Badge variant={opt.badgeVariant as 'success' | 'warning'}>{#snippet children()}{opt.badge}{/snippet}</Badge>
            {/if}
          </div>
          <p class="text-xs text-text-secondary">{opt.desc}</p>
          {#if opt.id === "postgres" && dbMode === "postgres"}
            <Input bind:value={pgUrl} placeholder="postgresql://user:pass@host:5432/dbname" class="mt-3" />
          {/if}
        </button>
      {/each}
    </div>
    <div class="flex justify-between">
      <Button variant="ghost" onclick={onBack}>{#snippet children()}Back{/snippet}</Button>
      <Button variant="primary" onclick={onNext}>{#snippet children()}Continue →{/snippet}</Button>
    </div>
  {/snippet}
</Card>
