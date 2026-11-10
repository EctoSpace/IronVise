<!-- StatusTiles: three numbers a first-time evaluator can read. Everything
     else stays in Prometheus. There is no whole-chain verdict: nothing
     verifies every session on a timer; Verify is per session, in History. -->
<script lang="ts">
  interface Props {
    summary: { sessions: number; denials: number; events: number } | null;
    error: string;
  }

  let { summary, error }: Props = $props();
</script>

{#if error && !error.includes("rate limit") && !error.includes("Rate limit")}
  <p class="text-danger text-xs font-mono">{error}</p>
{:else if summary}
  <ul class="list-none grid grid-cols-3 gap-3 m-0 p-0 shrink-0">
    <li class="bg-surface-elevated border border-border-muted/40 rounded-xl px-4 py-3 min-w-0">
      <div class="text-[11px] uppercase tracking-wide text-text-secondary truncate">Sessions</div>
      <div class="text-2xl font-semibold text-text-primary tabular-nums mt-1 leading-tight">{summary.sessions}</div>
    </li>
    <li class="bg-surface-elevated border border-border-muted/40 rounded-xl px-4 py-3 min-w-0">
      <div class="text-[11px] uppercase tracking-wide text-text-secondary truncate">Denials</div>
      <div class="text-2xl font-semibold text-text-primary tabular-nums mt-1 leading-tight">{summary.denials}</div>
    </li>
    <li class="bg-surface-elevated border border-border-muted/40 rounded-xl px-4 py-3 min-w-0">
      <div class="text-[11px] uppercase tracking-wide text-text-secondary truncate">Events</div>
      <div class="text-2xl font-semibold text-text-primary tabular-nums mt-1 leading-tight">{summary.events}</div>
    </li>
  </ul>
{:else}
  <p class="text-text-secondary text-xs">Loading…</p>
{/if}
