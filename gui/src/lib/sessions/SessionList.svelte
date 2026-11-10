<!-- SessionList: the Audit History sidebar - status filter, session rows,
     and pagination. -->
<script lang="ts">
  import type { SessionSummary } from "../backend";

  interface Props {
    sessions: SessionSummary[];
    selected: string | null;
    loading: boolean;
    sessionError: string;
    statusFilter: string;
    offset: number;
    more: boolean;
    onRefresh: () => void;
    onFilterChange: () => void;
    onSelect: (id: string) => void;
    onPrev: () => void;
    onNext: () => void;
  }

  let {
    sessions,
    selected,
    loading,
    sessionError,
    statusFilter = $bindable(""),
    offset,
    more,
    onRefresh,
    onFilterChange,
    onSelect,
    onPrev,
    onNext,
  }: Props = $props();

  function statusClass(status: string): string {
    if (status === "completed") return "bg-success-muted text-success";
    if (status === "running") return "bg-accent-muted text-accent-text";
    if (status === "failed" || status === "aborted" || status === "denied") return "bg-danger-muted text-danger-text";
    return "bg-surface-elevated text-text-secondary";
  }
</script>

<aside class="bg-surface rounded-2xl w-80 min-w-80 p-5 overflow-y-auto shadow-sm flex flex-col gap-4">
  <div class="flex justify-between items-center">
    <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted">Audit History</h2>
    <!-- The visible content is one glyph, so without an explicit name a
         screen reader announces this as "button" and nothing else. -->
    <button
      class="bg-transparent border border-border-muted/30 rounded-xl text-accent-text px-3 py-1.5 text-sm cursor-pointer hover:bg-surface-elevated transition-all duration-200"
      aria-label="Refresh audit history"
      title="Refresh audit history"
      onclick={onRefresh}
    ><span aria-hidden="true">↻</span></button>
  </div>
  <div class="flex items-center gap-3">
    <label for="status-filter" class="text-sm text-text-muted whitespace-nowrap">Status</label>
    <select id="status-filter" class="flex-1 bg-surface-elevated border border-border-muted rounded-xl px-3 py-2 text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200" bind:value={statusFilter} onchange={onFilterChange}>
      <option value="">All</option>
      <option value="running">Running</option>
      <option value="completed">Completed</option>
      <option value="failed">Failed</option>
      <option value="aborted">Aborted</option>
    </select>
  </div>

  {#if sessionError}
    <p class="text-danger text-sm">{sessionError}</p>
  {/if}
  {#if loading}
    <p class="text-text-muted text-sm">Loading…</p>
  {:else if sessions.length === 0 && !sessionError}
    <div class="text-sm text-text-muted leading-relaxed">
      <p>No sessions yet.</p>
      <p class="mt-2 text-xs">Run a goal from Home, or route an agent through the Claude Code hook or an SDK. Every session lands here with its signed ledger.</p>
    </div>
  {:else}
    <ul class="list-none flex flex-col gap-1">
      {#each sessions as s}
        <!-- The row is a real <button>. A per-row "VC" button used to sit
             beside it; selecting a completed session already loads its
             credential, and the side button dropped its result whenever the
             row was not the selected one, so it is gone. -->
        <li>
          <button
            type="button"
            class="w-full flex flex-col gap-1.5 px-3.5 py-3 border-none rounded-xl text-sm cursor-pointer text-left transition-all duration-200 {selected === s.id ? 'bg-surface-elevated' : 'bg-transparent hover:bg-surface-elevated/60'}"
            aria-pressed={selected === s.id}
            onclick={() => onSelect(s.id)}
          >
            <span class="flex items-center justify-between gap-2 w-full">
              <span class="font-mono text-xs {selected === s.id ? 'text-accent-text' : 'text-text-secondary'}">{s.id.slice(0, 8)}</span>
              <span class="text-[11px] px-2.5 py-0.5 rounded-full font-semibold whitespace-nowrap {statusClass(s.status)}">{s.status}</span>
            </span>
            <span class="text-text-primary text-[13px] leading-snug line-clamp-2">{s.goal || "No goal recorded"}</span>
          </button>
        </li>
      {/each}
    </ul>
  {/if}

  {#if offset > 0 || more}
    <div class="flex gap-2 justify-between mt-auto pt-2">
      <button class="bg-transparent border border-border-muted/30 rounded-xl text-accent-text px-4 py-2 text-xs whitespace-nowrap cursor-pointer hover:bg-surface-elevated transition-all duration-200 disabled:opacity-40 disabled:cursor-default" onclick={onPrev} disabled={offset === 0}>← Newer</button>
      <button class="bg-transparent border border-border-muted/30 rounded-xl text-accent-text px-4 py-2 text-xs whitespace-nowrap cursor-pointer hover:bg-surface-elevated transition-all duration-200 disabled:opacity-40 disabled:cursor-default" onclick={onNext} disabled={!more}>Older →</button>
    </div>
  {/if}
</aside>
