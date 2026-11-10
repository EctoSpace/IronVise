<!-- SessionSidebar: search, status filter pills, and the session list. -->
<script lang="ts">
  import { StatusDot } from "../ui/index.js";
  import { filterSessions, fmtTime } from "./eventRows";
  import type { SessionSummary } from "../backend";

  interface Props {
    sessions: SessionSummary[];
    activeId: string | null;
    sessionsLoading: boolean;
    searchQuery: string;
    statusFilter: string | null;
    onSelectFilter: (f: string | null) => void;
    onSelect: (id: string) => void;
  }

  let {
    sessions,
    activeId,
    sessionsLoading,
    searchQuery = $bindable(""),
    statusFilter,
    onSelectFilter,
    onSelect,
  }: Props = $props();

  const filtered = $derived(filterSessions(sessions, searchQuery));
</script>

<aside class="w-56 min-w-56 flex flex-col border-r border-border-muted/30 bg-surface overflow-hidden">
  <!-- Header -->
  <div class="px-4 pt-4 pb-2">
    <h3 class="text-xs font-semibold uppercase tracking-[0.1em] text-text-secondary m-0 mb-2">Sessions</h3>
    <input
      type="text"
      class="w-full bg-surface-elevated/30 border border-border-muted/25 rounded-lg text-text-primary text-xs px-2.5 py-1.5 outline-none focus:border-accent/50 transition-colors placeholder:text-text-muted"
      placeholder="Search…"
      bind:value={searchQuery}
    />
  </div>

  <!-- Filter pills -->
  <div class="flex gap-1 px-4 pb-2 flex-wrap">
    {#each [null, "running", "completed", "failed"] as f}
      <button
        class="text-[10px] px-2 py-0.5 rounded-full border transition-colors cursor-pointer
          {statusFilter === f
            ? 'bg-accent/15 border-accent/40 text-accent-text font-semibold'
            : 'bg-transparent border-border-muted/30 text-text-muted hover:text-text-secondary hover:border-border-muted/50'}"
        onclick={() => onSelectFilter(f)}
      >
        {f ? f.charAt(0).toUpperCase() + f.slice(1) : "All"}
      </button>
    {/each}
  </div>

  <!-- Session list -->
  <div class="flex-1 overflow-y-auto px-1.5 pb-2">
    {#if sessionsLoading && sessions.length === 0}
      <p class="text-text-muted text-[10px] text-center py-4">Loading…</p>
    {/if}
    {#each filtered as s (s.id)}
      <button
        class="w-full text-left px-2.5 py-2 rounded-lg mb-0.5 border border-transparent transition-colors cursor-pointer
          {activeId === s.id
            ? 'bg-accent/10 border-accent/25'
            : 'bg-transparent hover:bg-surface-elevated/40'}"
        onclick={() => onSelect(s.id)}
      >
        <div class="flex items-center gap-1.5 mb-0.5">
          <StatusDot status={s.status === "running" ? "running" : s.status === "completed" ? "passed" : s.status === "failed" ? "failed" : "idle"} />
          <span class="text-[10px] font-mono text-text-muted">{s.id.slice(0, 8)}…</span>
        </div>
        <p class="text-[11px] text-text-primary m-0 line-clamp-2 leading-snug">{s.goal || "-"}</p>
        <span class="text-[9px] text-text-muted">{fmtTime(s.created_at)}</span>
      </button>
    {/each}
    {#if !sessionsLoading && filtered.length === 0}
      <p class="text-text-muted text-[10px] text-center py-4">No sessions</p>
    {/if}
  </div>
</aside>
