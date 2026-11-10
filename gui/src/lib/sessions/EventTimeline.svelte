<!-- EventTimeline: the selected session's grouped ledger events, each
     collapsible to its occurrences when it repeated. -->
<script lang="ts">
  import type { EventTone } from "../events";
  import type { GroupedEvent } from "./groupEvents";

  interface Props {
    eventsLoading: boolean;
    eventsLength: number;
    groupedEvents: GroupedEvent[];
    expandedKeys: Set<string>;
    onToggleExpanded: (key: string) => void;
  }

  let { eventsLoading, eventsLength, groupedEvents, expandedKeys, onToggleExpanded }: Props = $props();

  /** Left rule and label colour per tone. Refusals are the loudest thing here on purpose. */
  const TONE_CLASS: Record<EventTone, { rule: string; label: string; dot: string }> = {
    neutral:  { rule: "border-l-border",      label: "text-text-secondary", dot: "before:border-border-muted" },
    info:     { rule: "border-l-accent",      label: "text-accent-text",    dot: "before:border-accent" },
    action:   { rule: "border-l-warning/70",  label: "text-warning",        dot: "before:border-warning" },
    success:  { rule: "border-l-success",     label: "text-success",        dot: "before:border-success" },
    warning:  { rule: "border-l-warning",     label: "text-warning",        dot: "before:border-warning" },
    blocked:  { rule: "border-l-danger",      label: "text-danger-text",    dot: "before:border-danger" },
    error:    { rule: "border-l-danger/70",   label: "text-danger-text",    dot: "before:border-danger" },
    evidence: { rule: "border-l-evidence",    label: "text-evidence-text",  dot: "before:border-evidence" },
    chat:     { rule: "border-l-border",      label: "text-text-secondary", dot: "before:border-border-muted" },
  };
</script>

{#if eventsLoading}
  <p class="text-text-muted text-sm">Loading events…</p>
{:else if eventsLength === 0}
  <p class="text-text-muted text-sm">No events for this session.</p>
{:else}
  <!-- A rail joins the events into one line: a ledger reads as a
       sequence, and the first thing a reviewer wants is to see it. -->
  <ul class="flex flex-col gap-3 relative pl-6 before:content-[''] before:absolute before:left-[9px] before:top-3 before:bottom-3 before:w-px before:bg-border-muted/60">
    {#each groupedEvents as g}
      <li class="relative px-5 py-4 flex flex-col gap-2 bg-surface-elevated/20 border border-border-muted/40 border-l-[3px] {TONE_CLASS[g.tone].rule} rounded-xl before:content-[''] before:absolute before:-left-[21px] before:top-[18px] before:w-2.5 before:h-2.5 before:rounded-full before:bg-surface before:border-2 {TONE_CLASS[g.tone].dot}">
        {#if g.count > 1}
          <button
            class="flex items-center gap-2 bg-transparent border-none text-inherit cursor-pointer text-left p-0"
            type="button"
            aria-expanded={expandedKeys.has(g.key)}
            onclick={() => onToggleExpanded(g.key)}
          >
            <span class="font-semibold text-sm {TONE_CLASS[g.tone].label}">{g.label}</span>
            <span class="bg-surface-elevated px-2.5 py-0.5 rounded-xl text-xs text-text-muted">×{g.count}</span>
            <span class="ml-auto text-xs text-text-muted" aria-hidden="true">{expandedKeys.has(g.key) ? "▼" : "▶"}</span>
          </button>
        {:else}
          <div class="flex items-center gap-2">
            <span class="font-semibold text-sm {TONE_CLASS[g.tone].label}">{g.label}</span>
            {#if g.occurrences[0]}
              <span class="ml-auto text-xs text-text-muted font-mono whitespace-nowrap">#{g.occurrences[0].seq} · {g.occurrences[0].timestamp}</span>
            {/if}
          </div>
        {/if}
        <div class="text-sm text-text-primary whitespace-pre-wrap break-words leading-relaxed">{g.content}</div>
        <details class="text-xs text-text-muted">
          <summary class="cursor-pointer select-none w-fit hover:text-text-secondary">Raw payload</summary>
          <pre class="mt-2 bg-background border border-border-muted/30 rounded-lg p-3 font-mono text-[11px] text-text-secondary overflow-x-auto whitespace-pre-wrap">{g.raw}</pre>
        </details>
        {#if expandedKeys.has(g.key) && g.count > 1}
          <div class="mt-2 text-xs">
            <table class="w-full border-collapse">
              <thead>
                <tr>
                  <th class="px-4 py-2.5 text-left border-b border-border-muted/15 text-text-muted font-semibold">Seq</th>
                  <th class="px-4 py-2.5 text-left border-b border-border-muted/15 text-text-muted font-semibold">Time</th>
                  <th class="px-4 py-2.5 text-left border-b border-border-muted/15 text-text-muted font-semibold">Type</th>
                </tr>
              </thead>
              <tbody>
                {#each g.occurrences as occ}
                  <tr>
                    <td class="px-4 py-2.5 text-left border-b border-border-muted/10">{occ.seq}</td>
                    <td class="px-4 py-2.5 text-left border-b border-border-muted/10">{occ.timestamp}</td>
                    <td class="px-4 py-2.5 text-left border-b border-border-muted/10">{occ.type}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </li>
    {/each}
  </ul>
{/if}
