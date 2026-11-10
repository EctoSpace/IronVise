<!-- EventTimeline: the active session's events, or its loading/empty state. -->
<script lang="ts">
  import EventCard from "./EventCard.svelte";
  import type { EventRow } from "./eventRows";

  interface Props {
    eventsLoading: boolean;
    events: EventRow[];
    activeStatus: string | undefined;
    verifyResults: Record<number, "pass" | "fail">;
    expandedBodies: Set<number>;
    onToggleBody: (seq: number) => void;
  }

  let { eventsLoading, events, activeStatus, verifyResults, expandedBodies, onToggleBody }: Props = $props();
</script>

<div class="flex-1 overflow-y-auto px-4 py-3 pl-10">
  {#if eventsLoading}
    <p class="text-text-muted text-xs py-8 text-center">Loading events…</p>
  {:else if events.length === 0}
    <p class="text-text-muted text-xs py-8 text-center">No events yet{activeStatus === "running" ? " - waiting for stream…" : ""}</p>
  {:else}
    {#each events as ev, i (ev.sequence)}
      <EventCard
        {ev}
        isLast={i === events.length - 1}
        verifyResult={verifyResults[ev.sequence]}
        isExpanded={expandedBodies.has(ev.sequence)}
        {onToggleBody}
      />
    {/each}
  {/if}
</div>
