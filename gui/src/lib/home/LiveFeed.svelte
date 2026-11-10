<!-- LiveFeed: the running session's events as they arrive. -->
<script lang="ts" module>
  export interface LiveEvent {
    typeLabel: string;
    content: string;
    isError: boolean;
    isComplete: boolean;
    /** Semantic colour hint: 'chat' | 'tripwire' | 'action' | null */
    colorHint: "chat" | "tripwire" | "action" | null;
  }
</script>

<script lang="ts">
  import { Button } from "../ui";

  interface Props {
    events: LiveEvent[];
    running: boolean;
    sessionDone: boolean;
    onstop: () => void;
  }

  let { events, running, sessionDone, onstop }: Props = $props();
</script>

  <div class="flex justify-between items-center mt-1 gap-2 flex-wrap">
    <span class="text-xs font-semibold text-text-secondary uppercase tracking-wide">
      {#if running}Live feed{:else if sessionDone}Complete{:else}Events{/if}
    </span>
    {#if running}
      <Button variant="ghost" size="sm" onclick={onstop}>Stop</Button>
    {/if}
  </div>
  <div class="flex-1 min-h-0 bg-surface-elevated/20 border border-border-muted/20 rounded-2xl p-5 font-mono text-xs text-text-primary whitespace-pre-wrap overflow-y-auto overflow-x-hidden break-words flex flex-col gap-2">
    {#each events as ev}
      <div class="flex flex-col gap-0.5 px-4 py-2.5 rounded-xl border-l-2
        {ev.colorHint === 'tripwire' ? 'bg-danger/10 border-l-danger'
        : ev.isError ? 'bg-danger-muted/30 border-l-danger'
        : ev.colorHint === 'chat' ? 'bg-warning/10 border-l-warning'
        : ev.colorHint === 'action' ? 'bg-accent/10 border-l-accent'
        : ev.isComplete ? 'bg-background border-l-success'
        : 'bg-background border-l-border-muted'}">
        <span class="text-[0.65rem] font-bold uppercase tracking-wide
          {ev.colorHint === 'tripwire' ? 'text-danger-text'
          : ev.isError ? 'text-danger'
          : ev.colorHint === 'chat' ? 'text-warning'
          : ev.colorHint === 'action' ? 'text-accent-text'
          : ev.isComplete ? 'text-success'
          : 'text-text-muted'}">{ev.typeLabel}</span>
        {#if ev.content}<span class="text-xs text-text-primary whitespace-pre-wrap break-words leading-snug">{ev.content}</span>{/if}
      </div>
    {/each}
  </div>
