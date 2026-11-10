<!-- SessionHeaderBar: the active session's status, goal, and Verify Chain action. -->
<script lang="ts">
  import type { SessionSummary } from "../backend";

  interface Props {
    activeSession: SessionSummary | null;
    verifying: boolean;
    eventsCount: number;
    onVerify: () => void;
  }

  let { activeSession, verifying, eventsCount, onVerify }: Props = $props();
</script>

<div class="flex items-center gap-3 px-4 py-3 border-b border-border-muted/20 min-h-[44px]">
  <span class="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full
    {activeSession?.status === 'running' ? 'bg-success/15 text-success'
    : activeSession?.status === 'completed' ? 'bg-accent/15 text-accent-text'
    : activeSession?.status === 'failed' ? 'bg-danger/15 text-danger-text'
    : 'bg-text-muted/15 text-text-muted'}"
  >
    {activeSession?.status ?? "-"}
  </span>
  <span class="text-xs text-text-primary truncate flex-1">{activeSession?.goal ?? "-"}</span>
  <button
    class="text-[10px] font-semibold text-accent-text bg-accent/10 border border-accent/25 rounded-lg px-3 py-1 cursor-pointer hover:bg-accent/20 transition-colors disabled:opacity-40 disabled:cursor-default shrink-0"
    onclick={onVerify}
    disabled={verifying || eventsCount === 0}
  >
    {verifying ? "Verifying…" : "✓ Verify Chain"}
  </button>
</div>
