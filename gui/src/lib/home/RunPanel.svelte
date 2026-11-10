<!-- RunPanel: the goal textarea, Run action, the pending-approval gate, and
     the live feed or last response beneath it. -->
<script lang="ts">
  import ConnectClaudeCode from "../ConnectClaudeCode.svelte";
  import ApprovalCard from "./ApprovalCard.svelte";
  import LiveFeed, { type LiveEvent } from "./LiveFeed.svelte";
  import ResponseView from "./ResponseView.svelte";
  import { Button } from "../ui";
  import type { BackendCapabilities } from "../backend";

  interface Props {
    serverUrl: string;
    onNavigateToTab?: (tab: string) => void;
    running: boolean;
    connectOpen: boolean;
    caps: BackendCapabilities;
    demoMode: boolean;
    prompt: string;
    onRun: () => void;
    liveSessionId: string | null;
    sessionDone: boolean;
    pendingApproval: Record<string, unknown> | null;
    approvalReason: string;
    decidingApproval: boolean;
    approvalError: string;
    onDecideApproval: (approved: boolean) => void;
    liveEvents: LiveEvent[];
    onStopPolling: () => void;
    result: string;
    rawResult: unknown;
    showRawOutput: boolean;
  }

  let {
    serverUrl,
    onNavigateToTab,
    running,
    connectOpen,
    caps,
    demoMode,
    prompt = $bindable(""),
    onRun,
    liveSessionId,
    sessionDone,
    pendingApproval,
    approvalReason = $bindable(""),
    decidingApproval,
    approvalError,
    onDecideApproval,
    liveEvents,
    onStopPolling,
    result,
    rawResult,
    showRawOutput = $bindable(false),
  }: Props = $props();
</script>

<section class="rounded-xl p-6 bg-surface shadow-sm border border-border-muted/40 min-w-0 flex flex-col gap-5 overflow-y-auto">
  {#if !running}
    <!-- First: the integration that can refuse an action before it runs.
         Open by default on an empty ledger, where it is the likeliest next
         step; folded to one line once sessions exist. Hidden while a run
         is live so the feed has the room. -->
    <ConnectClaudeCode {serverUrl} open={connectOpen} {onNavigateToTab} />
  {/if}
  <div>
    <h2 class="text-xs font-semibold uppercase tracking-[0.1em] text-text-secondary m-0">Audit goal</h2>
    {#if !caps.agent_supported}
      <div class="mt-3 rounded-xl border border-warning/30 bg-warning-muted px-4 py-3 text-xs text-warning leading-relaxed">
        This desktop session is on <span class="font-mono">{caps.ledger_backend}</span>,
        and Home → Run is unavailable on this connection. Check Settings for the database URL
        and restart if you recently changed it. Policy, Tripwire, and History still work here.
      </div>
    {:else if demoMode}
      <p class="text-xs text-text-muted mt-2 mb-0 leading-relaxed">
        Demo mode is on. A safe starter goal is filled in - change it or press Run.
      </p>
    {:else}
      <p class="text-xs text-text-muted mt-2 mb-0 leading-relaxed">
        Enter a goal and press Run. Denials appear in the feed; open History for the ledger.
      </p>
    {/if}
  </div>
  <textarea
    class="w-full shrink-0 bg-surface-elevated/30 border border-border-muted/30 rounded-xl text-text-primary font-mono px-5 py-4 text-sm resize-y outline-none leading-relaxed focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
    bind:value={prompt}
    placeholder="Enter agent goal…"
    rows="4"
    disabled={!caps.agent_supported}
  ></textarea>
  <div class="flex flex-wrap items-center gap-3 shrink-0 pb-1">
    <Button
      class="shrink-0 min-w-[7rem]"
      variant="primary"
      onclick={onRun}
      disabled={running || !prompt.trim() || !caps.agent_supported}
      loading={running}
    >
      {running ? "Running…" : "Run"}
    </Button>
    {#if liveSessionId}
      <span class="text-xs text-text-muted font-mono truncate">
        Session {liveSessionId.slice(0, 8)}…
      </span>
      {#if sessionDone && onNavigateToTab}
        <button
          type="button"
          class="text-xs text-accent-text hover:underline bg-transparent border-none cursor-pointer p-0"
          onclick={() => onNavigateToTab("sessions")}
        >
          Open in History
        </button>
      {/if}
    {/if}
  </div>

  {#if pendingApproval}
    <ApprovalCard
      approval={pendingApproval}
      bind:reason={approvalReason}
      deciding={decidingApproval}
      error={approvalError}
      ondecide={onDecideApproval}
    />
  {/if}

  {#if liveEvents.length > 0}
    <LiveFeed events={liveEvents} {running} {sessionDone} onstop={onStopPolling} />
  {:else if result || rawResult !== null}
    <ResponseView {result} {rawResult} bind:showRawOutput />
  {/if}
</section>
