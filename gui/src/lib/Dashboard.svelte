<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";
  import ObserverPanel from "./ObserverPanel.svelte";
  import RunPanel from "./home/RunPanel.svelte";
  import StatusTiles from "./home/StatusTiles.svelte";
  import { SSEConnection } from "./sse";
  import { detectDemoMode, fetchCapabilities, type BackendCapabilities } from "./backend";
  import { Button } from "./ui";
  import { parseResponse } from "./home/parseResponse";
  import { summarizeMetrics } from "./home/metricsSummary";
  import { parseLiveEventItem } from "./home/liveEvents";
  import { metricsPollDelay, sessionPollDelay } from "./home/backoff";
  import type { LiveEvent } from "./home/LiveFeed.svelte";

  let { serverUrl = "", onNavigateToTab }: { serverUrl?: string; onNavigateToTab?: (tab: string) => void } = $props();
  // Initialized to empty string; set via Tauri invoke("server_url") in onMount.
  // Keeping this empty prevents any accidental fetch against a hardcoded localhost
  // before the real backend URL is resolved (important in containerised deployments).
  let dashboardUrl = $state("");
  let observerToken = $state("");
  let metrics = $state<Record<string, unknown> | null>(null);
  let metricsErr = $state("");
  let tauriReady = $state(false);
  let pollTimeout = $state<ReturnType<typeof setTimeout> | null>(null);
  let _alive = true;
  let demoMode = $state(false);
  let caps = $state<BackendCapabilities>({
    ledger_backend: "sqlite",
    agent_supported: false,
    exports_supported: false,
    webhooks_live: false,
  });

  const summary = $derived(summarizeMetrics(metrics));

  onMount(async () => {
    if (!isTauri()) {
      metricsErr = "Run this app via the IronVise desktop window (`make start`, or .\\ironvise-win.ps1 on Windows), not in a browser.";
      return;
    }
    tauriReady = true;
    try {
      dashboardUrl = await invoke<string>("dashboard_url");
      observerToken = await invoke<string>("observer_token");
    } catch (e) {
      metricsErr = `Failed to initialise dashboard: ${e}`;
    }
    // Prefill a goal that does not trip the Markdown backtick scanner.
    detectDemoMode(serverUrl).then((v) => {
      if (!_alive) return;
      if (v) {
        demoMode = true;
        if (!prompt.trim()) {
          prompt = "Read Cargo.toml and report the workspace version.";
        }
      }
    });
    fetchCapabilities(serverUrl || dashboardUrl).then((c) => {
      if (!_alive) return;
      caps = c;
    });
    await loadMetrics();
    function scheduleMetricsPoll() {
      if (!_alive) return;
      const delay = metricsPollDelay(_metricsErrorCount);
      pollTimeout = setTimeout(async () => {
        if (!document.hidden) await loadMetrics();
        scheduleMetricsPoll();
      }, delay);
    }
    scheduleMetricsPoll();
    const onVisChange = () => {
      if (!document.hidden && !pollTimeout) scheduleMetricsPoll();
    };
    document.addEventListener("visibilitychange", onVisChange);
    _visibilityHandler = onVisChange;
  });

  let _visibilityHandler: (() => void) | null = null;

  onDestroy(() => {
    _alive = false;
    if (_visibilityHandler) document.removeEventListener("visibilitychange", _visibilityHandler);
    if (pollTimeout) clearTimeout(pollTimeout);
    if (sessionPoll) clearTimeout(sessionPoll);
    if (approvalPoll) clearInterval(approvalPoll);
    if (sseSource) { sseSource.close(); sseSource = null; }
  });

  let _loadingMetrics = false;
  let _metricsErrorCount = 0;
  async function loadMetrics() {
    if (!tauriReady || _loadingMetrics) return;
    _loadingMetrics = true;
    try {
      const data = await invoke<unknown>("get_metrics");
      if (!_alive) return;
      metrics = data && typeof data === "object" && !Array.isArray(data)
        ? (data as Record<string, unknown>)
        : null;
      metricsErr = "";
      _metricsErrorCount = 0;
    } catch (e) {
      _metricsErrorCount++;
      const msg = String(e);
      const isRateLimit = msg.includes("429") || msg.includes("Too Many Requests") || msg.includes("rate limit");
      if (!isRateLimit) {
        metricsErr = msg;
      }
    } finally {
      _loadingMetrics = false;
    }
  }

  let prompt = $state("");
  let running = $state(false);
  let result = $state("");
  let rawResult = $state<unknown>(null);
  let showRawOutput = $state(false);

  // Live event streaming state (populated after "Run Agent" creates a session).
  let liveSessionId = $state<string | null>(null);
  let liveEvents = $state<LiveEvent[]>([]);
  let sessionDone = $state(false);
  let sessionPoll = $state<ReturnType<typeof setTimeout> | null>(null);
  let lastEventCount = $state(0);
  let noNewEventsCount = $state(0);
  let pendingApproval = $state<Record<string, unknown> | null>(null);
  let approvalReason = $state("");
  let approvalError = $state("");
  let decidingApproval = $state(false);
  let approvalPoll = $state<ReturnType<typeof setInterval> | null>(null);

  function stopPolling() {
    if (sessionPoll) { clearTimeout(sessionPoll); sessionPoll = null; }
    if (sseSource) { sseSource.close(); sseSource = null; }
    if (approvalPoll) { clearInterval(approvalPoll); approvalPoll = null; }
    running = false;
  }

  async function pollApproval() {
    if (!liveSessionId || !tauriReady || sessionDone) return;
    try {
      // Server returns { pending: PendingApproval | null }
      const wrapper = await invoke<{ pending: Record<string, unknown> | null }>(
        "get_pending_approval",
        { sessionId: liveSessionId },
      );
      pendingApproval =
        wrapper && typeof wrapper === "object" && wrapper.pending
          ? (wrapper.pending as Record<string, unknown>)
          : null;
    } catch { /* no active gate - ignore */ }
  }

  async function decideApproval(approved: boolean) {
    if (!pendingApproval || !liveSessionId || decidingApproval) return;
    const gateId = String(pendingApproval.gate_id ?? "");
    decidingApproval = true;
    approvalError = "";
    try {
      await invoke("post_approval_decision", {
        sessionId: liveSessionId,
        gateId,
        approved,
        reason: approvalReason || null,
      });
      pendingApproval = null;
      approvalReason = "";
    } catch (e) {
      approvalError = `Approval decision failed: ${e}`;
      console.error("Approval decision failed:", e);
    } finally {
      decidingApproval = false;
    }
  }

  let sseSource: SSEConnection | null = null;

  /** Open an SSE connection for the current session.  Falls back to polling
   *  when SSE errors or is unavailable (e.g. restrictive CSP). */
  function startSSE(sessionId: string) {
    if (!dashboardUrl || !observerToken) {
      // No URL yet - fall back to polling.
      scheduleSessionPoll();
      return;
    }
    // The server names every ledger frame `event`; `onmessage` only sees unnamed frames.
    const handleFrame = (msg: MessageEvent) => {
      if (!_alive) { sseSource?.close(); return; }
      try {
        const raw = JSON.parse(msg.data);
        const ev = parseLiveEventItem(raw);
        if (ev) {
          liveEvents = [...liveEvents, ev].slice(-500);
          if (ev.isComplete) {
            sessionDone = true;
            sseSource?.close();
            sseSource = null;
            if (approvalPoll) { clearInterval(approvalPoll); approvalPoll = null; }
            running = false;
          }
        }
      } catch { /* ignore unparseable frames */ }
    };

    sseSource?.close();
    sseSource = new SSEConnection({
      url: `${dashboardUrl}/api/stream?session_id=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(observerToken)}`,
      events: { event: handleFrame },
      onError: () => {
        // SSE failed - fall back to polling instead of reconnecting.
        sseSource = null;
        if (!sessionDone && _alive) {
          scheduleSessionPoll();
        } else if (approvalPoll) {
          clearInterval(approvalPoll);
          approvalPoll = null;
        }
        return false;
      },
    });
    sseSource.connect();
  }

  function scheduleSessionPoll() {
    if (!_alive || sessionDone) return;
    sessionPoll = setTimeout(pollSessionEvents, sessionPollDelay(noNewEventsCount));
  }

  let _polling = false;
  async function pollSessionEvents() {
    if (_polling || !liveSessionId || !tauriReady || !_alive) return;
    _polling = true;
    try {
      const rawevs = await invoke<unknown>("get_events", { sessionId: liveSessionId });
      const arr = Array.isArray(rawevs) ? rawevs : [];
      liveEvents = arr.map(parseLiveEventItem).filter((e): e is LiveEvent => e !== null);

      if (arr.length === lastEventCount) {
        noNewEventsCount++;
      } else {
        noNewEventsCount = 0;
        lastEventCount = arr.length;
      }

      const hasComplete = liveEvents.some((e) => e.isComplete);
      // Stop after a complete action, or after ~16 s with no new events once
      // the agent has already produced at least one event.
      if (hasComplete || (noNewEventsCount >= 8 && lastEventCount > 0)) {
        stopPolling();
        sessionDone = true;
      } else {
        scheduleSessionPoll();
      }
    } catch {
      noNewEventsCount++;
      if (noNewEventsCount >= 8) {
        stopPolling();
      } else {
        scheduleSessionPoll();
      }
    } finally {
      _polling = false;
    }
  }

  /** Full agent cognitive loop - creates a session, streams events. */
  async function runAgent() {
    if (!prompt.trim() || !tauriReady || !caps.agent_supported) return;
    // Reset all live-event state.
    running = true;
    result = "";
    rawResult = null;
    liveSessionId = null;
    liveEvents = [];
    sessionDone = false;
    lastEventCount = 0;
    noNewEventsCount = 0;
    pendingApproval = null;
    approvalReason = "";
    if (sessionPoll) { clearTimeout(sessionPoll); sessionPoll = null; }
    if (approvalPoll) { clearInterval(approvalPoll); approvalPoll = null; }

    const goalText = prompt;
    prompt = "";
    try {
      const res = await invoke<unknown>("run_prompt", { args: { goal: goalText } });
      if (!_alive) return;
      rawResult = res;
      if (res && typeof res === "object" && !Array.isArray(res)) {
        const sr = res as Record<string, unknown>;
        liveSessionId = typeof sr.id === "string" ? sr.id : null;
        result = liveSessionId
          ? `Session ${liveSessionId.slice(0, 8)}… started - watching for agent events…`
          : parseResponse(res);
      } else {
        result = typeof res === "string" ? res : JSON.stringify(res, null, 2);
      }
      if (liveSessionId) {
        // Prefer SSE for real-time event streaming; falls back to polling.
        startSSE(liveSessionId);
        // Poll for human-approval gates every 3 s.
        approvalPoll = setInterval(pollApproval, 3000);
      } else {
        running = false;
      }
    } catch (e) {
      if (!_alive) return;
      result = String(e);
      rawResult = null;
      running = false;
    }
  }
</script>

<!-- Full-height panes only when side by side. Stacked (below xl), a fixed
     height made the two panes split it and squeezed the timeline to a strip. -->
<div class="grid grid-cols-1 xl:grid-cols-[minmax(300px,440px)_1fr] gap-6 xl:h-full min-w-0">
  <RunPanel
    {serverUrl}
    {onNavigateToTab}
    {running}
    connectOpen={summary?.sessions === 0}
    {caps}
    {demoMode}
    bind:prompt
    onRun={runAgent}
    {liveSessionId}
    {sessionDone}
    {pendingApproval}
    bind:approvalReason
    {decidingApproval}
    {approvalError}
    onDecideApproval={decideApproval}
    {liveEvents}
    onStopPolling={stopPolling}
    {result}
    {rawResult}
    bind:showRawOutput
  />

  <div class="min-w-0 min-h-[640px] xl:min-h-0 flex flex-col gap-6">
  <section class="rounded-xl p-6 bg-surface shadow-sm border border-border-muted/40 min-w-0 shrink-0 flex flex-col gap-5">
    <div class="flex justify-between items-center gap-3 flex-wrap shrink-0">
      <h2 class="text-xs font-semibold uppercase tracking-[0.1em] text-text-secondary m-0">Status</h2>
      <Button variant="ghost" size="sm" class="shrink-0" onclick={loadMetrics}>Refresh</Button>
    </div>

    <StatusTiles {summary} error={metricsErr} />

  </section>

    <div class="flex-1 min-h-0 min-w-0">
      <ObserverPanel {serverUrl} />
    </div>
  </div>
</div>
