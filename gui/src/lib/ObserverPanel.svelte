<!--
  ObserverPanel.svelte - Native Svelte replacement for the iframe Observer.

  Renders a compact session sidebar + event timeline with:
  • Color-coded event type badges matching the Observer palette
  • Hash chain visualisation (previous_hash → content_hash per event)
  • Chain verification through the ledger's own Rust verifier
  • Live SSE streaming for running sessions
  • Findings table for "complete" actions

  Data is fetched through Tauri IPC (invoke), which handles auth
  transparently - no postMessage token relay or cross-origin issues.

  The sidebar, header, verify banner, and timeline each live in
  `./observer/`; the JSON-parsing and filtering they share lives in
  `./observer/eventRows.ts`.
-->
<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { listSessions, sessionEvents, type SessionSummary } from "./backend";
  import { onMount, onDestroy } from "svelte";
  import { SSEConnection } from "./sse";
  import { describeVerification, type VerifyResponse } from "./verification";
  import { normaliseEvents, toEventRow, type EventRow } from "./observer/eventRows";
  import SessionSidebar from "./observer/SessionSidebar.svelte";
  import SessionHeaderBar from "./observer/SessionHeaderBar.svelte";
  import VerifyBanner from "./observer/VerifyBanner.svelte";
  import EventTimeline from "./observer/EventTimeline.svelte";

  interface Props { serverUrl: string; }
  let { serverUrl }: Props = $props();

  type Session = SessionSummary;

  let sessions       = $state<Session[]>([]);
  let activeId       = $state<string | null>(null);
  let activeSession  = $state<Session | null>(null);
  let events         = $state<EventRow[]>([]);
  let eventsLoading  = $state(false);
  let sessionsLoading = $state(false);
  let searchQuery    = $state("");
  let statusFilter   = $state<string | null>(null);
  let error          = $state("");

  type VerifyResult = "pass" | "fail";
  let verifyResults = $state<Record<number, VerifyResult>>({});
  let verifyBanner  = $state<{ type: "pass" | "warn" | "fail" | "running"; text: string } | null>(null);
  let verifying     = $state(false);

  let expandedBodies = $state<Set<number>>(new Set());

  let sse: SSEConnection | null = null;
  let sseToken  = "";
  let alive     = true;

  let refreshInterval: ReturnType<typeof setInterval> | null = null;

  onMount(async () => {
    if (!isTauri()) return;
    try {
      sseToken = await invoke<string>("observer_token");
    } catch { /* non-critical - SSE won't work but IPC still does */ }
    await loadSessions();
    refreshInterval = setInterval(() => {
      if (!document.hidden) loadSessions();
    }, 10_000);
  });

  onDestroy(() => {
    alive = false;
    sse?.close();
    sse = null;
    if (refreshInterval) clearInterval(refreshInterval);
  });

  async function loadSessions() {
    if (!isTauri()) return;
    sessionsLoading = true;
    try {
      const data = await listSessions({ status: statusFilter });
      if (!alive) return;
      sessions = data;
    } catch (e) {
      error = String(e);
    } finally {
      sessionsLoading = false;
    }
  }

  function selectStatusFilter(f: string | null) {
    statusFilter = f;
    loadSessions();
  }

  async function selectSession(id: string) {
    if (!isTauri()) return;
    activeId = id;
    activeSession = sessions.find(s => s.id === id) ?? null;
    events = [];
    eventsLoading = true;
    verifyResults = {};
    verifyBanner = null;
    expandedBodies = new Set();

    sse?.close();
    sse = null;

    try {
      const data = await sessionEvents(id);
      if (!alive || activeId !== id) return;
      events = normaliseEvents(data);
    } catch (e) {
      if (!alive || activeId !== id) return;
      error = `Failed to load events: ${e}`;
    } finally {
      eventsLoading = false;
    }

    if (activeSession?.status === "running") {
      startSSE(id);
    }
  }

  function startSSE(sessionId: string) {
    if (!serverUrl || !sseToken) return;

    // One handler for both bare `message` frames and named "event" frames.
    const handleFrame = (msg: MessageEvent) => {
      if (!alive || activeId !== sessionId) { sse?.close(); return; }
      try {
        const raw = JSON.parse(msg.data) as Record<string, unknown>;
        if (raw.sequence !== undefined && raw.content_hash) {
          const ev = toEventRow(raw, new Date().toISOString());
          if (!events.some(e => e.sequence === ev.sequence)) {
            events = [...events, ev];
          }
        }
        const payload = typeof raw.payload === "object" ? raw.payload as Record<string, unknown> : null;
        const evType = payload?.type ?? raw.type;
        if (evType === "action" && (payload as Record<string, unknown> | null)?.name === "complete") {
          // Session is done - reload to get the final state
          sse?.close();
          sse = null;
          loadSessions();
        }
      } catch { /* ignore unparseable */ }
    };

    sse?.close();
    sse = new SSEConnection({
      url: `${serverUrl}/api/stream?session_id=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(sseToken)}`,
      shouldConnect: () => alive && activeId === sessionId,
      onMessage: handleFrame,
      events: { event: handleFrame },
    });
    sse.connect();
  }

  function toggleBody(seq: number) {
    expandedBodies = new Set(expandedBodies);
    if (expandedBodies.has(seq)) expandedBodies.delete(seq);
    else expandedBodies.add(seq);
  }

  // The ledger has one verifier, in Rust; ask it rather than re-hashing here.

  async function verifyChain() {
    if (!activeId || events.length === 0) return;
    const id = activeId;
    verifying = true;
    verifyResults = {};
    verifyBanner = { type: "running", text: "Verifying the hash chain and signatures…" };

    try {
      const res = await invoke<VerifyResponse>("verify_session_chain", { sessionId: id });
      if (activeId !== id) return; // user moved on
      const v = describeVerification(res ?? {}, id);
      if (v.tone === "pass") {
        verifyResults = Object.fromEntries(events.map((e) => [e.sequence, "pass" as const]));
      }
      verifyBanner = {
        type: v.tone,
        text: `${v.title}. ${v.detail}`,
      };
    } catch (e) {
      // Could not run is not the same as failed; say which.
      verifyBanner = { type: "fail", text: `Verification could not run: ${e}` };
    } finally {
      verifying = false;
    }
  }

</script>

<div class="flex h-full min-h-0 overflow-hidden rounded-xl border border-border-muted/40 bg-surface shadow-sm">
  <SessionSidebar
    {sessions}
    {activeId}
    {sessionsLoading}
    bind:searchQuery
    {statusFilter}
    onSelectFilter={selectStatusFilter}
    onSelect={selectSession}
  />

  <div class="flex-1 min-w-0 flex flex-col overflow-hidden">
    {#if !activeId}
      <!-- Empty state -->
      <div class="flex-1 flex items-center justify-center">
        {#if sessions.length === 0 && !sessionsLoading}
          <p class="text-text-muted text-xs text-center max-w-xs leading-relaxed">
            No sessions yet. Run a goal, or connect Claude Code, and its timeline appears here.
          </p>
        {:else}
          <p class="text-text-muted text-xs">Select a session to view its event timeline</p>
        {/if}
      </div>
    {:else}
      <SessionHeaderBar {activeSession} {verifying} eventsCount={events.length} onVerify={verifyChain} />
      <VerifyBanner banner={verifyBanner} />
      <EventTimeline
        {eventsLoading}
        {events}
        activeStatus={activeSession?.status}
        {verifyResults}
        {expandedBodies}
        onToggleBody={toggleBody}
      />
    {/if}
  </div>
</div>
