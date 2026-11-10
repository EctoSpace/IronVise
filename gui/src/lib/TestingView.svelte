<!--
  TestingView - Testing & Verification tab.

  Unified testing menu with collapsible Happy Path and Sad Path sections.
  In demo mode, sessions use the mock LLM backend so no external LLM
  dependency is required for tests to run.
-->
<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { Badge, Button, Card, FieldLabel, Input, Panel } from "./ui";
  import TestSection from "./testing/TestSection.svelte";
  import adversarialTests from "./adversarial-tests.json";
  import happyPathTests from "./happy-path-tests.json";
  import { detectDemoMode, fetchSessionVc, verifySessionVc, listSessions } from "./backend";

  let _alive = true;
  onDestroy(() => { _alive = false; });

  interface Props {
    serverUrl: string;
  }

  let { serverUrl }: Props = $props();

  let demoMode = $state(false);

  type TestStatus = "idle" | "running" | "pass" | "fail";
  let happyStatuses = $state<Record<string, TestStatus>>({});
  let happyResults  = $state<Record<string, string>>({});
  let happySessionIds = $state<Record<string, string>>({});

  async function runHappyTest(testId: string, prompt: string) {
    happyStatuses = { ...happyStatuses, [testId]: "running" };
    happyResults  = { ...happyResults,  [testId]: "" };
    try {
      const session = await invoke<{ id: string; status: string }>("run_prompt", {
        args: { goal: prompt },
      });

      happySessionIds = { ...happySessionIds, [testId]: session.id };

      const TERMINAL = new Set(["completed", "aborted", "failed"]);
      const POLL_INTERVAL_MS = 1500;
      const TIMEOUT_MS = 30_000;
      const started = Date.now();
      let finalStatus = session.status;

      while (!TERMINAL.has(finalStatus) && Date.now() - started < TIMEOUT_MS && _alive) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        if (!_alive) break;
        try {
          const updated = await invoke<{ id: string; status: string }>("get_session", {
            sessionId: session.id,
          });
          finalStatus = updated.status;
        } catch { break; }
      }

      const passed = finalStatus === "completed";
      happyStatuses = { ...happyStatuses, [testId]: passed ? "pass" : "fail" };
      happyResults  = {
        ...happyResults,
        [testId]: passed
          ? `Session completed ✓ (${session.id.slice(0, 12)}…)`
          : `Session did not complete ✗ (status: ${finalStatus})`,
      };

      loadSessions();
    } catch (e) {
      happyStatuses = { ...happyStatuses, [testId]: "fail" };
      happyResults  = { ...happyResults,  [testId]: String(e) };
    }
  }

  async function runAllHappyTests() {
    for (const t of happyPathTests) {
      await runHappyTest(t.id, t.prompt);
    }
  }

  let testStatuses = $state<Record<string, TestStatus>>({});
  let testResults  = $state<Record<string, string>>({});
  let sadSessionIds = $state<Record<string, string>>({});

  async function runAdversarialTest(testId: string, prompt: string) {
    testStatuses = { ...testStatuses, [testId]: "running" };
    testResults  = { ...testResults,  [testId]: "" };
    try {
      const session = await invoke<{ id: string; status: string }>("run_prompt", {
        args: { goal: prompt },
      });

      sadSessionIds = { ...sadSessionIds, [testId]: session.id };

      const TERMINAL = new Set(["completed", "aborted", "failed"]);
      const POLL_INTERVAL_MS = 1500;
      const TIMEOUT_MS = 30_000;
      const started = Date.now();
      let finalStatus = session.status;

      while (!TERMINAL.has(finalStatus) && Date.now() - started < TIMEOUT_MS && _alive) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        if (!_alive) break;
        try {
          const updated = await invoke<{ id: string; status: string }>("get_session", {
            sessionId: session.id,
          });
          finalStatus = updated.status;
        } catch { break; }
      }

      const blocked = finalStatus === "aborted" || finalStatus === "failed";
      testStatuses = { ...testStatuses, [testId]: blocked ? "pass" : "fail" };
      testResults  = {
        ...testResults,
        [testId]: blocked
          ? `Tripwire triggered ✓ (session ${finalStatus})`
          : `Prompt was NOT blocked ✗ (status: ${finalStatus})`,
      };

      loadSessions();
    } catch (e) {
      testStatuses = { ...testStatuses, [testId]: "fail" };
      testResults  = { ...testResults,  [testId]: String(e) };
    }
  }

  async function runAllAdversarialTests() {
    for (const t of adversarialTests) {
      await runAdversarialTest(t.id, t.prompt);
    }
  }

  let sessionId = $state("");
  let loading = $state(false);
  let vcData = $state<Record<string, unknown> | null>(null);
  let verifyResult = $state<{ valid: boolean; message: string } | null>(null);
  let error = $state("");

  // Session list for quick-pick
  let sessions = $state<Array<{ id: string; goal: string; status: string }>>([]);
  let loadingSessions = $state(true);

  async function loadSessions() {
    loadingSessions = true;
    try {
      sessions = await listSessions();
    } catch {
      sessions = [];
    }
    loadingSessions = false;
  }

  onMount(() => {
    loadSessions();
    detectDemoMode(serverUrl).then((v) => { if (_alive && v) demoMode = true; });
  });

  /** The currently selected session object (if any). */
  let selectedSession = $derived(sessions.find((s) => s.id === sessionId));
  /** Whether the selected session can have a VC (only completed sessions). */
  let canHaveVC = $derived(selectedSession?.status === "completed");

  async function fetchVC() {
    if (!sessionId) return;
    loading = true;
    error = "";
    vcData = null;
    verifyResult = null;
    try {
      vcData = await fetchSessionVc(sessionId);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    loading = false;
  }

  async function verifyVC() {
    if (!sessionId) return;
    loading = true;
    error = "";
    try {
      const result = await verifySessionVc(sessionId);
      verifyResult = { valid: !!result.valid, message: result.message ?? result.error ?? "" };
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    loading = false;
  }

  function selectSession(id: string) {
    sessionId = id;
    vcData = null;
    verifyResult = null;
    error = "";
  }
</script>

<div class="space-y-8 animate-fade-in">
  <!-- Header -->
  <div>
    <h1 class="text-xl font-bold text-text-primary">Testing & Verification</h1>
    <p class="text-sm text-text-muted mt-1">Verify session integrity, run happy-path and adversarial security tests.</p>
  </div>

  <!-- Demo mode banner -->
  {#if demoMode}
    <div class="flex items-center gap-3 p-4 rounded-xl bg-warning/5 border border-warning/20">
      <div class="shrink-0 w-8 h-8 rounded-lg bg-warning/10 flex items-center justify-center">
        <svg class="w-4 h-4 text-warning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
      </div>
      <div>
        <p class="text-sm font-medium text-warning">Demo Mode</p>
        <p class="text-xs text-text-muted mt-0.5">Sessions use the mock LLM backend - no external LLM service required. The agent pipeline runs for real and produces genuine Verifiable Credentials.</p>
      </div>
    </div>
  {/if}

  <div class="space-y-4">
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <!-- Session picker -->
      <Card title="Sessions" subtitle="Select a session to verify">
        {#snippet children()}
          <div class="flex justify-end mb-2">
            <Button variant="secondary" onclick={loadSessions} loading={loadingSessions}>
              {#snippet children()}↻ Refresh{/snippet}
            </Button>
          </div>
          {#if loadingSessions}
            <div class="flex items-center gap-2.5 py-5">
              <div class="h-4 w-4 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
              <span class="text-xs text-text-secondary">Loading sessions…</span>
            </div>
          {:else if sessions.length === 0}
            <p class="text-sm text-text-muted py-4">No sessions found. Run a test first.</p>
          {:else}
            <div class="space-y-1.5 max-h-80 overflow-y-auto">
              {#each sessions as session}
                <button
                  class="w-full text-left px-4 py-3 rounded-xl text-sm transition-all duration-200 cursor-pointer
                    {sessionId === session.id
                      ? 'bg-accent-muted border border-accent/30'
                      : 'hover:bg-surface-elevated border border-transparent'}"
                  onclick={() => selectSession(session.id)}
                >
                  <div class="flex items-center justify-between">
                    <span class="text-text-primary truncate flex-1 mr-2 font-mono text-xs">{session.id.slice(0, 12)}…</span>
                    <Badge
                      variant={session.status === 'completed' ? 'success' : session.status === 'failed' ? 'danger' : session.status === 'aborted' ? 'danger' : session.status === 'running' ? 'accent' : 'default'}
                      dot
                    >
                      {#snippet children()}{session.status}{/snippet}
                    </Badge>
                  </div>
                  {#if session.goal}
                    <p class="text-xs text-text-secondary mt-1 truncate">{session.goal}</p>
                  {/if}
                </button>
              {/each}
            </div>
          {/if}
        {/snippet}
      </Card>

      <!-- Verification panel -->
      <div class="lg:col-span-2 space-y-4">
        <Card title="Verification" subtitle={sessionId ? `Session: ${sessionId.slice(0, 16)}…` : "Select a session"}>
          {#snippet children()}
            <div class="space-y-4">
              <div class="flex flex-wrap gap-3">
                <Input
                  bind:value={sessionId}
                  placeholder="Session ID (or select from list)"
                  class="flex-1 min-w-[180px]"
                />
                <div class="flex gap-2 shrink-0">
                  <Button variant="primary" onclick={fetchVC} loading={loading} disabled={!sessionId || (selectedSession != null && !canHaveVC)}>
                    {#snippet children()}Fetch VC{/snippet}
                  </Button>
                  <Button variant="secondary" onclick={verifyVC} loading={loading} disabled={!sessionId || (selectedSession != null && !canHaveVC)}>
                    {#snippet children()}Verify{/snippet}
                  </Button>
                </div>
              </div>

              <!-- Info message for non-completed sessions -->
              {#if selectedSession && !canHaveVC}
                <div class="flex items-center gap-2.5 p-3 rounded-lg bg-warning/5 border border-warning/20">
                  <svg class="w-4 h-4 text-warning shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                  <p class="text-xs text-text-secondary">
                    {#if selectedSession.status === "aborted"}
                      This session was <strong class="text-danger">aborted</strong> by the tripwire - no Verifiable Credential is issued for blocked sessions. This is expected for adversarial/sad-path tests.
                    {:else if selectedSession.status === "failed"}
                      This session <strong class="text-danger">failed</strong> - no Verifiable Credential was generated. Only successfully completed sessions produce a VC.
                    {:else}
                      This session is <strong class="text-accent-text">{selectedSession.status}</strong> - a Verifiable Credential is only available after completion.
                    {/if}
                  </p>
                </div>
              {/if}

              {#if error}
                <div class="p-3 rounded-lg bg-danger-muted border border-danger/30 text-sm text-danger">{error}</div>
              {/if}

              {#if verifyResult}
                {@const r = verifyResult}
                <div class="p-4 rounded-lg border {r.valid ? 'bg-success-muted border-success/30' : 'bg-danger-muted border-danger/30'}">
                  <div class="flex items-center gap-2 mb-2">
                    <Badge variant={r.valid ? 'success' : 'danger'} dot>
                      {#snippet children()}{r.valid ? 'Valid' : 'Invalid'}{/snippet}
                    </Badge>
                  </div>
                  <p class="text-sm text-text-secondary">{r.message}</p>
                </div>
              {/if}

              {#if vcData}
                <div class="space-y-2">
                  <h4 class="text-sm font-semibold text-text-primary">Verifiable Credential</h4>
                  <pre class="p-6 rounded-xl bg-surface-elevated border border-border-muted/15 text-xs text-text-secondary font-mono overflow-x-auto max-h-96 overflow-y-auto">{JSON.stringify(vcData, null, 2)}</pre>
                </div>
              {/if}
            </div>
          {/snippet}
        </Card>

        <!-- Quick checks -->
        <Card title="Integrity Checks">
          {#snippet children()}
            <div class="grid grid-cols-2 gap-4">
              <Panel>
                <FieldLabel spacing="below">Merkle Root</FieldLabel>
                <div class="text-sm text-text-primary font-mono">
                  {#if vcData && (vcData as Record<string, unknown>).merkle_root}
                    {String((vcData as Record<string, unknown>).merkle_root).slice(0, 24)}…
                  {:else}
                    <span class="text-text-muted"> - </span>
                  {/if}
                </div>
              </Panel>
              <Panel>
                <FieldLabel spacing="below">Signature</FieldLabel>
                <div class="text-sm text-text-primary font-mono">
                  {#if vcData && (vcData as Record<string, unknown>).proof}
                    <Badge variant="success" dot>{#snippet children()}Signed{/snippet}</Badge>
                  {:else}
                    <span class="text-text-muted"> - </span>
                  {/if}
                </div>
              </Panel>
              <Panel>
                <FieldLabel spacing="below">Events</FieldLabel>
                <div class="text-sm text-text-primary">
                  {#if vcData && (vcData as Record<string, unknown>).event_count}
                    {(vcData as Record<string, unknown>).event_count}
                  {:else}
                    <span class="text-text-muted"> - </span>
                  {/if}
                </div>
              </Panel>
              <Panel>
                <FieldLabel spacing="below">Policy Hash</FieldLabel>
                <div class="text-sm text-text-primary font-mono">
                  {#if vcData && (vcData as Record<string, unknown>).policy_hash}
                    {String((vcData as Record<string, unknown>).policy_hash).slice(0, 24)}…
                  {:else}
                    <span class="text-text-muted"> - </span>
                  {/if}
                </div>
              </Panel>
            </div>
          {/snippet}
        </Card>
      </div>
    </div>
  </div>

  <TestSection
    title="Happy Path Tests"
    tone="success"
    tests={happyPathTests}
    statuses={happyStatuses}
    results={happyResults}
    sessionIds={happySessionIds}
    gridClass="grid grid-cols-1 md:grid-cols-2 gap-5"
    onrun={runHappyTest}
    onrunall={runAllHappyTests}
    onselectsession={selectSession}
  />

  <TestSection
    title="Sad Path Tests"
    tone="danger"
    tests={adversarialTests}
    statuses={testStatuses}
    results={testResults}
    gridClass="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6"
    onrun={runAdversarialTest}
    onrunall={runAllAdversarialTests}
  />
</div>
