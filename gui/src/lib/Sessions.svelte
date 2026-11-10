<script lang="ts">
  import { isTauri } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import { writeFile } from "@tauri-apps/plugin-fs";
  import { onMount, onDestroy } from "svelte";
  import { fetchSessionVc, verifySessionVc, fetchCapabilities, listSessions, sessionEvents, type SessionSummary } from "./backend";
  import { describeEvent } from "./events";
  import { describeVerification, type VerificationView, type VerifyResponse } from "./verification";
  import { groupEvents, type RawEvent } from "./sessions/groupEvents";
  import { verifySessionChain, exportCertificateBytes, downloadReportBytes, signatureNote } from "./sessions/sessionActions";
  import SessionList from "./sessions/SessionList.svelte";
  import SessionHeaderPanel from "./sessions/SessionHeaderPanel.svelte";
  import CredentialCard from "./sessions/CredentialCard.svelte";
  import EventTimeline from "./sessions/EventTimeline.svelte";

  type Session = SessionSummary;

  let sessions = $state<Session[]>([]);
  let selected = $state<string | null>(null);
  let events = $state<RawEvent[]>([]);
  let loading = $state(false);
  let sessionError = $state("");
  let exporting = $state(false);
  let exportingReport = $state(false);
  let exportMsg = $state("");

  // pagination / filtering
  const PAGE_SIZE = 20;
  // `""`, not `null`: the "All" option's value is the empty string, and
  // `bind:value` matches by value. With `null` no option matched and the filter
  // rendered blank on first load - it looked broken and told you nothing about
  // what you were looking at. `load()` still sends `null` for "no filter".
  let statusFilter = $state<string>("");
  let offset = $state(0);
  let more = $state(false);

  // verifiable credential cache/loading
  let vcData = $state<{ vc_jwt: string; vc_payload: any } | null>(null);
  let vcLoading = $state(false);
  let vcError = $state("");
  // VC on-demand verification
  let vcVerifyResult = $state<{ valid?: boolean; signature_verified?: boolean; reason?: string; claims?: any; error?: string } | null>(null);
  let vcVerifying = $state(false);
  let eventsLoading = $state(false);
  let verification = $state<VerificationView | null>(null);
  let verifyingSession = $state(false);
  let exportsSupported = $state(false);
  let showVcDetails = $state(false);

  let _alive = true;
  let selectionVersion = 0;
  let listVersion = 0;
  function currentSelection(id: string, version: number): boolean {
    return _alive && selected === id && selectionVersion === version;
  }
  onDestroy(() => { _alive = false; });

  onMount(async () => {
    fetchCapabilities().then((c) => {
      if (!_alive) return;
      exportsSupported = c.exports_supported;
    });
    await load();
  });


  async function load() {
    if (!isTauri()) return;
    const request = ++listVersion;
    loading = true;
    sessionError = "";
    try {
      const data = await listSessions({ status: statusFilter, limit: PAGE_SIZE, offset });
      if (!_alive || request !== listVersion) return;
      sessions = data;
      more = sessions.length === PAGE_SIZE;
    } catch (e) {
      if (!_alive || request !== listVersion) return;
      sessionError = String(e);
      sessions = [];
    } finally {
      if (_alive && request === listVersion) loading = false;
    }
  }

  function onFilterChange() {
    offset = 0;
    load();
  }

  async function selectSession(id: string) {
    if (!isTauri()) return;
    const version = ++selectionVersion;
    selected = id;
    sessionError = "";
    verifyingSession = false;
    vcVerifying = false;
    vcLoading = false;
    exporting = false;
    exportingReport = false;
    events = [];
    eventsLoading = true;
    vcData = null;
    vcError = "";
    vcVerifyResult = null;
    showVcDetails = false;
    expandedKeys = new Set();
    exportMsg = "";
    verification = null;
    try {
      const data = await sessionEvents(id);
      if (!currentSelection(id, version)) return; // stale response guard
      events = data as RawEvent[];
    } catch (e) {
      if (!currentSelection(id, version)) return;
      events = [];
      sessionError = `Failed to load events: ${e}`;
    } finally {
      if (currentSelection(id, version)) eventsLoading = false;
    }
    // if session is completed, fetch VC as well
    const sess = sessions.find((s) => s.id === id);
    if (sess && sess.status === "completed") {
      loadVC(id);
    }
  }

  async function loadVC(id: string) {
    if (!isTauri()) return;
    const version = selectionVersion;
    vcLoading = true;
    vcError = "";
    vcData = null;
    vcVerifyResult = null;
    try {
      const data = await fetchSessionVc(id);
      if (!currentSelection(id, version)) return; // stale response guard
      vcData = data as any;
    } catch (e) {
      if (!currentSelection(id, version)) return;
      vcError = String(e);
      vcData = null;
    } finally {
      if (currentSelection(id, version)) vcLoading = false;
    }
  }

  async function verifyVC(id: string) {
    if (!isTauri()) return;
    const version = selectionVersion;
    vcVerifying = true;
    vcVerifyResult = null;
    try {
      const data = await verifySessionVc(id);
      if (!currentSelection(id, version)) return;
      vcVerifyResult = data as any;
    } catch (e) {
      if (!currentSelection(id, version)) return;
      vcVerifyResult = { error: String(e) };
    } finally {
      if (currentSelection(id, version)) vcVerifying = false;
    }
  }

  let expandedKeys = $state<Set<string>>(new Set());

  function toggleExpanded(key: string) {
    expandedKeys = new Set(expandedKeys);
    if (expandedKeys.has(key)) {
      expandedKeys.delete(key);
    } else {
      expandedKeys.add(key);
    }
  }

  /** The ledger's own verifier, chain and signatures, not a recomputation here. */
  async function verifySession() {
    if (!selected || !isTauri()) return;
    const id = selected;
    const version = selectionVersion;
    verifyingSession = true;
    verification = null;
    try {
      const res: VerifyResponse = await verifySessionChain(id);
      if (!currentSelection(id, version)) return;
      verification = describeVerification(res ?? {}, id);
    } catch (e) {
      if (!currentSelection(id, version)) return;
      verification = { tone: "fail", title: "Verification could not run", detail: String(e) };
    } finally {
      if (currentSelection(id, version)) verifyingSession = false;
    }
  }

  async function exportCert() {
    if (!selected || !isTauri() || exporting) return;
    const id = selected;
    const version = selectionVersion;
    exporting = true;
    exportMsg = "";
    try {
      const bytes = await exportCertificateBytes(id);
      if (!currentSelection(id, version)) return;
      const path = await save({
        defaultPath: `audit-${id.slice(0, 8)}.elc`,
        filters: [{ name: "IronVise Certificate", extensions: ["elc"] }],
      });
      if (path) {
        await writeFile(path, new Uint8Array(bytes));
        const note = await signatureNote(bytes);
        if (currentSelection(id, version)) exportMsg = `Certificate saved to ${path}. ${note}`;
      } else if (currentSelection(id, version)) {
        exportMsg = "Save cancelled.";
      }
    } catch (e) {
      if (currentSelection(id, version)) exportMsg = String(e);
    } finally {
      if (currentSelection(id, version)) exporting = false;
    }
  }

  async function downloadReport() {
    if (!selected || !isTauri() || exportingReport) return;
    const id = selected;
    const version = selectionVersion;
    exportingReport = true;
    exportMsg = "";
    try {
      const bytes = await downloadReportBytes(id);
      if (!currentSelection(id, version)) return;
      const path = await save({
        defaultPath: `report-${id.slice(0, 8)}.json`,
        filters: [{ name: "JSON Report", extensions: ["json"] }],
      });
      if (path) {
        await writeFile(path, new Uint8Array(bytes));
        if (currentSelection(id, version)) exportMsg = `Report saved to ${path}`;
      } else if (currentSelection(id, version)) {
        exportMsg = "Save cancelled.";
      }
    } catch (e) {
      if (currentSelection(id, version)) exportMsg = String(e);
    } finally {
      if (currentSelection(id, version)) exportingReport = false;
    }
  }

  const groupedEvents = $derived(groupEvents(events));
  const refusalCount = $derived(
    events.filter((ev) => describeEvent(ev.payload).tone === "blocked").length,
  );
  const selectedSession = $derived(sessions.find((s) => s.id === selected) ?? null);
  /** A missing credential is a normal state for most sessions, not an error. */
  const vcMissing = $derived(vcError.startsWith("No VC found"));

  function prevPage() {
    offset = Math.max(0, offset - PAGE_SIZE);
    selected = null;
    events = [];
    load();
  }

  function nextPage() {
    if (more) {
      offset += PAGE_SIZE;
      selected = null;
      events = [];
      load();
    }
  }


</script>

<div class="flex gap-6 h-full overflow-hidden">
  <SessionList
    {sessions}
    {selected}
    {loading}
    {sessionError}
    bind:statusFilter
    {offset}
    {more}
    onRefresh={load}
    {onFilterChange}
    onSelect={selectSession}
    onPrev={prevPage}
    onNext={nextPage}
  />

  <section class="bg-surface rounded-2xl flex-1 min-w-0 p-7 overflow-y-auto flex flex-col gap-6 shadow-sm">
    {#if !selected}
      <p class="text-text-muted text-sm text-center mt-16">Select a session to view events.</p>
    {:else}
      <SessionHeaderPanel
        {selectedSession}
        selectedId={selected}
        {eventsLoading}
        eventsLength={events.length}
        {refusalCount}
        {exportsSupported}
        verifying={verifyingSession}
        {exporting}
        {exportingReport}
        {verification}
        onVerify={verifySession}
        onExportCert={exportCert}
        onDownloadReport={downloadReport}
      />

      <CredentialCard
        {vcLoading}
        {vcError}
        {vcMissing}
        {vcData}
        {showVcDetails}
        {vcVerifying}
        {vcVerifyResult}
        onToggleDetails={() => (showVcDetails = !showVcDetails)}
        onVerifyVc={() => selected && verifyVC(selected)}
      />

      {#if exportMsg}
        <div class="bg-background border border-border-muted/20 rounded-xl p-5 text-sm text-text-primary whitespace-pre-wrap max-h-[120px] overflow-y-auto {exportMsg.startsWith('fs.') || exportMsg.includes('not allowed') ? 'border-danger text-danger' : ''}">
          {exportMsg}
        </div>
      {/if}

      <EventTimeline
        {eventsLoading}
        eventsLength={events.length}
        {groupedEvents}
        {expandedKeys}
        onToggleExpanded={toggleExpanded}
      />
    {/if}
  </section>
</div>
