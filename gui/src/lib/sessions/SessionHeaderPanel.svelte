<!-- SessionHeaderPanel: the selected session's goal, event/refusal counts,
     Verify/Certificate/Report actions, and the verification result. -->
<script lang="ts">
  import { Button } from "../ui";
  import type { SessionSummary } from "../backend";
  import type { VerificationView } from "../verification";

  interface Props {
    selectedSession: SessionSummary | null;
    selectedId: string;
    eventsLoading: boolean;
    eventsLength: number;
    refusalCount: number;
    exportsSupported: boolean;
    verifying: boolean;
    exporting: boolean;
    exportingReport: boolean;
    verification: VerificationView | null;
    onVerify: () => void;
    onExportCert: () => void;
    onDownloadReport: () => void;
  }

  let {
    selectedSession,
    selectedId,
    eventsLoading,
    eventsLength,
    refusalCount,
    exportsSupported,
    verifying,
    exporting,
    exportingReport,
    verification,
    onVerify,
    onExportCert,
    onDownloadReport,
  }: Props = $props();

  const VERIFY_BOX: Record<VerificationView["tone"], string> = {
    pass: "border-success/30 bg-success-muted/40",
    warn: "border-warning/30 bg-warning-muted/40",
    fail: "border-danger/30 bg-danger-muted/40",
  };
  const VERIFY_TITLE: Record<VerificationView["tone"], string> = {
    pass: "text-success",
    warn: "text-warning",
    fail: "text-danger-text",
  };
</script>

<div class="flex justify-between items-start gap-3 flex-wrap min-w-0">
  <div class="min-w-0">
    <h2 class="text-lg font-semibold text-text-primary leading-snug tracking-tight">{selectedSession?.goal || "Session"}</h2>
    <p class="text-xs text-text-muted mt-1.5">
      <span class="font-mono">{selectedId.slice(0, 8)}</span>
      {#if !eventsLoading}
        · {eventsLength} event{eventsLength === 1 ? "" : "s"}
        {#if refusalCount > 0}
          · <span class="text-danger-text font-medium">{refusalCount} refused</span>
        {/if}
      {/if}
    </p>
  </div>
  <div class="flex gap-3 flex-wrap shrink-0">
    <Button variant="secondary" onclick={onVerify} disabled={verifying} loading={verifying}>
      {verifying ? "Verifying…" : "Verify"}
    </Button>
    {#if exportsSupported}
      <Button variant="primary" onclick={onExportCert} disabled={exporting} loading={exporting}>
        {exporting ? "Exporting…" : "Certificate"}
      </Button>
      <Button variant="secondary" onclick={onDownloadReport} disabled={exportingReport} loading={exportingReport}>
        {exportingReport ? "Downloading…" : "Report"}
      </Button>
    {:else}
      <p class="text-xs text-warning m-0 max-w-xs leading-relaxed">
        Certificate and report export are unavailable on this ledger connection. Check Settings and restart if you recently changed the database URL.
      </p>
    {/if}
  </div>
</div>

{#if verification}
  <div class="rounded-xl border px-5 py-4 {VERIFY_BOX[verification.tone]}" role="status">
    <p class="text-sm font-semibold {VERIFY_TITLE[verification.tone]}">{verification.title}</p>
    <p class="text-sm text-text-primary mt-1 leading-relaxed">{verification.detail}</p>
  </div>
{/if}
