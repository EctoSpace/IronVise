<!-- CredentialCard: the session's Verifiable Credential, loaded when a
     completed session is selected, with on-demand signature verification. -->
<script lang="ts">
  interface Props {
    vcLoading: boolean;
    vcError: string;
    vcMissing: boolean;
    vcData: { vc_jwt: string; vc_payload: any } | null;
    showVcDetails: boolean;
    vcVerifying: boolean;
    vcVerifyResult: { valid?: boolean; signature_verified?: boolean; reason?: string; claims?: any; error?: string } | null;
    onToggleDetails: () => void;
    onVerifyVc: () => void;
  }

  let {
    vcLoading,
    vcError,
    vcMissing,
    vcData,
    showVcDetails,
    vcVerifying,
    vcVerifyResult,
    onToggleDetails,
    onVerifyVc,
  }: Props = $props();
</script>

{#if vcLoading}
  <p class="text-text-muted text-sm">Loading credential…</p>
{:else if vcError && vcMissing}
  <p class="text-xs text-text-muted">No verifiable credential for this session. Only completed agent-mode sessions issue one.</p>
{:else if vcError}
  <div class="bg-danger-muted border border-danger/20 text-danger px-5 py-4 rounded-xl text-sm">{vcError}</div>
{:else if vcData}
  <div class="bg-surface-elevated/20 border border-border-muted/40 rounded-xl p-5">
    <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
      <h3 class="m-0 text-sm font-semibold text-text-primary">Verifiable Credential</h3>
      <button
        type="button"
        class="bg-transparent border border-border-muted/30 rounded-xl text-accent-text px-4 py-2 text-xs cursor-pointer hover:bg-surface-elevated transition-all duration-200"
        onclick={onToggleDetails}
      >
        {showVcDetails ? "Hide JWT / payload" : "Show JWT / payload"}
      </button>
    </div>
    {#if showVcDetails}
      <textarea readonly rows={5} class="w-full bg-background border border-border-muted/40 rounded-xl text-text-primary font-mono resize-none mb-4">{vcData.vc_jwt}</textarea>
      <pre class="bg-background border border-border-muted/30 rounded-xl p-4 text-text-primary text-sm overflow-x-auto">{JSON.stringify(vcData.vc_payload, null, 2)}</pre>
    {/if}
    <div class="flex items-center gap-4 mt-4">
      <button
        class="bg-transparent border border-border-muted/30 rounded-xl text-accent-text px-4 py-2 text-xs cursor-pointer hover:bg-surface-elevated transition-all duration-200"
        onclick={onVerifyVc}
        disabled={vcVerifying}
      >
        {vcVerifying ? "Verifying…" : "Verify VC"}
      </button>
      {#if vcVerifyResult}
        {#if vcVerifyResult.error}
          <span class="text-sm px-3 py-1.5 rounded-full bg-danger-muted border border-danger/20 text-danger">{vcVerifyResult.error}</span>
        {:else if vcVerifyResult.valid === false}
          <span class="text-sm px-3 py-1.5 rounded-full bg-danger-muted border border-danger/20 text-danger">{vcVerifyResult.reason ?? "Invalid"}</span>
        {:else if vcVerifyResult.signature_verified === true}
          <span class="text-sm px-3 py-1.5 rounded-full bg-success-muted border border-success/20 text-success">Signature valid</span>
        {:else}
          <span class="text-sm px-3 py-1.5 rounded-full bg-warning-muted border border-warning/20 text-warning">Unsigned: nothing proves who issued it</span>
        {/if}
      {/if}
    </div>
  </div>
{/if}
