<!-- ApprovalCard: a policy asked for a human decision on the next action. -->
<script lang="ts">
  import { Button } from "../ui";

  interface Props {
    approval: Record<string, unknown>;
    reason: string;
    deciding: boolean;
    error: string;
    ondecide: (approved: boolean) => void;
  }

  let { approval, reason = $bindable(""), deciding, error, ondecide }: Props = $props();
</script>

  <div class="mt-2 rounded-2xl border border-warning/30 bg-warning-muted p-5 flex flex-col gap-4">
    <div class="flex items-center gap-2">
      <span class="text-xs font-bold text-warning uppercase tracking-wide">Approval required</span>
    </div>
    {#if approval.action_name}
      <p class="text-sm text-text-primary m-0">
        <span class="font-semibold">Action:</span> {String(approval.action_name)}
      </p>
    {/if}
    {#if approval.action_params_summary}
      <p class="text-xs text-text-secondary m-0 font-mono break-all">{String(approval.action_params_summary)}</p>
    {/if}
    {#if approval.description}
      <p class="text-xs text-text-secondary m-0">{String(approval.description)}</p>
    {/if}
    <textarea
      class="w-full bg-surface-elevated/30 border border-border-muted/30 rounded-xl text-text-primary px-5 py-3 text-sm resize-none outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
      bind:value={reason}
      placeholder="Reason (optional)…"
      rows="2"
    ></textarea>
    <div class="flex flex-wrap gap-3">
      <Button variant="success" class="flex-1" onclick={() => ondecide(true)} disabled={deciding}>
        {deciding ? "…" : "Approve"}
      </Button>
      <Button variant="danger" class="flex-1" onclick={() => ondecide(false)} disabled={deciding}>
        {deciding ? "…" : "Deny"}
      </Button>
    </div>
    {#if error}
      <p class="text-xs text-danger mt-1">{error}</p>
    {/if}
  </div>
