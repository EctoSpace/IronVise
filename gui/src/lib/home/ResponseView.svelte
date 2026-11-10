<!-- ResponseView: the agent's last response, pretty or raw. -->
<script lang="ts">
  import { parseResponse } from "./parseResponse";

  interface Props {
    result: string;
    rawResult: unknown;
    showRawOutput: boolean;
  }

  let { result, rawResult, showRawOutput = $bindable(false) }: Props = $props();
</script>

<div class="flex justify-between items-center mt-2 gap-2 flex-wrap">
  <span class="text-xs font-semibold text-text-muted uppercase tracking-wide">Response</span>
  <label class="flex items-center gap-2 text-xs text-text-muted cursor-pointer select-none">
    <input type="checkbox" bind:checked={showRawOutput} />
    Raw
  </label>
</div>
{#if showRawOutput}
  <pre class="bg-surface-elevated/20 border border-border-muted/20 rounded-2xl p-5 font-mono text-xs text-text-primary whitespace-pre-wrap overflow-y-auto overflow-x-auto max-h-[200px] break-words">{JSON.stringify(rawResult, null, 2)}</pre>
{:else}
  <div class="bg-surface-elevated/20 border border-border-muted/20 rounded-2xl p-5 text-sm text-text-primary whitespace-pre-wrap overflow-y-auto overflow-x-auto max-h-[200px] break-words leading-relaxed">{parseResponse(rawResult ?? result)}</div>
{/if}
