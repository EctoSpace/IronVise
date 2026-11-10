<!-- DetectingStep (0): probing for Ollama, existing databases, hardware. -->
<script lang="ts">
  import { Button } from "../ui";

  interface Props {
    detectionError: string;
    onRetry: () => void;
  }

  let { detectionError, onRetry }: Props = $props();
</script>

<div class="text-center py-16">
  <div class="h-10 w-10 mx-auto mb-6 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
  <h2 class="text-xl font-bold text-text-primary mb-2">Detecting system capabilities…</h2>
  <p class="text-text-secondary text-sm">Checking for Ollama, existing databases, and hardware.</p>
  {#if detectionError}
    <div class="mt-6 p-4 rounded-lg bg-danger-muted border border-danger/30 text-sm text-danger text-left">
      <p class="font-semibold mb-1">Detection failed</p>
      <p>{detectionError}</p>
      <div class="mt-3">
        <Button variant="primary" onclick={onRetry}>Retry</Button>
      </div>
    </div>
  {/if}
</div>
