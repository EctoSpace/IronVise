<!--
  CopyButton - clipboard copy with visual success feedback.
  Swaps the icon to a checkmark for 2 seconds after copying.
-->
<script lang="ts">
  interface Props {
    text: string;
    class?: string;
    title?: string;
  }

  let { text, class: cls = "", title = "Copy to clipboard" }: Props = $props();

  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch (e) {
      console.error("Clipboard write failed:", e);
    }
  }
</script>

<button
  type="button"
  class="inline-flex items-center gap-1.5 bg-transparent border border-border-muted/50 rounded-lg px-2.5 py-1.5
         text-xs text-text-secondary hover:text-text-primary hover:bg-surface-elevated
         transition-all duration-150 cursor-pointer {cls}"
  onclick={copy}
  {title}
  aria-label={title}
>
  <!-- Inline SVG, not a symbol character: Ubuntu 22.04's default fonts have
       no glyph for U+29C9 and drew an empty box (WSL smoke test, 2026-10-06). -->
  {#if copied}
    <svg class="text-success shrink-0" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12" /></svg>
    <span class="text-success">Copied</span>
  {:else}
    <svg class="shrink-0" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
    <span>Copy</span>
  {/if}
</button>
