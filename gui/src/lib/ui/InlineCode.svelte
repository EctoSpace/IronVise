<!--
  InlineCode - a short code token inside prose (an env var, a flag, a path).

  The most duplicated string in the app: the same twelve-class span appeared
  12 times across the screens before this existed.

  For multi-line or copyable blocks use CodeBlock instead.

  No `break-all`: it split short tokens at any line end ("settings.js / on").
  The base layer gives <code> `overflow-wrap: anywhere`, which breaks a token
  only when it cannot fit on a line of its own.
-->
<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../utils";

  interface Props {
    class?: string;
    children: Snippet;
  }

  let { class: className = "", children }: Props = $props();
</script>

<code class={cn("text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md", className)}>
  {@render children()}
</code>
