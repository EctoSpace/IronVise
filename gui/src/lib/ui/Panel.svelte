<!--
  Panel - an inset region *inside* a Card: a settings group, a stat tile, a
  callout. Card is the outer container; Panel is a subdivision of one.

  `tone` covers the callout cases that were previously written inline with
  ad-hoc colour classes, so a warning looks the same everywhere it appears.
-->
<script lang="ts">
  import type { Snippet } from "svelte";
  import { tv } from "tailwind-variants";

  interface Props {
    tone?: "default" | "warning" | "danger" | "success";
    class?: string;
    children: Snippet;
  }

  let { tone = "default", class: className = "", children }: Props = $props();

  const panel = tv({
    base: "p-5 rounded-xl border",
    variants: {
      tone: {
        default: "bg-surface-elevated border-border-muted/15",
        warning: "bg-warning-muted/20 border-warning/30",
        danger: "bg-danger-muted/20 border-danger/30",
        success: "bg-success-muted/20 border-success/30",
      },
    },
  });
</script>

<div class={panel({ tone, class: className })}>{@render children()}</div>
