<!--
  Th - a table header cell.

  Six copies of the same six-class string existed before this. Pairs with Td;
  the two carry the row rhythm (padding, divider weight) so a table added later
  lines up with the ones already there instead of being eyeballed.
-->
<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../utils";

  interface Props {
    /** Right-align numeric columns; the default suits text. */
    align?: "left" | "right";
    class?: string;
    /** Optional: an actions or spacer column legitimately has no content. */
    children?: Snippet;
  }

  let { align = "left", class: className = "", children }: Props = $props();
</script>

<th
  class={cn(
    "text-text-muted text-xs uppercase tracking-wide px-4 py-2.5",
    "border-b border-border-muted/15",
    align === "right" ? "text-right" : "text-left",
    className,
  )}
>
  {@render children?.()}
</th>
