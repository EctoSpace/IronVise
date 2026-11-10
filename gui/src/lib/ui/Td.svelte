<!--
  Td - a table body cell. Pairs with Th.

  The divider here is deliberately lighter than Th's (/10 against /15): the
  header rule should read as a boundary and the row rules as separators. That
  distinction was already present in the copied strings and is worth keeping
  rather than flattening to one value.
-->
<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../utils";

  interface Props {
    align?: "left" | "right";
    /** Muted styling for secondary values such as hashes or timestamps. */
    muted?: boolean;
    class?: string;
    /** Optional: an actions or spacer column legitimately has no content. */
    children?: Snippet;
  }

  let {
    align = "left",
    muted = false,
    class: className = "",
    children,
  }: Props = $props();
</script>

<td
  class={cn(
    "px-4 py-3 border-b border-border-muted/10",
    muted ? "text-text-muted" : "text-text-primary",
    align === "right" ? "text-right" : "text-left",
    className,
  )}
>
  {@render children?.()}
</td>
