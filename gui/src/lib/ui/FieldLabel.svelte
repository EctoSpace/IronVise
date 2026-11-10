<!--
  FieldLabel - the small uppercase caption above a value or control.

  Two spellings of this had drifted apart across the screens (`tracking-wide`
  and `tracking-wider mb-1`), which is the kind of difference nobody notices
  individually and everybody notices in aggregate. `spacing` keeps both
  behaviours available while the markup converges on one component.

  Renders a <label> when `for` is given so the caption is associated with its
  control, and a <span> otherwise - a <label> pointing at nothing is worse for
  a screen reader than no label at all.
-->
<script lang="ts">
  import type { Snippet } from "svelte";
  import { tv } from "tailwind-variants";

  interface Props {
    for?: string;
    spacing?: "none" | "below";
    class?: string;
    children: Snippet;
  }

  let {
    for: htmlFor,
    spacing = "none",
    class: className = "",
    children,
  }: Props = $props();

  const label = tv({
    base: "block text-xs text-text-muted uppercase tracking-wide",
    variants: {
      spacing: { none: "", below: "mb-1" },
    },
  });
</script>

{#if htmlFor}
  <label for={htmlFor} class={label({ spacing, class: className })}>
    {@render children()}
  </label>
{:else}
  <span class={label({ spacing, class: className })}>{@render children()}</span>
{/if}
