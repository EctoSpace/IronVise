<!--
  Shared Button primitive.
  Usage:
    <Button variant="primary" size="md" onclick={handler}>Label</Button>
-->
<script lang="ts">
  import { cn } from "../utils";
  import type { Snippet } from "svelte";

  type Variant = "primary" | "secondary" | "ghost" | "danger" | "success";
  type Size = "sm" | "md" | "lg" | "icon";

  interface Props {
    variant?: Variant;
    size?: Size;
    disabled?: boolean;
    loading?: boolean;
    class?: string;
    children: Snippet;
    onclick?: (e: MouseEvent) => void;
    type?: "button" | "submit" | "reset";
    /**
     * Accessible name, for buttons whose visible content is an icon or a bare
     * glyph. `size="icon"` buttons have no text at all, so a screen reader
     * announces them as "button" and nothing else without this.
     */
    ariaLabel?: string;
    /** Wired through for disclosure buttons that toggle a region. */
    ariaExpanded?: boolean;
  }

  let {
    variant = "primary",
    size = "md",
    disabled = false,
    loading = false,
    class: className = "",
    children,
    onclick,
    type = "button",
    ariaLabel,
    ariaExpanded,
  }: Props = $props();

  const base =
    "inline-flex items-center justify-center gap-2 font-medium transition-all duration-200 " +
    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent " +
    "disabled:pointer-events-none disabled:opacity-50 cursor-pointer select-none active:scale-[0.98]";

  // White-on-accent / white-on-success / white-on-danger fail WCAG AA. Use dark
  // text on a light fill for primary, and muted fills with coloured text for
  // success/danger - same weight, readable contrast.
  const variants: Record<Variant, string> = {
    primary:
      "bg-accent-text text-text-inverse hover:bg-accent shadow-sm",
    secondary:
      "bg-surface-elevated text-text-primary border border-border-muted/40 hover:bg-surface hover:border-text-muted shadow-xs",
    ghost:
      "text-text-secondary hover:bg-surface-elevated hover:text-text-primary",
    danger:
      "bg-danger-muted text-danger-text border border-danger/30 hover:bg-danger/20",
    success:
      "bg-success-muted text-success border border-success/30 hover:bg-success/20",
  };

  const sizes: Record<Size, string> = {
    sm: "h-9 px-4 text-xs rounded-xl shrink-0",
    md: "h-11 px-6 text-sm rounded-xl shrink-0",
    lg: "h-[52px] px-8 text-base rounded-xl shrink-0",
    icon: "h-11 w-11 rounded-xl shrink-0",
  };
</script>

<button
  {type}
  disabled={disabled || loading}
  class={cn(base, variants[variant], sizes[size], className)}
  aria-label={ariaLabel}
  aria-expanded={ariaExpanded}
  aria-busy={loading || undefined}
  onclick={onclick}
>
  {#if loading}
    <span class="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full"></span>
  {/if}
  {@render children()}
</button>
