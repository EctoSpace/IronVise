<!--
  CommandPalette: ⌘K / Ctrl+K. A combobox + listbox over every screen the
  sidebar can reach, every Settings section, and a short list of cheap,
  already-exposed actions (theme switching, opening DevTools).

  Filtering/ranking lives in commandPalette.ts so it has its own unit tests;
  this file is the dialog, the keyboard wiring and the DOM.
-->
<script lang="ts">
  import { filterPaletteItems, groupPaletteItems, type PaletteItem } from "./commandPalette";
  import { NO_SUGGESTIONS } from "./ui/noSuggestions";

  interface Props {
    items: PaletteItem[];
    open?: boolean;
    onselect: (item: PaletteItem) => void;
  }

  let { items, open = $bindable(false), onselect }: Props = $props();

  let query = $state("");
  let activeIndex = $state(0);
  let inputEl = $state<HTMLInputElement | null>(null);
  let lastFocused: HTMLElement | null = null;

  const results = $derived(filterPaletteItems(items, query));
  const groups = $derived(groupPaletteItems(results));
  const flat = $derived(groups.flatMap((g) => g.items));

  $effect(() => {
    if (!open) return;
    lastFocused = document.activeElement as HTMLElement | null;
    query = "";
    activeIndex = 0;
    // The dialog is not in the DOM yet on the same tick it opens.
    queueMicrotask(() => inputEl?.focus());
  });

  // Clamp the selection when filtering shrinks the list.
  $effect(() => {
    if (flat.length === 0) {
      if (activeIndex !== 0) activeIndex = 0;
    } else if (activeIndex >= flat.length) {
      activeIndex = flat.length - 1;
    }
  });

  $effect(() => {
    const id = flat[activeIndex]?.id;
    if (!id) return;
    document.getElementById(`command-palette-option-${id}`)?.scrollIntoView({ block: "nearest" });
  });

  function close() {
    open = false;
    lastFocused?.focus();
    lastFocused = null;
  }

  function choose(item: PaletteItem) {
    onselect(item);
    close();
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (flat.length) activeIndex = (activeIndex + 1) % flat.length;
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (flat.length) activeIndex = (activeIndex - 1 + flat.length) % flat.length;
    } else if (e.key === "Enter") {
      e.preventDefault();
      const item = flat[activeIndex];
      if (item) choose(item);
    } else if (e.key === "Tab") {
      // The input is the only focusable element in the dialog; trap focus on it.
      e.preventDefault();
    }
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] px-4 bg-background/70 backdrop-blur-sm animate-fade-in"
    onclick={close}
  >
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      tabindex="-1"
      class="w-full max-w-lg rounded-2xl bg-surface border border-border-muted/40 shadow-xl overflow-hidden animate-slide-up"
      onclick={(e) => e.stopPropagation()}
      onkeydown={onKeydown}
    >
      <div class="flex items-center gap-3 px-4 border-b border-border-muted/40">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="shrink-0 text-text-muted" aria-hidden="true">
          <circle cx="11" cy="11" r="7" stroke-linecap="round" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" stroke-linecap="round" />
        </svg>
        <input
          bind:this={inputEl}
          bind:value={query}
          role="combobox"
          aria-expanded="true"
          aria-controls="command-palette-listbox"
          aria-autocomplete="list"
          {...NO_SUGGESTIONS}
          aria-activedescendant={flat[activeIndex] ? `command-palette-option-${flat[activeIndex].id}` : undefined}
          aria-label="Search screens, settings and actions"
          placeholder="Search screens, settings, actions…"
          class="flex-1 min-w-0 h-14 bg-transparent border-none outline-none text-sm text-text-primary placeholder:text-text-muted"
          oninput={() => (activeIndex = 0)}
        />
        <kbd class="text-[11px] text-text-muted border border-border-muted/40 rounded-md px-1.5 py-0.5 shrink-0">Esc</kbd>
      </div>

      <ul id="command-palette-listbox" role="listbox" aria-label="Results" class="max-h-[50vh] overflow-y-auto py-2">
        {#if flat.length === 0}
          <li role="presentation" class="px-4 py-6 text-sm text-text-muted text-center">No matches.</li>
        {/if}
        {#each groups as g (g.group)}
          <li role="presentation" class="px-4 pt-3 pb-1 text-[11px] font-semibold uppercase tracking-wide text-text-secondary">{g.group}</li>
          {#each g.items as item (item.id)}
            {@const idx = flat.indexOf(item)}
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <li
              id={`command-palette-option-${item.id}`}
              role="option"
              aria-selected={idx === activeIndex}
              class="mx-2 px-3 py-2.5 rounded-xl text-sm cursor-pointer flex items-center justify-between gap-3 {idx === activeIndex
                ? 'bg-accent/12 text-accent-text'
                : 'text-text-primary hover:bg-surface-elevated'}"
              onmouseenter={() => (activeIndex = idx)}
              onclick={() => choose(item)}
            >
              <span class="truncate">{item.label}</span>
              {#if item.hint}<span class="text-xs text-text-muted shrink-0">{item.hint}</span>{/if}
            </li>
          {/each}
        {/each}
      </ul>
    </div>
  </div>
{/if}
