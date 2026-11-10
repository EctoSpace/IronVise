<!--
  ListEditor - one way to edit a list of strings, everywhere a screen has one:
  allowed paths, allowed domains, banned patterns. Items are chips with a
  remove button; one field adds an item at a time, on Enter or Add, after
  the caller's `validate` has had its say. Duplicates are refused.

  Tripwire used to offer two textareas ("one per line") and one chip list
  for three lists of the same kind. Same idiom now, one component.

  `tone="deny"` draws the chips in the refusal colour: a banned pattern is
  not an allowance, and green chips said otherwise.
-->
<script lang="ts">
  import { Button } from ".";

  interface Props {
    items: string[];
    id: string;
    placeholder?: string;
    /** Return a message to refuse an item, or null to accept it. */
    validate?: (value: string) => string | null;
    tone?: "allow" | "deny";
    mono?: boolean;
    disabled?: boolean;
    /** Accessible name for the add field. */
    addLabel: string;
    class?: string;
  }

  let {
    items = $bindable([]),
    id,
    placeholder = "",
    validate,
    tone = "allow",
    mono = true,
    disabled = false,
    addLabel,
    class: className = "",
  }: Props = $props();

  let draft = $state("");
  let problem = $state<string | null>(null);

  function add() {
    const v = draft.trim();
    if (!v) return;
    if (items.includes(v)) {
      problem = "Already in the list.";
      return;
    }
    const refused = validate?.(v) ?? null;
    if (refused) {
      problem = refused;
      return;
    }
    items = [...items, v];
    draft = "";
    problem = null;
  }

  function remove(i: number) {
    items = items.filter((_, k) => k !== i);
  }

  const chip = {
    allow: "bg-surface-elevated border-border-muted/40 text-text-primary",
    deny: "bg-danger-muted/30 border-danger/30 text-danger-text",
  };
</script>

<div class="flex flex-col gap-3 min-w-0 {className}">
  {#if items.length}
    <ul class="flex flex-wrap gap-2 list-none m-0 p-0" aria-label="{addLabel}: current items">
      {#each items as item, i (item)}
        <li class="inline-flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs {mono ? 'font-mono' : ''} {chip[tone]} max-w-full">
          <span class="truncate">{item}</span>
          <button
            type="button"
            class="shrink-0 bg-transparent border-none cursor-pointer text-text-muted hover:text-text-primary p-0 leading-none text-sm disabled:opacity-50"
            aria-label="Remove {item}"
            {disabled}
            onclick={() => remove(i)}
          >×</button>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="text-xs text-text-muted m-0">Nothing in this list yet.</p>
  {/if}
  <div class="flex gap-2 min-w-0">
    <label for={id} class="sr-only">{addLabel}</label>
    <input
      {id}
      type="text"
      class="flex-1 min-w-0 h-10 rounded-xl border border-border-muted/40 bg-surface-elevated/40 px-4 text-sm {mono ? 'font-mono' : ''} text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200 disabled:opacity-50"
      {placeholder}
      {disabled}
      bind:value={draft}
      aria-invalid={problem ? "true" : undefined}
      aria-describedby={problem ? `${id}-problem` : undefined}
      oninput={() => (problem = null)}
      onkeydown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }}
    />
    <Button variant="secondary" size="sm" onclick={add} disabled={disabled || !draft.trim()}>Add</Button>
  </div>
  {#if problem}
    <p id="{id}-problem" class="text-xs text-danger-text m-0" role="alert">{problem}</p>
  {/if}
</div>
