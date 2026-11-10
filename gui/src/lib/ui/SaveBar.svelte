<!--
  SaveBar - the one place a form's unsaved state is shown. Hidden while
  nothing changed; when something has, it sits at the bottom of the screen
  with Discard and Save and a line saying what the save will do (a restart
  needed, a change that applies to the next action). A form whose Save
  button lives 1,600 px down with no sign that anything changed was the
  previous design.

  Caller owns `dirty`, `saving` and the message; this is layout and the two
  buttons only.
-->
<script lang="ts">
  import { Button } from ".";

  interface Props {
    dirty: boolean;
    saving?: boolean;
    /** One sentence on what Save will do, or what it will not do yet. */
    message?: string;
    /** When true the message is drawn as a warning (a restart is needed). */
    warn?: boolean;
    onsave: () => void;
    ondiscard: () => void;
    saveLabel?: string;
  }

  let {
    dirty,
    saving = false,
    message = "",
    warn = false,
    onsave,
    ondiscard,
    saveLabel = "Save",
  }: Props = $props();
</script>

{#if dirty}
  <div
    role="status"
    class="sticky bottom-0 -mx-6 md:-mx-8 lg:-mx-10 mt-6 px-6 md:px-8 lg:px-10 py-3.5 bg-surface border-t border-border-muted/40 shadow-lg flex flex-wrap items-center gap-3 animate-slide-up"
  >
    <span class="text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full {warn ? 'bg-warning-muted text-warning' : 'bg-accent-muted text-accent-text'}">unsaved</span>
    <span class="text-sm text-text-secondary flex-1 min-w-[12rem]">{message}</span>
    <div class="flex gap-2">
      <Button variant="secondary" onclick={ondiscard} disabled={saving}>Discard</Button>
      <Button variant="primary" onclick={onsave} disabled={saving} loading={saving}>{saving ? "Saving…" : saveLabel}</Button>
    </div>
  </div>
{/if}
