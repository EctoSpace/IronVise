<!-- AgentSection: limits of the agent loop. Allowed domains live in Tripwire. -->
<script lang="ts">
  import { SELECT_CLASS } from "./selectClass";
  import { type Config, HINT_CLASS, LABEL_CLASS, SECTION_CLASS, SECTION_TITLE_CLASS } from "./types";

  let {
    config = $bindable(),
    visibleFields = null,
  }: { config: Config; visibleFields?: Set<string> | null } = $props();

  function shows(field: string): boolean {
    return !visibleFields || visibleFields.has(field);
  }
</script>

<section id="settings-agent" tabindex="-1" class={SECTION_CLASS}>
  <h3 class={SECTION_TITLE_CLASS}>Agent</h3>
  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 min-w-0">
    {#if shows("Max steps per session")}
      <div class="min-w-0">
        <label for="settings-max-steps" class={LABEL_CLASS}>Max steps per session</label>
        <input id="settings-max-steps" type="number" class="{SELECT_CLASS} sm:max-w-[160px]" bind:value={config.max_steps} min="1" />
        <p class={HINT_CLASS}>The loop stops after this many actions.</p>
      </div>
    {/if}
    {#if shows("Allowed domains (HTTP)")}
      <div class="min-w-0">
        <span class={LABEL_CLASS}>Allowed domains (HTTP)</span>
        <p class="text-sm text-text-secondary leading-relaxed m-0 break-words">
          Set once, in Tripwire: that list is the one every check enforces. This screen used to carry a second copy that stopped counting as soon as Tripwire was saved.
        </p>
      </div>
    {/if}
  </div>
</section>
