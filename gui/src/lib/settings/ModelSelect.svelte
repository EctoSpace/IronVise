<!--
  ModelSelect: a model chosen from the models a provider lists, and nothing
  else. Used for the agent's model and the semantic guard's model.

  - Only listed names are offered. A saved name the provider lacks is not
    shown: the select sits on "Choose a model" until one is chosen.
  - Nothing listed: the select is empty ("No models listed"), never a text
    field and never a default name. Refresh asks the provider again.
  - Ollama reads a bare name as name:latest, so a saved "mistral" is the
    listed "mistral:latest".

  History: a <datalist> hid the list (it suggests only names matching the
  text in the field), then an "Other" entry kept the preset's default name
  when Ollama did not have it. Both found on Windows 11, October 2026.
-->
<script lang="ts" module>
  /** The listed name `value` is, if any. Ollama reads a bare name as
   *  name:latest, so "mistral" is the listed "mistral:latest". */
  export function listedName(models: string[], value: string | undefined): string {
    return value ? (models.find((m) => m === value || m === `${value}:latest`) ?? "") : "";
  }
</script>

<script lang="ts">
  import { Button } from "../ui";
  import { SELECT_CLASS } from "./selectClass";

  interface Props {
    id: string;
    /** Chat models the provider lists (the backend drops embedding models). */
    models: string[];
    /** The saved model name. */
    value?: string;
    loading?: boolean;
    onrefresh: () => void;
  }

  let { id, models, value = $bindable(""), loading = false, onrefresh }: Props = $props();

  const listed = $derived(listedName(models, value));
  const choice = $derived(listed);

  function choose(e: Event) {
    const v = (e.currentTarget as HTMLSelectElement).value;
    if (v) value = v;
  }
</script>

<div class="flex items-stretch gap-2 min-w-0">
  <select
    {id}
    class="{SELECT_CLASS} flex-1 min-w-0"
    value={choice}
    onchange={choose}
    disabled={models.length === 0}
  >
    {#if !choice}
      <option value="" disabled>{models.length > 0 ? "Choose a model" : "No models listed"}</option>
    {/if}
    {#each models as m}
      <option value={m}>{m}</option>
    {/each}
  </select>
  <Button variant="secondary" size="sm" class="shrink-0 self-stretch h-auto" onclick={onrefresh} disabled={loading} {loading} ariaLabel="Refresh the model list">
    {loading ? "Refreshing…" : "Refresh"}
  </Button>
</div>
