<!--
  ApiKeyField: the API key for a hosted provider (Anthropic, OpenAI).

  The key goes to the OS credential store through `set_api_key` and is never
  read back: the field only learns whether a key is stored, or whether the
  environment variable is set (used when nothing is stored). It is not part
  of the Settings payload, settings.json or the config API.
-->
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { Button, Input } from "../ui";

  interface Props {
    /** The environment variable the backend reads, e.g. ANTHROPIC_API_KEY. */
    envName: string;
    /** Provider name for the text, e.g. "Anthropic". */
    provider: string;
    /** Called after a key is saved or removed (to list models again). */
    onchange?: () => void;
  }

  let { envName, provider, onchange }: Props = $props();

  type Status = { stored: boolean; environment: boolean; store: string };
  let status = $state<Status | null>(null);
  let draft = $state("");
  let busy = $state(false);
  let error = $state("");

  async function refresh(name: string) {
    error = "";
    try {
      status = await invoke<Status>("api_key_status", { name });
    } catch (e) {
      status = null;
      error = String(e);
    }
  }

  $effect(() => {
    void refresh(envName);
  });

  async function save() {
    busy = true;
    error = "";
    try {
      status = await invoke<Status>("set_api_key", { name: envName, key: draft });
      draft = "";
      onchange?.();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function remove() {
    busy = true;
    error = "";
    try {
      status = await invoke<Status>("delete_api_key", { name: envName });
      onchange?.();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="min-w-0">
  <label for="settings-api-key" class="block text-sm font-medium text-text-primary mb-1.5">{provider} API key</label>
  <div class="flex items-stretch gap-2 min-w-0">
    <Input
      id="settings-api-key"
      type="password"
      class="font-mono text-xs flex-1 min-w-0 sm:max-w-[520px]"
      bind:value={draft}
      placeholder={status?.stored ? "Saved. Enter a new key to replace it." : "Paste the key"}
    />
    <Button variant="secondary" size="sm" class="shrink-0 self-stretch h-auto" onclick={save} disabled={busy || !draft.trim()} loading={busy}>
      Save key
    </Button>
    {#if status?.stored}
      <Button variant="ghost" size="sm" class="shrink-0 self-stretch h-auto" onclick={remove} disabled={busy}>Remove</Button>
    {/if}
  </div>
  <p class="text-xs leading-relaxed mt-2 mb-0 break-words {error ? 'text-danger-text' : 'text-text-muted'}">
    {#if error}
      {error}
    {:else if status?.stored}
      A key is saved in {status.store}. It is not written to the settings file.
    {:else if status?.environment}
      Using the key from the environment. A key saved here takes its place.
    {:else if status}
      No key yet. {provider} needs one to list models and run audits. It is kept in {status.store}, not in the settings file.
    {/if}
  </p>
</div>
