<!-- DangerZone: demo mode only. Resets the test database. -->
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { Button } from "../ui";

  let resetting = $state(false);
  let message = $state("");

  async function reset() {
    resetting = true;
    message = "";
    try {
      const res = await invoke<{ message?: string }>("reset_demo_data");
      message = res?.message ?? "Database reset successfully.";
    } catch (e) {
      message = `Reset failed: ${e}`;
    }
    resetting = false;
  }
</script>

<section id="settings-danger" class="rounded-2xl bg-surface border border-danger/40 shadow-sm p-6 flex flex-col gap-3 min-w-0 scroll-mt-4">
  <h3 class="text-xs font-semibold uppercase tracking-[0.1em] text-danger-text m-0">Danger zone · demo mode</h3>
  <div class="flex items-start justify-between gap-4 min-w-0 flex-wrap">
    <div class="min-w-0 flex-1">
      <p class="text-sm font-medium text-text-primary m-0">Reset the test database</p>
      <p class="text-xs text-text-muted leading-relaxed mt-1 mb-0 break-words">Erases every session, event, snapshot and action log. Tokens, webhooks and policy files stay.</p>
      {#if message}
        <p class="text-sm mt-2 mb-0 break-words {message.startsWith('Reset failed') ? 'text-danger-text' : 'text-success'}">{message}</p>
      {/if}
    </div>
    <Button variant="danger" onclick={reset} disabled={resetting} loading={resetting}>
      {resetting ? "Resetting…" : "Reset test database"}
    </Button>
  </div>
</section>
