<!--
  Access - Tokens and Webhooks under one nav item so the primary sidebar
  stays short. Admin surface, not a first-run destination.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import TokensView from "./TokensView.svelte";
  import WebhooksView from "./WebhooksView.svelte";
  import { fetchCapabilities } from "./backend";

  let section = $state<"tokens" | "webhooks">("tokens");
  let webhooksLive = $state(true);

  onMount(() => {
    fetchCapabilities().then((c) => {
      webhooksLive = c.webhooks_live;
    });
  });
</script>

<div class="flex flex-col gap-6 min-w-0">
  <header class="min-w-0">
    <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted m-0">Access</h2>
    <p class="text-sm text-text-secondary mt-2 mb-0 leading-relaxed">
      API tokens for Observer clients, and outbound webhooks for SIEM-style event delivery.
    </p>
  </header>

  <div class="flex flex-wrap items-center gap-2">
    <button
      type="button"
      class="rounded-xl px-4 py-2 text-sm transition-all duration-200
        {section === 'tokens'
          ? 'bg-accent/15 text-accent-text font-medium'
          : 'bg-transparent text-text-secondary hover:bg-surface-elevated hover:text-text-primary'}"
      onclick={() => (section = "tokens")}
    >
      Tokens
    </button>
    <button
      type="button"
      class="rounded-xl px-4 py-2 text-sm transition-all duration-200
        {section === 'webhooks'
          ? 'bg-accent/15 text-accent-text font-medium'
          : 'bg-transparent text-text-secondary hover:bg-surface-elevated hover:text-text-primary'}"
      onclick={() => (section = "webhooks")}
    >
      Webhooks <span class="text-[10px] uppercase tracking-wide text-text-muted ml-1">preview</span>
    </button>
  </div>

  {#if section === "tokens"}
    <TokensView />
  {:else}
    {#if !webhooksLive}
      <div class="bg-warning-muted border border-warning/30 text-warning px-4 py-3 rounded-xl text-sm leading-relaxed">
        Webhook rows can be saved on SQLite, but delivery is off until the live ledger is PostgreSQL.
        Set a Postgres URL in Settings (or Custom setup) and restart the app.
      </div>
    {/if}
    <WebhooksView />
  {/if}
</div>
