<!-- LedgerSection: which ledger is live, and the database for the next start. -->
<script lang="ts">
  import { Input } from "../ui";
  import { type Config, HINT_CLASS, LABEL_CLASS, SECTION_CLASS, SECTION_TITLE_CLASS } from "./types";

  let {
    config = $bindable(),
    visibleFields = null,
  }: { config: Config; visibleFields?: Set<string> | null } = $props();

  function shows(field: string): boolean {
    return !visibleFields || visibleFields.has(field);
  }
</script>

<section id="settings-ledger" tabindex="-1" class={SECTION_CLASS}>
  <h3 class={SECTION_TITLE_CLASS}>Ledger</h3>
  <div class="flex items-center gap-3 rounded-xl bg-surface-elevated border border-border-muted/40 px-4 py-3 min-w-0">
    <span class="w-2 h-2 rounded-full shrink-0 {config.ledger_backend === 'postgres' ? 'bg-accent' : 'bg-success'}" aria-hidden="true"></span>
    <div class="min-w-0 flex-1">
      <div class="text-sm font-medium text-text-primary">
        Running on {config.ledger_backend === "postgres" ? "PostgreSQL" : config.ledger_backend === "sqlite" ? "SQLite, embedded" : (config.ledger_backend ?? "an unknown backend")}
      </div>
      <div class="text-xs text-text-muted mt-0.5">
        {#if config.agent_supported}Home → Run is available on this ledger.{:else}Home → Run is unavailable on this ledger backend.{/if}
      </div>
    </div>
    <span class="text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full bg-success-muted text-success shrink-0">live</span>
  </div>
  {#if shows("Database for the next start")}
    <div class="min-w-0">
      <label for="settings-database-url" class={LABEL_CLASS}>Database for the next start</label>
      <Input id="settings-database-url" class="font-mono text-xs" bind:value={config.database_url} placeholder="postgres://… or leave empty for SQLite" />
      <p class={HINT_CLASS}>Leave empty for the embedded SQLite ledger. A PostgreSQL URL takes effect after a restart; the bar at the bottom says so when this changes.</p>
    </div>
  {/if}
</section>
