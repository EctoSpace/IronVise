<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  let content = $state("");
  /** The exposition text as rows: a counter and its HELP line read faster
   *  than the raw format, which stays one click away. */
  interface MetricRow { name: string; value: string; help: string; type: string }
  const rows = $derived.by((): MetricRow[] => {
    const help: Record<string, string> = {};
    const type: Record<string, string> = {};
    const out: MetricRow[] = [];
    for (const raw of content.split("\n")) {
      const line = raw.trim();
      if (!line) continue;
      let m = line.match(/^# HELP (\S+) (.*)$/);
      if (m) { help[m[1]] = m[2]; continue; }
      m = line.match(/^# TYPE (\S+) (\S+)$/);
      if (m) { type[m[1]] = m[2]; continue; }
      if (line.startsWith("#")) continue;
      m = line.match(/^(\S+?)(\{[^}]*\})?\s+(\S+)/);
      if (!m) continue;
      out.push({ name: m[1] + (m[2] ?? ""), value: m[3], help: help[m[1]] ?? "", type: type[m[1]] ?? "" });
    }
    return out;
  });
  let showRaw = $state(false);
  let error = $state("");
  let loading = $state(true);

  onMount(load);

  async function load() {
    if (!isTauri()) {
      error = "Run this app via the IronVise desktop window (`make start`, or .\\ironvise-win.ps1 on Windows), not in a browser.";
      loading = false;
      return;
    }
    loading = true;
    error = "";
    try {
      content = await invoke<string>("get_prometheus_metrics");
    } catch (e) {
      error = String(e);
      content = "";
    } finally {
      loading = false;
    }
  }
</script>

<div class="flex flex-col gap-6 pb-6">
  <div class="rounded-2xl p-7 bg-surface shadow-sm border border-border-muted/40 flex flex-col flex-1 min-h-0">
    <!-- No px-2.5: the panel's p-7 provides uniform inset on all sides -->
    <div class="flex justify-between items-center mb-6">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted">Prometheus Metrics</h2>
      <button
        class="bg-transparent border border-border-muted/30 rounded-xl text-accent-text px-5 py-2.5 text-sm cursor-pointer hover:bg-surface-elevated transition-all duration-200 disabled:opacity-60 disabled:cursor-not-allowed"
        onclick={load}
        disabled={loading}
      >
        <!-- ↻ renders unreliably in the Tauri WebView; use plain text -->
        {loading ? "Loading…" : "Refresh"}
      </button>
    </div>

    {#if error}
      <!-- No px-2.5: error text aligns with the panel's own p-7 boundary -->
      <p class="text-danger text-sm">{error}</p>
    {:else if loading}
      <p class="text-text-muted text-sm">Loading metrics…</p>
    {:else}
      <!-- No mx-2.5: the pre already has p-6 inner padding; panel provides outer -->
      {#if rows.length === 0}
        <p class="text-text-muted text-sm">No metrics yet.</p>
      {:else}
        <table class="w-full border-collapse text-sm">
          <thead>
            <tr>
              <th class="text-left text-[11px] font-semibold uppercase tracking-wide text-text-secondary px-4 py-2.5 border-b border-border-muted/40">Metric</th>
              <th class="text-right text-[11px] font-semibold uppercase tracking-wide text-text-secondary px-4 py-2.5 border-b border-border-muted/40 w-32">Value</th>
              <th class="text-left text-[11px] font-semibold uppercase tracking-wide text-text-secondary px-4 py-2.5 border-b border-border-muted/40">What it counts</th>
            </tr>
          </thead>
          <tbody>
            {#each rows as r (r.name)}
              <tr>
                <td class="px-4 py-3 border-b border-border-muted/20 font-mono text-xs text-text-primary break-all">{r.name}</td>
                <td class="px-4 py-3 border-b border-border-muted/20 text-right font-semibold tabular-nums text-text-primary">{r.value}</td>
                <td class="px-4 py-3 border-b border-border-muted/20 text-text-secondary">{r.help}{#if r.type} <span class="text-text-muted">· {r.type}</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        <details class="mt-5 text-xs text-text-muted" bind:open={showRaw}>
          <summary class="cursor-pointer select-none w-fit hover:text-text-secondary">Raw exposition text, as /metrics serves it</summary>
          <pre class="mt-3 overflow-auto bg-background border border-border-muted/40 rounded-xl p-5 text-xs font-mono text-text-primary whitespace-pre-wrap break-all">{content}</pre>
        </details>
      {/if}
    {/if}
  </div>
</div>
