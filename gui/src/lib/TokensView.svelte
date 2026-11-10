<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import { Button, FieldLabel, Td, Th } from "./ui";

  interface ApiToken {
    token_hash: string;
    role: string;
    label: string;
    created_at: string;
    expires_at: string | null;
  }

  let tokens = $state<ApiToken[]>([]);
  let loading = $state(false);
  let error = $state("");
  let success = $state("");

  let newLabel = $state("");
  let newRole = $state("agent");
  let newExpiryDays = $state<number | null>(null);
  let creating = $state(false);
  let newTokenValue = $state(""); // revealed once after creation

  onMount(load);

  async function load() {
    if (!isTauri()) return;
    loading = true;
    error = "";
    try {
      const data = await invoke<unknown>("get_tokens");
      tokens = Array.isArray(data) ? (data as ApiToken[]) : [];
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function create() {
    if (!isTauri() || !newLabel.trim()) return;
    creating = true;
    error = "";
    success = "";
    newTokenValue = "";
    try {
      const result = await invoke<{ token: string }>("create_token", {
        label: newLabel.trim(),
        role: newRole,
        expiryDays: newExpiryDays,
      });
      if (!result?.token) {
        throw new Error("Unexpected server response: missing 'token' field");
      }
      newTokenValue = result.token;
      success = "Token created. Copy it now - it won't be shown again.";
      newLabel = "";
      newExpiryDays = null;
      await load();
    } catch (e) {
      error = String(e);
    } finally {
      creating = false;
    }
  }

  async function deleteToken(hash: string) {
    if (!isTauri() || !confirm("Revoke this token? This cannot be undone.")) return;
    error = "";
    success = "";
    try {
      await invoke("delete_token", { tokenHash: hash });
      success = "Token revoked.";
      await load();
    } catch (e) {
      error = String(e);
    }
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "Never";
    return new Date(iso).toLocaleString();
  }
</script>

<div class="flex flex-col gap-6 pb-6">
  <h2 class="text-xl font-bold text-text-primary m-0">API Tokens</h2>
  <p class="text-text-muted text-sm m-0">Manage RBAC bearer tokens for REST API and dashboard access.</p>

  {#if error}
    <div class="bg-danger-muted border border-danger/30 text-danger-text px-4 py-3 rounded-xl text-sm">{error}</div>
  {:else if success}
    <div class="bg-success-muted border border-success/30 text-success px-4 py-3 rounded-xl text-sm">{success}</div>
  {/if}

  {#if newTokenValue}
    <div class="bg-warning-muted border border-warning/30 rounded-xl p-4 flex flex-col gap-2">
      <span class="text-warning text-sm font-semibold">Copy it now. It is shown once; the ledger keeps only its hash.</span>
      <code class="text-sm text-text-primary break-all">{newTokenValue}</code>
      <span class="text-xs text-text-muted">Put it in <code>ECTOLEDGER_TOKEN</code> where the hook runs.</span>
    </div>
  {/if}

  <!-- Create form -->
  <section class="bg-background rounded-2xl px-7 py-6 shadow-sm">
    <h3 class="text-base font-semibold text-text-primary mb-1 mt-0">Create New Token</h3>
    <p class="text-xs text-text-muted m-0 mb-4">Pick what it may do first; the label is for you.</p>
    <fieldset class="border-none p-0 m-0 mb-5 min-w-0">
      <legend class="sr-only">Role</legend>
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <label class="flex flex-col gap-1.5 rounded-xl border px-4 py-3.5 cursor-pointer min-w-0 transition-colors {newRole === 'agent' ? 'border-accent bg-accent-muted/40 ring-2 ring-accent/20' : 'border-border-muted/40 bg-surface-elevated/40 hover:border-border-muted/60'}">
          <span class="flex items-center gap-2">
            <input type="radio" name="role" value="agent" bind:group={newRole} class="sr-only" />
            <span class="text-sm font-semibold text-text-primary">agent</span>
            <span class="text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full bg-success-muted text-success">writes</span>
          </span>
          <span class="text-xs text-text-muted leading-relaxed">What the Claude Code hook and the SDKs use: opens sessions, appends events, reads its own. Cannot read other sessions' payloads.</span>
        </label>
        <label class="flex flex-col gap-1.5 rounded-xl border px-4 py-3.5 cursor-pointer min-w-0 transition-colors {newRole === 'auditor' ? 'border-accent bg-accent-muted/40 ring-2 ring-accent/20' : 'border-border-muted/40 bg-surface-elevated/40 hover:border-border-muted/60'}">
          <span class="flex items-center gap-2">
            <input type="radio" name="role" value="auditor" bind:group={newRole} class="sr-only" />
            <span class="text-sm font-semibold text-text-primary">auditor</span>
            <span class="text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full bg-accent-muted text-accent-text">reads</span>
          </span>
          <span class="text-xs text-text-muted leading-relaxed">Reads every session and verifies it; exports certificates and reports. Cannot change anything.</span>
        </label>
        <div class="flex flex-col gap-1.5 rounded-xl border border-dashed border-border-muted/60 bg-background px-4 py-3.5 min-w-0" aria-label="admin role, not available here">
          <span class="flex items-center gap-2">
            <span class="text-sm font-semibold text-text-secondary">admin</span>
            <span class="text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full bg-danger-muted text-danger-text">everything</span>
          </span>
          <span class="text-xs text-text-muted leading-relaxed">All of the above plus tokens, webhooks and policies. Minted only outside the app (<code>OBSERVER_TOKEN</code> or <code>POST /api/tokens</code>), so a script in this window can never mint one.</span>
        </div>
      </div>
    </fieldset>
    <div class="flex gap-4 flex-wrap mb-5">
      <div class="flex flex-col gap-1.5 flex-1 min-w-[140px]">
        <FieldLabel for="label">Label</FieldLabel>
        <input id="label" type="text" bind:value={newLabel} placeholder="e.g. CI pipeline, auditor@corp" class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-inherit focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200" />
      </div>
      <div class="flex flex-col gap-1.5 flex-1 min-w-[140px]">
        <FieldLabel for="expiry">Expiry (days)</FieldLabel>
        <input
          id="expiry"
          type="number"
          min="1"
          max="3650"
          bind:value={newExpiryDays}
          placeholder="Never"
          class="bg-surface-elevated/40 border border-border-muted/40 rounded-xl px-5 py-3 text-text-primary text-sm font-inherit focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
        />
      </div>
    </div>
    <Button variant="success" onclick={create} disabled={creating || !newLabel.trim()} loading={creating}>
      {creating ? "Creating…" : "Create Token"}
    </Button>
  </section>

  <!-- Token list -->
  <section class="bg-surface rounded-2xl px-7 py-6 shadow-sm">
    <div class="flex justify-between items-center gap-3 flex-wrap mb-5 min-w-0">
      <h3 class="text-base font-semibold text-text-primary m-0">Active Tokens</h3>
      <Button variant="ghost" size="sm" onclick={load}>↺ Refresh</Button>
    </div>
    {#if loading}
      <p class="text-text-muted text-sm">Loading tokens…</p>
    {:else if tokens.length === 0}
      <p class="text-text-muted text-sm">No tokens yet. Create one above.</p>
    {:else}
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr>
            <Th>Label</Th>
            <Th>Role</Th>
            <Th>Hash (truncated)</Th>
            <Th>Created</Th>
            <Th>Expires</Th>
            <Th></Th>
          </tr>
        </thead>
        <tbody>
          {#each tokens as t}
            <tr>
              <Td>{t.label}</Td>
              <Td>
                <span class="px-3 py-1.5 rounded-full text-xs font-semibold uppercase {t.role === 'admin' ? 'bg-danger-muted text-danger-text border border-danger/30' : t.role === 'auditor' ? 'bg-accent-muted text-accent-text border border-accent/30' : t.role === 'agent' ? 'bg-success-muted text-success border border-success/30' : 'bg-border text-text-primary'}">{t.role}</span>
              </Td>
              <Td><code class="text-xs text-text-muted">{t.token_hash.slice(0, 12)}…</code></Td>
              <Td>{formatDate(t.created_at)}</Td>
              <Td>{formatDate(t.expires_at)}</Td>
              <Td>
                <Button variant="danger" size="sm" onclick={() => deleteToken(t.token_hash)}>Revoke</Button>
              </Td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
</div>
