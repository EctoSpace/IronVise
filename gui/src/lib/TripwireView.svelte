<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import { Button, ListEditor, Switch, SaveBar } from "./ui";

  interface TripwireConfig {
    allowed_paths?: string[];
    allowed_domains?: string[];
    banned_command_patterns?: string[];
    min_justification_length?: number;
    require_https?: boolean;
    saved?: boolean;
  }

  let config = $state<TripwireConfig | null>(null);
  let allowedPaths = $state<string[]>([]);
  let allowedDomains = $state<string[]>([]);
  let bannedPatterns = $state<string[]>([]);
  let minJustification = $state(5);
  let requireHttps = $state(true);
  let error = $state("");
  let saveError = $state("");
  let saveSuccess = $state("");
  let saving = $state(false);
  /** The payload as last loaded or saved; `dirty` is "it differs". */
  let snapshot = $state("");

  function payload() {
    const minLen = Number(minJustification);
    return {
      allowed_paths: [...allowedPaths],
      allowed_domains: [...allowedDomains],
      banned_command_patterns: [...bannedPatterns],
      min_justification_length: Number.isNaN(minLen) || minLen < 0 ? 5 : Math.min(500, Math.floor(minLen)),
      require_https: requireHttps,
    };
  }
  const dirty = $derived(!!config && JSON.stringify(payload()) !== snapshot);

  onMount(load);

  async function load() {
    if (!isTauri()) return;
    try {
      const data = await invoke<unknown>("get_tripwire_config");
      config = data && typeof data === "object" && !Array.isArray(data) ? (data as TripwireConfig) : null;
      if (config) {
        allowedPaths = [...(config.allowed_paths ?? [])];
        allowedDomains = [...(config.allowed_domains ?? [])];
        bannedPatterns = [...(config.banned_command_patterns ?? [])];
        minJustification = config.min_justification_length ?? 5;
        requireHttps = config.require_https ?? true;
        snapshot = JSON.stringify(payload());
      }
      error = "";
      saveError = "";
    } catch (e) {
      error = String(e);
    }
  }

  /** A pattern must compile: a broken one would refuse nothing, silently. */
  function validatePattern(v: string): string | null {
    try {
      new RegExp(v);
      return null;
    } catch {
      return "Not a valid regular expression.";
    }
  }

  function validateDomain(v: string): string | null {
    if (/^https?:\/\//i.test(v)) return "A host name only, without the scheme.";
    if (/[\s/]/.test(v)) return "A host name only, without paths or spaces.";
    return null;
  }

  function validatePath(v: string): string | null {
    if (!v.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(v)) return "An absolute path.";
    return null;
  }

  async function save() {
    if (!isTauri() || !config) return;
    saving = true;
    saveError = "";
    saveSuccess = "";
    try {
      const body = payload();
      await invoke("save_tripwire_config", { payload: body });
      config = { ...config, ...body, saved: true };
      snapshot = JSON.stringify(body);
      saveSuccess = "Saved. The next action is checked against these rules.";
      setTimeout(() => { saveSuccess = ""; }, 5000);
    } catch (e) {
      saveError = String(e);
    } finally {
      saving = false;
    }
  }

  // ── Try a command: the tripwire's own answer, recorded nowhere ─────────
  interface CheckResult {
    allowed: boolean;
    reason?: string | null;
    rule?: string | null;
    matched?: string | null;
  }
  let tryCommand = $state("");
  let tryResult = $state<CheckResult | null>(null);
  let tryError = $state("");
  let trying = $state(false);

  const RULE_NAMES: Record<string, string> = {
    allowed_paths: "Allowed paths",
    allowed_domains: "Allowed domains",
    banned_command_patterns: "Banned command patterns",
    min_justification: "Minimum justification",
    require_https: "Require HTTPS",
  };

  async function tryIt() {
    const cmd = tryCommand.trim();
    if (!cmd || !isTauri()) return;
    trying = true;
    tryError = "";
    tryResult = null;
    try {
      const res = await invoke<CheckResult>("check_tripwire", {
        intent: { action: "run_command", params: { command: cmd } },
      });
      tryResult = res;
    } catch (e) {
      tryError = String(e);
    } finally {
      trying = false;
    }
  }
</script>

<div class="grid grid-cols-1 xl:grid-cols-[minmax(0,720px)_minmax(300px,360px)] gap-6 min-w-0 pb-6">
  <div class="flex flex-col gap-5 min-w-0">
    <div>
      <h2 class="text-xl font-semibold text-text-primary tracking-tight m-0">Tripwire</h2>
      <p class="text-sm text-text-secondary leading-relaxed mt-1 mb-0 break-words">
        Hard limits the agent cannot talk its way past. Every proposed action goes through Policy rules, then these tripwires, then the semantic guard when it is on; the first refusal stops the action.
      </p>
      <ol class="flex flex-wrap items-center gap-x-2 gap-y-1 mt-3 m-0 p-0 list-none text-xs text-text-muted" aria-label="Order of checks">
        <li><span class="font-semibold text-text-primary">1 Policy</span> rules per action</li>
        <li aria-hidden="true">›</li>
        <li><span class="font-semibold text-accent-text">2 Tripwire</span> paths, domains, patterns</li>
        <li aria-hidden="true">›</li>
        <li><span class="font-semibold text-text-primary">3 Guard</span> model judgement, if on</li>
      </ol>
    </div>

    {#if error}
      <p class="text-danger-text text-sm break-words">{error}</p>
    {:else if config}
      <form class="flex flex-col gap-5 min-w-0" onsubmit={(e) => { e.preventDefault(); save(); }}>
        <section class="rounded-2xl bg-surface border border-border-muted/40 shadow-sm p-6 flex flex-col gap-3 min-w-0">
          <div>
            <h3 class="text-sm font-medium text-text-primary m-0">Allowed paths</h3>
            <p class="text-xs text-text-muted leading-relaxed mt-1 mb-0 break-words">File reads and writes must be under one of these. {allowedPaths.length} {allowedPaths.length === 1 ? "path" : "paths"}.</p>
          </div>
          <ListEditor id="tripwire-paths" bind:items={allowedPaths} addLabel="Add an allowed path" placeholder="/path/to/workspace" validate={validatePath} />
          {#if config.saved === false}
            <p class="text-xs text-text-secondary leading-relaxed m-0 break-words">
              Not saved yet. Until you save, each Claude Code session is confined to the project folder it runs in, and the path above (where this app started) applies only to audits run from here. Saving applies these paths to both.
            </p>
          {/if}
        </section>

        <section class="rounded-2xl bg-surface border border-border-muted/40 shadow-sm p-6 flex flex-col gap-3 min-w-0">
          <div>
            <h3 class="text-sm font-medium text-text-primary m-0">Allowed domains (HTTP)</h3>
            <p class="text-xs text-text-muted leading-relaxed mt-1 mb-0 break-words">The only place this list lives; every check reads it from here. {allowedDomains.length} {allowedDomains.length === 1 ? "domain" : "domains"}.</p>
          </div>
          <ListEditor id="tripwire-domains" bind:items={allowedDomains} addLabel="Add an allowed domain" placeholder="api.example.com" validate={validateDomain} />
          <div class="flex items-start justify-between gap-4 border-t border-border-muted/40 pt-3 min-w-0">
            <div class="min-w-0">
              <p id="tripwire-require-https-label" class="text-sm font-medium text-text-primary m-0">Require HTTPS</p>
              <p class="text-xs text-text-muted leading-relaxed mt-1 mb-0">Plain HTTP requests are refused.</p>
            </div>
            <Switch id="tripwire-require-https" bind:checked={requireHttps} labelledby="tripwire-require-https-label" />
          </div>
        </section>

        <section class="rounded-2xl bg-surface border border-border-muted/40 shadow-sm p-6 flex flex-col gap-3 min-w-0">
          <div>
            <h3 class="text-sm font-medium text-text-primary m-0">Banned command patterns</h3>
            <p class="text-xs text-text-muted leading-relaxed mt-1 mb-0 break-words">Regular expressions; a command matching any of them is refused. {bannedPatterns.length} {bannedPatterns.length === 1 ? "pattern" : "patterns"}.</p>
          </div>
          <ListEditor id="tripwire-patterns" bind:items={bannedPatterns} addLabel="Add a banned pattern" placeholder="a regular expression" validate={validatePattern} tone="deny" />
        </section>

        <section class="rounded-2xl bg-surface border border-border-muted/40 shadow-sm p-6 flex items-start justify-between gap-4 min-w-0 flex-wrap">
          <div class="min-w-0 flex-1">
            <label for="tripwire-min-justification" class="block text-sm font-medium text-text-primary">Minimum justification</label>
            <p class="text-xs text-text-muted leading-relaxed mt-1 mb-0 break-words">Actions other than complete must explain themselves in at least this many characters.</p>
          </div>
          <input
            id="tripwire-min-justification"
            type="number"
            min="0"
            max="500"
            class="w-24 shrink-0 bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
            bind:value={minJustification}
          />
        </section>

        {#if saveError}
          <p class="text-danger-text text-sm m-0 break-words" role="alert">{saveError}</p>
        {:else if saveSuccess}
          <p class="text-success text-sm m-0 break-words" role="status">{saveSuccess}</p>
        {/if}
        <button type="submit" class="sr-only" tabindex="-1" aria-hidden="true">Save</button>
      </form>
    {:else}
      <p class="text-text-secondary text-sm">Loading…</p>
    {/if}

    <SaveBar
      {dirty}
      {saving}
      message="Changes apply to the next action once saved. Every session records the hash of the rules it ran under, so an edit here cannot change what an old certificate says."
      onsave={save}
      ondiscard={load}
    />
  </div>

  <aside class="flex flex-col gap-4 min-w-0">
    <section class="rounded-2xl bg-surface border border-border-muted/40 shadow-sm p-6 flex flex-col gap-3 min-w-0 xl:sticky xl:top-0">
      <div>
        <h3 class="text-sm font-medium text-text-primary m-0">Try a command</h3>
        <p class="text-xs text-text-muted leading-relaxed mt-1 mb-0 break-words">The tripwire's own answer for a shell command, against the saved rules. Nothing is recorded. Policy rules and the guard are not consulted here.</p>
      </div>
      <label for="tripwire-try" class="sr-only">Command to try</label>
      <textarea
        id="tripwire-try"
        rows="3"
        class="w-full bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-4 py-3 text-sm font-mono resize-y focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all duration-200"
        placeholder="a shell command"
        bind:value={tryCommand}
        onkeydown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); tryIt(); } }}
      ></textarea>
      <div class="flex items-center gap-3">
        <Button variant="primary" size="sm" onclick={tryIt} disabled={trying || !tryCommand.trim()} loading={trying}>{trying ? "Checking…" : "Check"}</Button>
        {#if dirty}<span class="text-xs text-warning">Unsaved edits are not checked.</span>{/if}
      </div>
      {#if tryError}
        <p class="text-xs text-danger-text m-0 break-words" role="alert">{tryError}</p>
      {:else if tryResult}
        <div class="rounded-xl border px-4 py-3 flex flex-col gap-1.5 {tryResult.allowed ? 'border-success/30 bg-success-muted/30' : 'border-danger/30 bg-danger-muted/30'}" role="status">
          <span class="text-sm font-semibold {tryResult.allowed ? 'text-success' : 'text-danger-text'}">{tryResult.allowed ? "Tripwire allows it" : "Tripwire refuses it"}</span>
          {#if !tryResult.allowed}
            <span class="text-xs text-text-primary break-words">
              {#if tryResult.rule}<span class="font-medium">{RULE_NAMES[tryResult.rule] ?? tryResult.rule}</span>{/if}
              {#if tryResult.matched}: <code class="font-mono">{tryResult.matched}</code>{/if}
            </span>
            {#if tryResult.reason}<span class="text-xs text-text-secondary break-words">{tryResult.reason}</span>{/if}
          {:else}
            <span class="text-xs text-text-secondary">Policy rules and the guard still get their say when it runs for real.</span>
          {/if}
        </div>
      {/if}
    </section>
  </aside>
</div>
