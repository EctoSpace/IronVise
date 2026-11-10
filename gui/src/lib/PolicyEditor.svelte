<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";

  let policies = $state<string[]>([]);
  let selected = $state("");
  let content = $state("");
  let original = $state("");
  let saving = $state(false);
  let saveMsg = $state("");
  let newPolicyName = $state("");
  let creating = $state(false);
  let createError = $state("");
  let loadError = $state("");
  let _loadSeq = 0;
  let _timers: ReturnType<typeof setTimeout>[] = [];

  onDestroy(() => {
    _timers.forEach(clearTimeout);
  });

  // Written as tables, the engine's own format (bare names are accepted
  // too). See audit_policy.example.toml for every rule.
  const DEFAULT_POLICY_TEMPLATE = `# New policy. Every rule: audit_policy.example.toml

name = "policy-name"
goal = "Describe the audit goal here."
max_steps = 20

[[forbidden_actions]]
action = "write_file"

[[forbidden_actions]]
action = "delete_file"
`;

  /** The policy Home → Run uses (Settings' active_policy), and the
   *  environment's ECTO_POLICY_PATH, which wins when set. */
  let activePolicy = $state("");
  let policyFromEnv = $state("");
  let activeMsg = $state("");

  async function loadActive() {
    try {
      const cfg = await invoke<{ active_policy?: string | null; policy_from_environment?: string | null }>("get_config");
      activePolicy = cfg?.active_policy ?? "";
      policyFromEnv = cfg?.policy_from_environment ?? "";
    } catch {
      /* the editor still works without it */
    }
  }

  async function useForRuns(name: string) {
    activeMsg = "";
    try {
      await invoke("save_config", { payload: { active_policy: name } });
      activePolicy = name;
    } catch (e) {
      activeMsg = String(e);
    }
  }

  onMount(() => {
    load();
    loadActive();
  });

  async function load() {
    if (!isTauri()) return;
    loadError = "";
    try {
      const data = await invoke<unknown>("get_policies");
      policies = Array.isArray(data) ? (data as string[]) : [];
      if (policies.length > 0 && !selected) {
        selected = policies[0];
        await loadPolicyContent(policies[0]);
      }
    } catch (e) {
      loadError = `Failed to load policies: ${e}`;
    }
  }

  async function loadPolicyContent(name: string) {
    if (!isTauri()) return;
    const seq = ++_loadSeq;
    try {
      const data = await invoke<string>("get_policy_content", { name });
      if (seq !== _loadSeq) return; // stale response guard
      content = data;
      original = content;
    } catch (e) {
      if (seq !== _loadSeq) return;
      content = `# Policy: ${name}\n# (Failed to load: ${e})\n# Edit TOML controls here`;
      original = content;
    }
  }

  async function save() {
    saving = true;
    saveMsg = "";
    try {
      await invoke("save_policy", { name: selected, content });
      original = content;
      saveMsg = "Saved successfully.";
    } catch (e) {
      saveMsg = String(e);
    } finally {
      saving = false;
      _timers.push(setTimeout(() => (saveMsg = ""), 3000));
    }
  }

  async function selectPolicy(name: string) {
    if (dirty && !confirm("You have unsaved changes. Discard?")) return;
    selected = name;
    await loadPolicyContent(name);
  }

  function sanitizePolicyName(name: string): string {
    return name.trim().replace(/[^a-zA-Z0-9_-]/g, "-").toLowerCase() || "new-policy";
  }

  async function deletePolicy() {
    if (!isTauri() || !selected) return;
    if (!confirm(`Delete policy "${selected}"? This cannot be undone.`)) return;
    try {
      await invoke("delete_policy", { name: selected });
      selected = "";
      content = "";
      original = "";
      await load();
    } catch (e) {
      saveMsg = String(e);
      _timers.push(setTimeout(() => (saveMsg = ""), 3000));
    }
  }

  const BUILTIN_POLICIES = ["soc2-audit", "pci-dss-audit", "owasp-top10", "iso42001"];

  async function addPolicy() {
    if (!isTauri() || !newPolicyName.trim()) return;
    const name = sanitizePolicyName(newPolicyName);
    if (policies.includes(name)) {
      createError = `Policy "${name}" already exists.`;
      _timers.push(setTimeout(() => (createError = ""), 3000));
      return;
    }
    creating = true;
    createError = "";
    try {
      const template = DEFAULT_POLICY_TEMPLATE.replace(/policy-name/g, name);
      await invoke("save_policy", { name, content: template });
      await load();
      selected = name;
      await loadPolicyContent(name);
      newPolicyName = "";
    } catch (e) {
      createError = String(e);
    } finally {
      creating = false;
    }
  }

  const dirty = $derived(content !== original);
  const canDelete = $derived(selected && !dirty && !BUILTIN_POLICIES.includes(selected) && selected !== activePolicy);
  const isBuiltin = $derived(BUILTIN_POLICIES.includes(selected));

  const validationError = $derived.by(() => {
    try {
      const lines = content.split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[")) continue;
        if (trimmed === "]" || trimmed === "],") continue;
        if (trimmed.includes("=")) continue;
        if (trimmed.startsWith('"') || trimmed.startsWith("'")) continue;
        return `Unexpected line: "${trimmed}"`;
      }
      return null;
    } catch {
      return "Parse error";
    }
  });
</script>

<div class="flex gap-6 h-full overflow-hidden">
  <!-- Policy list -->
  <aside class="bg-surface rounded-2xl w-72 min-w-72 max-w-72 p-6 overflow-y-auto overflow-x-hidden flex flex-col gap-3 shrink-0 shadow-sm border border-border-muted/40">
    <h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Policies</h2>
    <div class="flex gap-2 mb-4 shrink-0 min-w-0">
      <input
        type="text"
        class="flex-1 min-w-0 bg-surface-elevated/40 border border-border-muted/40 rounded-xl text-text-primary px-4 py-2.5 text-sm outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200"
        placeholder="New policy name…"
        bind:value={newPolicyName}
        onkeydown={(e) => e.key === "Enter" && addPolicy()}
      />
      <button
        type="button"
        class="bg-surface-elevated border border-border-muted/40 rounded-xl text-accent-text px-4 py-2.5 text-sm font-semibold cursor-pointer whitespace-nowrap hover:bg-border-muted disabled:opacity-50 disabled:cursor-default transition-all duration-200"
        onclick={addPolicy}
        disabled={creating || !newPolicyName.trim()}
      >
        {creating ? "…" : "+ Add"}
      </button>
    </div>
    {#if createError}
      <p class="text-xs text-danger mb-2">{createError}</p>
    {/if}
    {#if loadError}
      <p class="text-xs text-danger mb-2">{loadError}</p>
    {/if}
    <ul class="list-none m-0 p-0 flex-1 min-h-0 overflow-y-auto">
      {#each policies as p}
        <li>
          <button
            class="w-full text-left px-4 py-3 bg-transparent border-none rounded-xl text-text-secondary text-sm cursor-pointer transition-all duration-200 hover:bg-surface-elevated hover:text-text-primary {selected === p ? 'bg-surface-elevated text-accent-text font-semibold' : ''}"
            onclick={() => selectPolicy(p)}
          >
            {p}
          </button>
        </li>
      {/each}
    </ul>
  </aside>

  <!-- Editor pane -->
  <section class="bg-surface rounded-2xl flex-1 p-7 flex flex-col gap-5 overflow-hidden shadow-sm border border-border-muted/40">
    {#if !selected}
      <p class="text-text-muted text-sm text-center mt-16">Select a policy to edit.</p>
    {:else}
      <div class="flex justify-between items-start gap-3 flex-wrap min-w-0">
        <div class="min-w-0"><p class="text-[11px] font-semibold uppercase tracking-[0.1em] text-text-secondary m-0 mb-1">{isBuiltin ? "Built-in, read only" : "Editing"}</p><h2 class="text-base font-semibold font-mono text-text-primary m-0 min-w-0 truncate">{selected}</h2></div>
        <div class="flex items-center gap-3 flex-wrap shrink-0">
          {#if saveMsg}
            <span class="text-sm text-success">{saveMsg}</span>
          {/if}
          {#if dirty}
            <span class="text-xs px-2 py-0.5 rounded-full bg-warning-muted text-warning font-semibold">Unsaved</span>
          {/if}
          {#if !policyFromEnv}
            {#if selected === activePolicy}
              <span class="text-xs px-2 py-0.5 rounded-full bg-success-muted text-success font-semibold">Used for new runs</span>
              <button class="bg-surface-elevated border border-border-muted/40 rounded-xl px-4 py-3 text-sm font-semibold text-text-primary cursor-pointer hover:bg-border-muted transition-all duration-200" onclick={() => useForRuns("")}>Stop using</button>
            {:else}
              <button class="bg-surface-elevated border border-border-muted/40 rounded-xl px-4 py-3 text-sm font-semibold text-text-primary cursor-pointer hover:bg-border-muted disabled:opacity-50 disabled:cursor-default transition-all duration-200" onclick={() => useForRuns(selected)} disabled={dirty}>Use for new runs</button>
            {/if}
          {/if}
          {#if !isBuiltin}
            <button class="bg-accent-text text-text-inverse border-none rounded-xl px-6 py-3 text-sm font-semibold cursor-pointer disabled:opacity-50 disabled:cursor-default transition-all duration-200 active:scale-[0.98] shadow-sm hover:bg-accent" onclick={save} disabled={saving || !!validationError}>
              {saving ? "Saving…" : "Save"}
            </button>
          {/if}
          {#if canDelete}
            <button class="bg-danger-muted text-danger-text border border-danger/20 rounded-xl px-6 py-3 text-sm font-semibold cursor-pointer hover:bg-danger/20 transition-all duration-200" onclick={deletePolicy}>Delete</button>
          {/if}
        </div>
      </div>

      <p class="text-xs text-text-muted leading-relaxed m-0 break-words">
        {#if policyFromEnv}
          New runs use the policy the environment sets (<code>ECTO_POLICY_PATH</code> = {policyFromEnv}); it overrides the choice here.
        {:else if activePolicy}
          New runs from Home are checked against <strong>{activePolicy}</strong>, read when each run starts, so a saved edit applies to the next run.
        {:else}
          New runs from Home use no policy: only tripwire (and the semantic guard, if on) checks their actions. Choose one with "Use for new runs".
        {/if}
        {#if isBuiltin}Built-in policies cannot be edited; copy the text into a new policy to change it.{/if}
      </p>
      {#if activeMsg}
        <p class="text-xs text-danger-text m-0 break-words" role="alert">{activeMsg}</p>
      {/if}

      {#if validationError}
        <div class="bg-danger-muted border border-danger/20 rounded-xl px-5 py-4 text-sm text-danger-text">{validationError}</div>
      {/if}

      <textarea
        class="flex-1 w-full bg-background border border-border-muted/30 rounded-xl text-text-primary p-6 font-mono text-sm leading-relaxed resize-none outline-none focus:border-accent focus:ring-2 focus:ring-accent/30 transition-all duration-200 {validationError ? 'border-danger' : ''}"
        aria-label="Policy file contents (TOML)"
        aria-invalid={!!validationError}
        readonly={isBuiltin}
        bind:value={content}
        spellcheck="false"
      ></textarea>
    {/if}
  </section>
</div>
