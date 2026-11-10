<!--
  ConnectClaudeCode: the Home entry point for the one integration that can
  refuse an action before it runs.

  Home used to offer only "type a goal and press Run", which drives the native
  audit loop. The integration most people would actually use, putting a coding
  agent they already run behind the ledger, existed only in
  docs/guides/integrations.md, so nothing in the app said it was possible.

  This card writes nothing. It shows the exact settings and environment the
  hook needs, with this app's live URL filled in, and states the coverage
  limits from docs/guides/integrations.md next to the setup rather than after it.
-->
<script lang="ts">
  import { CodeBlock, InlineCode } from "./ui";

  let {
    serverUrl = "",
    open = false,
    onNavigateToTab,
  }: {
    serverUrl?: string;
    open?: boolean;
    onNavigateToTab?: (tab: string) => void;
  } = $props();

  // Same settings as docs/guides/integrations.md. The matcher is one long string, so
  // the block wraps rather than scroll sideways in the Home column; copying
  // takes `settingsJson` itself, not the wrapped text.
  const hookEntry = `[{
      "matcher": "Bash|Read|WebFetch|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|apply_patch|mcp__.*",
      "hooks": [{
        "type": "command",
        "command": "ironvise hook",
        "timeout": 15
      }]
    }]`;
  const settingsJson = `{
  "hooks": {
    "PreToolUse": ${hookEntry},
    "PostToolUse": ${hookEntry}
  }
}`;

  let envBlock = $derived(
    `export ECTOLEDGER_URL=${serverUrl || "http://127.0.0.1:3000"}\n` +
      `export ECTOLEDGER_TOKEN=<an agent token from Access>`,
  );
</script>

<details class="group shrink-0 rounded-xl border border-border-muted/40 bg-surface-elevated/20 open:border-accent/40 open:bg-accent-muted/30" {open}>
  <summary class="flex items-center gap-3 px-5 py-4 cursor-pointer select-none list-none [&::-webkit-details-marker]:hidden">
    <span class="flex-1 min-w-0">
      <span class="block text-sm font-semibold text-text-primary">Protect Claude Code</span>
      <span class="block text-xs text-text-secondary mt-1 leading-relaxed">
        Check its tool calls against your policy before they run, and record every decision here.
      </span>
      <span class="mt-2 inline-flex items-center font-mono text-xs text-text-primary bg-background border border-border-muted/40 rounded-lg px-2.5 py-1">ironvise hook install</span>
    </span>
    <span class="text-xs text-text-muted shrink-0 group-open:rotate-90 transition-transform" aria-hidden="true">▶</span>
  </summary>

  <div class="px-5 pb-5 flex flex-col gap-4 text-xs text-text-secondary leading-relaxed">
    <div class="flex flex-col gap-2">
      <p><span class="text-text-primary font-medium">1.</span> In your project, run <InlineCode>ironvise hook install</InlineCode>. Or add this to <InlineCode>.claude/settings.json</InlineCode> yourself:</p>
      <CodeBlock code={settingsJson} language="json" showLineNumbers={false} maxHeight="280px" class="[&_pre]:text-xs [&_pre]:whitespace-pre-wrap" />
    </div>

    <div class="flex flex-col gap-2">
      <p>
        <span class="text-text-primary font-medium">2.</span> Point it at this app. The token needs the
        <InlineCode>agent</InlineCode> role.
        {#if onNavigateToTab}
          <button
            type="button"
            class="text-accent-text hover:underline bg-transparent border-none cursor-pointer p-0"
            onclick={() => onNavigateToTab("access")}
          >Create one in Access</button>.
        {/if}
      </p>
      <CodeBlock code={envBlock} language="shell" showLineNumbers={false} class="[&_pre]:text-xs [&_pre]:whitespace-pre-wrap" />
    </div>

    <ul class="list-disc pl-5 flex flex-col gap-1.5 text-text-muted">
      <li>Checks <InlineCode>Bash</InlineCode>, <InlineCode>Read</InlineCode>, <InlineCode>WebFetch</InlineCode>, <InlineCode>Glob</InlineCode> and <InlineCode>Grep</InlineCode> with policy and tripwire rules. When the semantic guard is required, it judges each call too: one model call per tool call.</li>
      <li>Checks file writes (<InlineCode>Write</InlineCode>, <InlineCode>Edit</InlineCode>, <InlineCode>NotebookEdit</InlineCode>) by where they land: inside the project, never its own hook settings, git hooks or <InlineCode>.ssh</InlineCode>. It does not read what they write.</li>
      <li>Records what each tool returned as a data receipt: SHA-256 hashes only, never the data. <InlineCode>ironvise data-receipts &lt;session&gt; --file PATH</InlineCode> checks a file against them.</li>
      <li>Only takes permissions away: a refusal blocks the call, and anything it allows still goes through Claude Code's own prompts. Set <InlineCode>ECTOLEDGER_HOOK_MODE=approve</InlineCode> to let an allow skip them.</li>
      <li>Fails closed: while the hook is installed, those tools are blocked whenever this app is not running.</li>
      <li>This app listens on a new loopback port each launch, so the URL above changes when you relaunch it. For a hook that outlives a relaunch, run <InlineCode>ironvise serve</InlineCode> (port 3000) and point <InlineCode>ECTOLEDGER_URL</InlineCode> there instead.</li>
      <li>Needs the <InlineCode>ironvise</InlineCode> command on your PATH (<InlineCode>ectoledger</InlineCode> is the same program). Sessions show up in History as <InlineCode>claude-code</InlineCode>, or <InlineCode>codex</InlineCode> for Codex.</li>
    </ul>
  </div>
</details>
