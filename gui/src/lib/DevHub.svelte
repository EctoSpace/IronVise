<!--
  DevHub - Developer Hub tab.

  Shows SDK integration snippets, API reference, and quick-start
  guides for Python and TypeScript SDKs. Includes interactive "Run Test"
  buttons that spawn shell commands and stream output into the GUI.
-->
<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { onDestroy } from "svelte";
  import { Badge, Button, Card, FieldLabel, Panel } from "./ui";

  interface Props {
    serverUrl: string;
  }

  let { serverUrl }: Props = $props();

  let activeSDK = $state<"python" | "typescript">("python");
  let _alive = true;

  onDestroy(() => {
    _alive = false;
  });

  // The exact (cmd, cwd) pairs allowlisted in the Rust backend
  // (commands.rs ALLOWED_DEV_COMMANDS); anything else is rejected there.
  const DEV_COMMANDS = {
    python: {
      cmd: 'python -m pip install -e ".[langchain,autogen]" && python -m pytest tests/',
      cwd: "sdk/python",
    },
    typescript: {
      cmd: "npm ci && npm run build",
      cwd: "sdk/typescript",
    },
  } as const;

  interface TestRun {
    output: string[];
    running: boolean;
    exitCode: number | null;
    error: string;
  }

  const emptyRun = (): TestRun => ({ output: [], running: false, exitCode: null, error: "" });
  let pyTest  = $state<TestRun>(emptyRun());
  let tsTest  = $state<TestRun>(emptyRun());

  /**
   * Run SDK tests via the backend's allowlisted `run_shell_command_streaming`
   * Tauri command; output lines arrive as "shell-command-output" events.
   */
  async function runTests(sdk: "python" | "typescript") {
    if (!isTauri()) return;

    // Only one run at a time: the output event channel is shared.
    if (pyTest.running || tsTest.running) return;

    if (sdk === "python") {
      pyTest = { output: [], running: true, exitCode: null, error: "" };
    } else {
      tsTest = { output: [], running: true, exitCode: null, error: "" };
    }

    const appendLine = (line: string, isErr = false) => {
      const prefix = isErr ? "[stderr] " : "";
      if (sdk === "python") {
        pyTest = { ...pyTest, output: [...pyTest.output, prefix + line] };
      } else {
        tsTest = { ...tsTest, output: [...tsTest.output, prefix + line] };
      }
    };

    let unlisten: UnlistenFn | null = null;
    try {
      unlisten = await listen<{ line: string; stream: string }>(
        "shell-command-output",
        (ev) => {
          if (_alive) appendLine(ev.payload.line, ev.payload.stream === "stderr");
        },
      );

      const { cmd, cwd } = DEV_COMMANDS[sdk];
      const result = await invoke<{ stdout: string; stderr: string; exit_code: number | null }>(
        "run_shell_command_streaming",
        { args: { cmd, cwd } },
      );
      const code = result.exit_code ?? -1;

      if (sdk === "python") {
        pyTest = { ...pyTest, running: false, exitCode: code };
      } else {
        tsTest = { ...tsTest, running: false, exitCode: code };
      }
    } catch (e) {
      const msg = `Test run failed: ${e}`;
      if (sdk === "python") {
        pyTest = { ...pyTest, running: false, exitCode: -1, error: msg };
      } else {
        tsTest = { ...tsTest, running: false, exitCode: -1, error: msg };
      }
    } finally {
      unlisten?.();
    }
  }

  function exitBadgeVariant(code: number | null): "success" | "danger" | "default" {
    if (code === null) return "default";
    return code === 0 ? "success" : "danger";
  }
  function exitLabel(code: number | null): string {
    if (code === null) return "";
    return code === 0 ? "✓ Passed" : `✗ Exited ${code}`;
  }

  const pythonInstall = `pip install ./sdk/python`;
  const pythonQuickstart = $derived(`import asyncio
from ironvise_sdk import LedgerClient

async def main():
    async with LedgerClient(
        base_url="${serverUrl}",
        bearer_token="your-api-token",
    ) as client:
        # Create a session and append events
        session = await client.create_session(
            goal="Audit the login endpoint for OWASP Top 10",
            record=True,
        )
        await client.append_event(session.session_id, {"step": "read", "file": "config.py"})
        await client.seal_session(session.session_id)

        # Verify the hash chain
        ok = await client.verify_chain(session.session_id)
        print(f"Chain intact: {ok}")

        # Get the Verifiable Credential
        vc = await client.get_session_vc(session.session_id)
        print(f"VC issued: {vc}")

asyncio.run(main())`);

  const tsInstall = `cd sdk/typescript && npm install && npm run build`;
  const tsQuickstart = $derived(`import { IronViseClient } from "ironvise";

const client = new IronViseClient({
  baseUrl: "${serverUrl}",
  bearerToken: "your-api-token",
});

// Create a session and append events
const session = await client.createSession({
  goal: "Audit the login endpoint for OWASP Top 10",
  record: true,
});
await client.appendEvent(session.id, { step: "read", file: "config.ts" });
await client.sealSession(session.id);

// Verify the hash chain
const ok = await client.verifyChain(session.id);
console.log(\`Chain intact: \${ok}\`);

// Get the Verifiable Credential
const vc = await client.getSessionVc(session.id);
console.log(\`VC issued:\`, vc);
`);

  const apiEndpoints = [
    { method: "GET",    path: "/api/sessions",              desc: "List all audit sessions" },
    { method: "POST",   path: "/api/sessions",              desc: "Create a new session" },
    { method: "GET",    path: "/api/events?session_id=:id", desc: "Get events for a session" },
    { method: "GET",    path: "/api/stream",                desc: "SSE event stream" },
    { method: "GET",    path: "/api/sessions/:id/vc",       desc: "Get session Verifiable Credential" },
    { method: "GET",    path: "/api/sessions/:id/vc/verify",desc: "Verify session VC" },
    { method: "GET",    path: "/api/certificates/:id",      desc: "Download audit certificate" },
    { method: "GET",    path: "/api/reports/:id",           desc: "Download audit report" },
    { method: "GET",    path: "/api/policies",              desc: "List audit policies" },
    { method: "GET",    path: "/api/config",                desc: "Get server configuration" },
    { method: "PUT",    path: "/api/config",                desc: "Update configuration" },
    { method: "GET",    path: "/api/tokens",                desc: "List API tokens (admin)" },
    { method: "POST",   path: "/api/tokens",                desc: "Create API token (admin)" },
    { method: "DELETE", path: "/api/tokens/:hash",          desc: "Delete API token (admin)" },
    { method: "GET",    path: "/api/webhooks",              desc: "List webhooks (admin)" },
    { method: "POST",   path: "/api/webhooks",              desc: "Create webhook (admin)" },
    { method: "GET",    path: "/metrics",                   desc: "Prometheus metrics" },
  ];

  const methodColors: Record<string, string> = {
    GET: "accent",
    POST: "success",
    PUT: "warning",
    DELETE: "danger",
  };
</script>

<div class="space-y-8 animate-fade-in">
  <div>
    <h1 class="text-xl font-bold text-text-primary">Developer Hub</h1>
    <p class="text-sm text-text-muted mt-1">SDK integration guides, API reference, and code snippets.</p>
  </div>

  <!-- SDK tabs -->
  <div class="flex gap-2">
    <Button
      variant={activeSDK === "python" ? "primary" : "ghost"}
      size="sm"
      onclick={() => activeSDK = "python"}
    >
      {#snippet children()}Python SDK{/snippet}
    </Button>
    <Button
      variant={activeSDK === "typescript" ? "primary" : "ghost"}
      size="sm"
      onclick={() => activeSDK = "typescript"}
    >
      {#snippet children()}TypeScript SDK{/snippet}
    </Button>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-7">
    <!-- Quick start -->
    <Card title={activeSDK === "python" ? "Python Quick Start" : "TypeScript Quick Start"}>
      {#snippet children()}
        <div class="space-y-4">
          <div>
            <h4 class="text-xs text-text-muted uppercase tracking-wider mb-2">Install</h4>
            <Panel class="overflow-x-auto"><pre class="m-0 text-sm font-mono text-accent-text">{activeSDK === "python" ? pythonInstall : tsInstall}</pre></Panel>
          </div>
          <div>
            <h4 class="text-xs text-text-muted uppercase tracking-wider mb-2">Quick Start</h4>
            <pre class="p-6 rounded-xl bg-surface-elevated border border-border-muted/15 text-xs font-mono text-text-secondary overflow-x-auto max-h-96 overflow-y-auto">{activeSDK === "python" ? pythonQuickstart : tsQuickstart}</pre>
          </div>
        </div>
      {/snippet}
    </Card>

    <!-- API Reference -->
    <Card title="API Reference" subtitle="All available endpoints">
      {#snippet children()}
        <div class="space-y-1 max-h-[500px] overflow-y-auto">
          {#each apiEndpoints as ep}
            <div class="flex items-start gap-3 py-3.5 px-4 rounded-xl hover:bg-surface-elevated transition-all duration-200">
              <Badge variant={methodColors[ep.method] as "accent" | "success" | "warning" | "danger" ?? "default"}>
                {#snippet children()}<span class="font-mono text-[10px] w-10 text-center inline-block">{ep.method}</span>{/snippet}
              </Badge>
              <div class="flex-1 min-w-0">
                <code class="text-xs font-mono text-text-primary">{ep.path}</code>
                <p class="text-xs text-text-muted mt-0.5">{ep.desc}</p>
              </div>
            </div>
          {/each}
        </div>
      {/snippet}
    </Card>
  </div>

  <!-- Connection info -->
  <Card title="Connection Details">
    {#snippet children()}
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Panel>
          <FieldLabel spacing="below">Server URL</FieldLabel>
          <code class="text-sm text-accent-text font-mono">{serverUrl}</code>
        </Panel>
        <Panel>
          <FieldLabel spacing="below">Database</FieldLabel>
          <span class="text-sm text-text-primary">SQLite (embedded)</span>
        </Panel>
        <Panel>
          <FieldLabel spacing="below">Authentication</FieldLabel>
          <span class="text-sm text-text-primary">Bearer Token (RBAC)</span>
        </Panel>
      </div>
    {/snippet}
  </Card>

  <!-- Integration Tests -->
  <Card title="Integration Tests" subtitle="Run SDK test suites directly from this tab">
    {#snippet children()}
      <div class="space-y-6">

        <!-- Python SDK tests -->
        <div class="space-y-2">
          <div class="flex items-center justify-between gap-4">
            <div class="flex-1 min-w-0">
              <h4 class="text-sm font-semibold text-text-primary">Python SDK</h4>
              <code class="text-xs font-mono text-text-muted break-all">
                python -m pip install -e ".[langchain,autogen]" &amp;&amp; python -m pytest tests/
              </code>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              {#if pyTest.exitCode !== null}
                <Badge variant={exitBadgeVariant(pyTest.exitCode)}>
                  {#snippet children()}{exitLabel(pyTest.exitCode)}{/snippet}
                </Badge>
              {/if}
              <Button
                variant="primary"
                size="sm"
                disabled={pyTest.running}
                onclick={() => runTests("python")}
              >
                {#snippet children()}{pyTest.running ? "Running…" : "Run Tests"}{/snippet}
              </Button>
            </div>
          </div>
          {#if pyTest.error}
            <p class="text-xs text-danger">{pyTest.error}</p>
          {/if}
          {#if pyTest.output.length > 0}
            <pre class="h-44 overflow-y-auto rounded-xl border border-border-muted/15 bg-background p-5 text-xs font-mono text-text-secondary whitespace-pre-wrap">{pyTest.output.join("\n")}</pre>
          {/if}
        </div>

        <div class="border-t border-border-muted/15"></div>

        <!-- TypeScript SDK tests -->
        <div class="space-y-2">
          <div class="flex items-center justify-between gap-4">
            <div class="flex-1 min-w-0">
              <h4 class="text-sm font-semibold text-text-primary">TypeScript SDK</h4>
              <code class="text-xs font-mono text-text-muted">npm ci &amp;&amp; npm run build</code>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              {#if tsTest.exitCode !== null}
                <Badge variant={exitBadgeVariant(tsTest.exitCode)}>
                  {#snippet children()}{exitLabel(tsTest.exitCode)}{/snippet}
                </Badge>
              {/if}
              <Button
                variant="primary"
                size="sm"
                disabled={tsTest.running}
                onclick={() => runTests("typescript")}
              >
                {#snippet children()}{tsTest.running ? "Running…" : "Run Tests"}{/snippet}
              </Button>
            </div>
          </div>
          {#if tsTest.error}
            <p class="text-xs text-danger">{tsTest.error}</p>
          {/if}
          {#if tsTest.output.length > 0}
            <pre class="h-44 overflow-y-auto rounded-xl border border-border-muted/15 bg-background p-5 text-xs font-mono text-text-secondary whitespace-pre-wrap">{tsTest.output.join("\n")}</pre>
          {/if}
        </div>

      </div>
    {/snippet}
  </Card>

</div>
