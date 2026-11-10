<!--
  TestSection: one collapsible list of prompt tests (happy path or sad
  path). The two sections were copies of each other; this is the one copy.
  The toggle and "Run All" are siblings: one <button> inside another is
  invalid HTML and made the inner control unreachable by keyboard.
-->
<script lang="ts">
  import { Badge, Button } from "../ui";

  type TestStatus = "idle" | "running" | "pass" | "fail";
  interface PromptTest {
    id: string;
    name: string;
    category: string;
    description: string;
    prompt: string;
  }

  interface Props {
    title: string;
    /** "success" for the happy path, "danger" for the sad path. */
    tone: "success" | "danger";
    tests: PromptTest[];
    statuses: Record<string, TestStatus>;
    results: Record<string, string>;
    /** Session ids per test, for "Select Session" after a pass. */
    sessionIds?: Record<string, string>;
    gridClass: string;
    onrun: (id: string, prompt: string) => void;
    onrunall: () => void;
    onselectsession?: (sessionId: string) => void;
  }

  let {
    title, tone, tests, statuses, results, sessionIds = {}, gridClass,
    onrun, onrunall, onselectsession,
  }: Props = $props();

  let expanded = $state(true);
</script>

<div class="rounded-2xl border border-border-muted/20 bg-surface overflow-hidden">
  <div class="w-full flex items-center justify-between px-6 py-4 gap-3">
    <button
      class="flex items-center gap-3 flex-1 min-w-0 text-left cursor-pointer rounded-lg px-2 py-1 -mx-2 hover:bg-surface-elevated/50 transition-colors"
      aria-expanded={expanded}
      onclick={() => (expanded = !expanded)}
    >
      <svg
        class="w-4 h-4 text-text-muted transition-transform duration-200 {expanded ? 'rotate-90' : ''}"
        viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"
      >
        <polyline points="9 18 15 12 9 6" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div class="flex items-center gap-2">
        <div class="w-2.5 h-2.5 rounded-full {tone === 'success' ? 'bg-success' : 'bg-danger'}" aria-hidden="true"></div>
        <h2 class="text-base font-semibold text-text-primary">{title}</h2>
      </div>
      <span class="text-xs text-text-muted">({tests.length} tests)</span>
    </button>
    <Button variant={tone === "success" ? "primary" : "danger"} onclick={onrunall} ariaLabel="Run all {title.toLowerCase()}">
      {#snippet children()}Run All{/snippet}
    </Button>
  </div>

  {#if expanded}
    <div class="px-6 pb-6 border-t border-border-muted/10">
      <div class="{gridClass} pt-5">
        {#each tests as test}
          {@const status = statuses[test.id] ?? "idle"}
          {@const resultText = results[test.id] ?? ""}
          <div class="bg-surface-elevated rounded-2xl p-5 flex flex-col gap-3.5 border border-border-muted/10 hover:border-border-muted/25 transition-all duration-200">
            <div class="flex items-start justify-between gap-2">
              <div>
                <p class="text-xs text-text-muted uppercase tracking-wider mb-0.5">{test.category}</p>
                <h3 class="text-sm font-semibold text-text-primary">{test.name}</h3>
              </div>
              {#if status === "idle"}
                <Badge variant="default">{#snippet children()}Idle{/snippet}</Badge>
              {:else if status === "running"}
                <Badge variant="accent" dot>{#snippet children()}Running{/snippet}</Badge>
              {:else if status === "pass"}
                <Badge variant="success" dot>{#snippet children()}Pass{/snippet}</Badge>
              {:else}
                <Badge variant="danger" dot>{#snippet children()}Fail{/snippet}</Badge>
              {/if}
            </div>
            <p class="text-xs text-text-secondary leading-relaxed">{test.description}</p>
            <div class="bg-surface rounded-xl border border-border-muted/15 p-3.5">
              <p class="text-[10px] text-text-muted uppercase tracking-wider mb-1">Prompt</p>
              <p class="text-xs font-mono text-text-primary break-words">{test.prompt}</p>
            </div>
            {#if resultText}
              <p class="text-xs {status === 'pass' ? 'text-success' : 'text-danger'}">{resultText}</p>
            {/if}
            <div class="flex gap-2">
              <Button
                variant={status === "running" ? "secondary" : "primary"}
                onclick={() => onrun(test.id, test.prompt)}
                loading={status === "running"}
              >
                {#snippet children()}{status === "running" ? "Running…" : "Run Test"}{/snippet}
              </Button>
              {#if onselectsession && sessionIds[test.id] && status === "pass"}
                <Button variant="secondary" onclick={() => onselectsession(sessionIds[test.id])}>
                  {#snippet children()}Select Session{/snippet}
                </Button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    </div>
  {/if}
</div>
