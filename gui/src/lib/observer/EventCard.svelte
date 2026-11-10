<!-- EventCard: one event on the timeline, with its findings table (for a
     "complete" action) and the hash chain it links into. -->
<script lang="ts">
  import { describeEvent } from "../events";
  import { fmtTime, getFindings, sevClass, shortHash, TONE_COLORS, type EventRow } from "./eventRows";

  interface Props {
    ev: EventRow;
    isLast: boolean;
    verifyResult: "pass" | "fail" | undefined;
    isExpanded: boolean;
    onToggleBody: (seq: number) => void;
  }

  let { ev, isLast, verifyResult, isExpanded, onToggleBody }: Props = $props();

  const view = $derived(describeEvent(ev.payload));
  const color = $derived(TONE_COLORS[view.tone]);
  const content = $derived(view.text);
  const findings = $derived(getFindings(ev));
  const isLong = $derived(content.length > 300);
</script>

<div
  class="relative mb-0.5 py-2 px-3 pl-4 rounded-md transition-colors hover:bg-surface-elevated/40"
  style:border-left="3px solid {color.border}"
  style:background={color.bg ?? "transparent"}
>
  <!-- Timeline connector line -->
  <div
    class="absolute -left-5 top-0 w-0.5 bg-border-muted"
    style:bottom={isLast ? "50%" : "-2px"}
  ></div>
  <!-- Timeline dot -->
  <div
    class="absolute -left-[22px] top-4 w-2.5 h-2.5 rounded-full border-2 border-background"
    style:background={color.dot}
  ></div>

  <!-- Event header -->
  <div class="flex items-center gap-2 mb-1">
    <span class="text-[10px] font-mono text-text-muted">#{ev.sequence}</span>
    <span
      class="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-px rounded-full bg-surface-elevated/60"
      style:color={color.border}
    >{view.label}</span>
    <span class="text-[10px] text-text-muted ml-auto">{fmtTime(ev.created_at)}</span>
    {#if verifyResult === "pass"}
      <span class="text-[10px] text-success" title="Hash verified">✓</span>
    {:else if verifyResult === "fail"}
      <span class="text-[10px] text-danger-text" title="Hash mismatch">✗</span>
    {/if}
  </div>

  <!-- Event body -->
  <div
    class="text-[11px] text-text-primary leading-relaxed whitespace-pre-wrap break-words font-mono
      {!isExpanded && isLong ? 'max-h-[120px] overflow-hidden' : ''}"
  >{content}</div>
  {#if isLong}
    <button
      class="text-[10px] text-accent-text bg-transparent border-none cursor-pointer p-0 mt-1 hover:underline"
      onclick={() => onToggleBody(ev.sequence)}
    >{isExpanded ? "Show less" : "Show more"}</button>
  {/if}

  <!-- Findings table -->
  {#if findings && findings.length > 0}
    <div class="mt-2 overflow-x-auto">
      <table class="w-full text-[10px] border-collapse">
        <thead>
          <tr class="border-b border-border-muted/30">
            <th class="text-left py-1 px-2 text-text-muted font-semibold">Severity</th>
            <th class="text-left py-1 px-2 text-text-muted font-semibold">Title</th>
            <th class="text-left py-1 px-2 text-text-muted font-semibold">Evidence</th>
            <th class="text-left py-1 px-2 text-text-muted font-semibold">Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {#each findings as f}
            <tr class="border-b border-border-muted/15">
              <td class="py-1 px-2 {sevClass(String(f.severity ?? 'low'))}">{f.severity ?? "low"}</td>
              <td class="py-1 px-2 text-text-primary">{f.title ?? ""}</td>
              <td class="py-1 px-2 text-text-secondary">{f.evidence ?? ""}</td>
              <td class="py-1 px-2 text-text-secondary">{f.recommendation ?? ""}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <!-- Hash chain -->
  <div class="flex items-center gap-1.5 mt-1.5 text-[9px] font-mono">
    <span class="px-1.5 py-px rounded border border-border-muted/30 text-text-muted" title="previous_hash: {ev.previous_hash}">{shortHash(ev.previous_hash)}</span>
    <span class="text-text-muted">→</span>
    <span class="px-1.5 py-px rounded border border-accent/25 text-accent-text" title="content_hash: {ev.content_hash}">{shortHash(ev.content_hash)}</span>
  </div>
</div>
