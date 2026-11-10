<!-- StepProgress: the five named steps shown above every step but the first. -->
<script lang="ts">
  interface Props { step: number; }
  let { step }: Props = $props();
</script>

<!-- Named steps: five bare bars said nothing about what came next. -->
<ol class="flex items-center gap-2 mb-10 list-none m-0 p-0" aria-label="Setup steps">
  {#each ["Setup", "Ledger", "Provider", "Model", "Finish"] as label, i}
    {@const n = i + 1}
    <li class="flex items-center gap-2 {n < 5 ? 'flex-1' : ''} min-w-0">
      <span class="flex items-center gap-2 text-xs whitespace-nowrap {n <= step ? 'text-accent-text' : 'text-text-muted'}" aria-current={n === step ? 'step' : undefined}>
        <span class="w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-semibold border {n < step ? 'bg-accent/15 border-accent/40' : n === step ? 'bg-accent-text text-text-inverse border-accent-text' : 'border-border-muted/60'}">{n}</span>
        {label}
      </span>
      {#if n < 5}<span class="flex-1 h-px {n < step ? 'bg-accent/50' : 'bg-border-muted/50'}"></span>{/if}
    </li>
  {/each}
</ol>
