<!-- VerifyBanner: the result of the last "Verify Chain" run. -->
<script lang="ts">
  interface Props {
    banner: { type: "pass" | "warn" | "fail" | "running"; text: string } | null;
  }

  let { banner }: Props = $props();
</script>

{#if banner}
  <div class="flex items-center gap-2 px-4 py-2 text-xs animate-[slidein_0.2s_ease]
    {banner.type === 'pass' ? 'bg-success/10 text-success border-b border-success/20'
    : banner.type === 'fail' ? 'bg-danger/10 text-danger-text border-b border-danger/20'
    : 'bg-warning/10 text-warning border-b border-warning/20'}"
  >
    <span aria-hidden="true">{banner.type === "pass" ? "✅" : banner.type === "fail" ? "❌" : banner.type === "warn" ? "⚠️" : "⏳"}</span>
    <span>{banner.text}</span>
  </div>
{/if}

<style>
  @keyframes slidein {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: none; }
  }
</style>
