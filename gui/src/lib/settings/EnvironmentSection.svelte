<!-- EnvironmentSection: what the environment decides, shown and not edited. -->
<script lang="ts">
  import { InlineCode } from "../ui";
  import { type Config, SECTION_TITLE_CLASS } from "./types";

  let {
    config,
    visibleFields = null,
  }: { config: Config; visibleFields?: Set<string> | null } = $props();

  function shows(field: string): boolean {
    return !visibleFields || visibleFields.has(field);
  }

  const CARD = "rounded-xl border border-dashed border-border-muted/60 bg-background px-4 py-3.5 flex flex-col gap-1.5 min-w-0";
  const PILL = "text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full";
</script>

<section id="settings-environment" tabindex="-1" class="flex flex-col gap-3 min-w-0 scroll-mt-4">
  <h3 class={SECTION_TITLE_CLASS}>From the environment · read only</h3>
  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 min-w-0">
    {#if shows("Sandbox")}
    <div class={CARD}>
      <div class="flex items-center justify-between gap-3">
        <span class="text-sm font-medium text-text-primary">Sandbox</span>
        <span class="{PILL} {config.sandbox_mode === 'none' || !config.sandbox_mode ? 'bg-surface-elevated text-text-secondary' : 'bg-success-muted text-success'}">{config.sandbox_mode ?? "none"}</span>
      </div>
      <p class="text-xs text-text-muted leading-relaxed m-0 break-words">
        {#if config.sandbox_mode === "firecracker"}
          Firecracker microVM (<InlineCode>ECTO_FC_BINARY</InlineCode> is set). Commands run inside an isolated KVM guest.
        {:else if config.sandbox_mode === "docker"}
          Docker/Podman (<InlineCode>ECTO_DOCKER_IMAGE</InlineCode> is set). Commands run in a container with no network, read-only, no new privileges.
        {:else}
          No hardware sandbox. Set <InlineCode>ECTO_FC_BINARY</InlineCode> (Firecracker) or <InlineCode>ECTO_DOCKER_IMAGE</InlineCode> (Docker/Podman) in the environment before launching.
        {/if}
      </p>
    </div>
    {/if}
  </div>
</section>
