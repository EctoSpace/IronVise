<!-- DesktopSection: app-only switches and per-device UI preferences. -->
<script lang="ts">
  import { Switch } from "../ui";
  import { SELECT_CLASS } from "./selectClass";
  import { themePreference, type ThemePreference } from "../stores/theme";
  import { type Config, SECTION_CLASS, SECTION_TITLE_CLASS, LABEL_CLASS, HINT_CLASS } from "./types";

  let {
    config = $bindable(),
    visibleFields = null,
  }: { config: Config; visibleFields?: Set<string> | null } = $props();

  function shows(field: string): boolean {
    return !visibleFields || visibleFields.has(field);
  }

  function onAppearanceChange(e: Event) {
    themePreference.set((e.currentTarget as HTMLSelectElement).value as ThemePreference);
  }
</script>

<section id="settings-desktop" tabindex="-1" class={SECTION_CLASS}>
  <h3 class={SECTION_TITLE_CLASS}>Desktop</h3>
  {#if shows("Appearance")}
    <div class="min-w-0">
      <label for="settings-appearance" class={LABEL_CLASS}>Appearance</label>
      <select
        id="settings-appearance"
        class="{SELECT_CLASS} sm:max-w-[220px]"
        value={$themePreference}
        onchange={onAppearanceChange}
      >
        <option value="system">Match system</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
      <p class={HINT_CLASS}>Applies immediately and stays on this device - it is not part of settings.json.</p>
    </div>
  {/if}
  {#if shows("Show developer tools")}
    <div class="flex items-start justify-between gap-4 min-w-0">
      <div class="min-w-0">
        <p id="settings-devtools-label" class="text-sm font-medium text-text-primary m-0">Show developer tools</p>
        <p class="text-xs text-text-muted leading-relaxed mt-1 mb-0 break-words">Adds Testing, Prometheus, Live Feed and Dev Hub to the sidebar. For maintainers; demo mode turns it on.</p>
      </div>
      <Switch id="settings-devtools" bind:checked={config.show_developer_tools} labelledby="settings-devtools-label" />
    </div>
  {/if}
</section>
