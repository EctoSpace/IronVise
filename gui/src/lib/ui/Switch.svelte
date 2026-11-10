<!--
  Switch - an on/off control for a setting that takes effect as a whole
  (the semantic guard, developer tools, require HTTPS). A real <button
  role="switch"> with aria-checked, so it reads as a switch and toggles on
  Space and Enter; the visible label is the caller's, linked by `labelledby`.

  Not for choices with more than two states, and not for an action: those
  stay a Select and a Button.
-->
<script lang="ts">
  interface Props {
    checked?: boolean;
    disabled?: boolean;
    /** id of the element that names this switch. */
    labelledby?: string;
    /** Accessible name when no visible label element exists. */
    ariaLabel?: string;
    id?: string;
    class?: string;
    onchange?: (checked: boolean) => void;
  }

  let {
    checked = $bindable(false),
    disabled = false,
    labelledby,
    ariaLabel,
    id,
    class: className = "",
    onchange,
  }: Props = $props();

  function toggle() {
    if (disabled) return;
    checked = !checked;
    onchange?.(checked);
  }
</script>

<button
  {id}
  type="button"
  role="switch"
  aria-checked={checked}
  aria-labelledby={labelledby}
  aria-label={ariaLabel}
  {disabled}
  onclick={toggle}
  class="relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border-none p-0 cursor-pointer transition-colors duration-200
    focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent
    disabled:opacity-50 disabled:cursor-not-allowed
    {checked ? 'bg-accent' : 'bg-border-muted'} {className}"
>
  <span
    aria-hidden="true"
    class="inline-block h-4 w-4 rounded-full transition-transform duration-200 {checked ? 'translate-x-6 bg-text-inverse' : 'translate-x-1 bg-text-muted'}"
  ></span>
</button>
