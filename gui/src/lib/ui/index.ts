// IronVise UI primitives.
//
// Screens import from here rather than repeating class strings. That is not a
// style preference: the webhook filter picker once offered ten event kinds the
// server never emitted, because the list had been copied instead of derived,
// and nothing failed when they drifted apart.
//
// tests/visual/primitives.spec.ts fails the build if a screen re-inlines a
// class string one of these owns, and names the component to use instead.
//
// Adding one? Export it here - the same test checks that every primitive in
// this directory is reachable from the barrel, since one that is not is one a
// screen cannot import.

export { default as Button } from "./Button.svelte";
export { default as Card } from "./Card.svelte";
export { default as Badge } from "./Badge.svelte";
export { default as Input } from "./Input.svelte";
export { default as StatusDot } from "./StatusDot.svelte";
export { default as Select } from "./Select.svelte";
export { default as Toast } from "./Toast.svelte";
export type { ToastMessage } from "./Toast.svelte";
export { default as CopyButton } from "./CopyButton.svelte";
export { default as CodeBlock } from "./CodeBlock.svelte";
export { default as InlineCode } from "./InlineCode.svelte";
export { default as FieldLabel } from "./FieldLabel.svelte";
export { default as Panel } from "./Panel.svelte";
export { default as Th } from "./Th.svelte";
export { default as Td } from "./Td.svelte";
export { default as Switch } from "./Switch.svelte";
export { default as ListEditor } from "./ListEditor.svelte";
export { default as SaveBar } from "./SaveBar.svelte";
