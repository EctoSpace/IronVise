// Attributes that keep the OS's own text help out of a search field:
// autocomplete history, autocorrect, spellcheck and macOS writing
// suggestions, which WebKit draws as a chip under the field. Spread onto the
// input; `autocorrect` and `writingsuggestions` are not in Svelte's typings.
export const NO_SUGGESTIONS: Record<string, string> = {
  autocomplete: "off",
  autocapitalize: "off",
  autocorrect: "off",
  spellcheck: "false",
  writingsuggestions: "false",
};
