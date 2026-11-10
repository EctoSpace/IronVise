// The native <select> look shared by Settings' selects. They keep the native
// element (inline {#each} option markup); sharing the class list is what stops
// the styling drifting between them.
export const SELECT_CLASS =
  "w-full max-w-full sm:max-w-[520px] bg-surface-elevated border border-border-muted " +
  "rounded-xl text-text-primary px-5 py-3 text-sm cursor-pointer " +
  "focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent " +
  "transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed";
