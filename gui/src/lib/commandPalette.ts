// Command palette: the list of reachable things, and the filtering/ranking
// logic over them. Kept free of Svelte and of `invoke` so it can be unit
// tested directly - CommandPalette.svelte owns the dialog, keyboard wiring
// and DOM; this module owns "does this query match this item, and in what
// order".

export type PaletteGroup = "Screens" | "Settings" | "Actions";

export interface PaletteItem {
  /** Unique, and meaningful to the caller: "screen:<tabId>", "settings:<sectionId>", "action:<name>". */
  id: string;
  label: string;
  group: PaletteGroup;
  /** Extra words a query can match against, invisible in the list. */
  keywords?: string[];
  /** Short text shown at the end of the row, e.g. a shortcut or a note. */
  hint?: string;
}

function isSubsequence(query: string, text: string): boolean {
  if (query.length === 0) return true;
  let i = 0;
  for (const ch of text) {
    if (ch === query[i]) i++;
    if (i === query.length) return true;
  }
  return false;
}

/** -1 when `item` does not match `query` at all; otherwise higher is a better
 *  match. An exact label match ranks above a prefix, which ranks above a
 *  substring, which ranks above the same tiers on a keyword, with a loose
 *  in-order subsequence match (fuzzy: "stg lgr" finds "Settings → Ledger")
 *  as the last resort. */
export function scoreItem(item: PaletteItem, query: string): number {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const label = item.label.toLowerCase();

  if (label === q) return 100;
  if (label.startsWith(q)) return 80;
  if (label.includes(q)) return 60;

  for (const raw of item.keywords ?? []) {
    const kw = raw.toLowerCase();
    if (kw === q) return 50;
    if (kw.startsWith(q)) return 40;
    if (kw.includes(q)) return 20;
  }

  if (isSubsequence(q, label)) return 5;

  return -1;
}

/** Filters and ranks `items` against `query`. An empty query returns every
 *  item in its given order (the palette's "browse everything" state). */
export function filterPaletteItems(items: PaletteItem[], query: string): PaletteItem[] {
  if (!query.trim()) return items;
  return items
    .map((item) => ({ item, score: scoreItem(item, query) }))
    .filter((r) => r.score >= 0)
    .sort((a, b) => b.score - a.score || a.item.label.localeCompare(b.item.label))
    .map((r) => r.item);
}

/** Groups already-filtered results, in a fixed group order, dropping empty
 *  groups. Order within a group is preserved from `items`. */
export function groupPaletteItems(items: PaletteItem[]): { group: PaletteGroup; items: PaletteItem[] }[] {
  const order: PaletteGroup[] = ["Screens", "Settings", "Actions"];
  return order
    .map((group) => ({ group, items: items.filter((i) => i.group === group) }))
    .filter((g) => g.items.length > 0);
}

function isMac(): boolean {
  const platform =
    typeof navigator !== "undefined" ? navigator.platform || navigator.userAgent || "" : "";
  return /Mac|iPod|iPhone|iPad/.test(platform);
}

/** macOS uses the Command glyph; everywhere else types Ctrl. Guarded for
 *  environments (SSR, a very old WebView) with no `navigator`. */
export function paletteShortcutLabel(): string {
  return isMac() ? "⌘K" : "Ctrl+K";
}

/** ⌘K on macOS, Ctrl+K elsewhere - not both on the same platform. Plain
 *  Ctrl+K on macOS is already taken (kill-to-end-of-line in a text field),
 *  so accepting it there would fight that binding instead of adding one. */
export function isPaletteShortcut(e: Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey">): boolean {
  if (e.key.toLowerCase() !== "k") return false;
  return isMac() ? e.metaKey : e.ctrlKey;
}
