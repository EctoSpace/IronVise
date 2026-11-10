import { describe, expect, it, vi, afterEach } from "vitest";
import {
  filterPaletteItems,
  groupPaletteItems,
  isPaletteShortcut,
  paletteShortcutLabel,
  scoreItem,
  type PaletteItem,
} from "./commandPalette";

const ITEMS: PaletteItem[] = [
  { id: "screen:dashboard", label: "Home", group: "Screens", keywords: ["dashboard"] },
  { id: "screen:sessions", label: "History", group: "Screens", keywords: ["sessions", "audit log"] },
  { id: "settings:settings-ledger", label: "Settings → Ledger", group: "Settings", keywords: ["database", "postgres", "sqlite"] },
  { id: "action:theme-dark", label: "Switch theme to Dark", group: "Actions", keywords: ["appearance", "dark mode"] },
];

describe("scoreItem", () => {
  it("returns 0 for an empty query on every item", () => {
    for (const item of ITEMS) expect(scoreItem(item, "")).toBe(0);
    expect(scoreItem(ITEMS[0], "   ")).toBe(0);
  });

  it("ranks an exact label match above a prefix match", () => {
    const exact = scoreItem(ITEMS[0], "Home");
    const prefix = scoreItem(ITEMS[0], "Ho");
    expect(exact).toBeGreaterThan(prefix);
    expect(exact).toBe(100);
  });

  it("is case-insensitive", () => {
    expect(scoreItem(ITEMS[0], "HOME")).toBe(scoreItem(ITEMS[0], "home"));
  });

  it("ranks a label substring above any keyword match", () => {
    const labelSub = scoreItem(ITEMS[1], "stor"); // "Hi-stor-y"
    const keyword = scoreItem(ITEMS[1], "sessions");
    expect(labelSub).toBeGreaterThan(keyword);
  });

  it("matches on a keyword the label does not contain", () => {
    expect(scoreItem(ITEMS[2], "postgres")).toBeGreaterThanOrEqual(0);
    expect(scoreItem(ITEMS[2], "nonsense-keyword")).toBe(-1);
  });

  it("falls back to an in-order subsequence match on the label", () => {
    // "stlgr" has no substring match in "Settings → Ledger" but is a
    // subsequence of it (s-t...l-g-r), so it should not be excluded.
    expect(scoreItem(ITEMS[2], "stlgr")).toBeGreaterThanOrEqual(0);
  });

  it("excludes an item with no relation to the query", () => {
    expect(scoreItem(ITEMS[0], "zzzzz")).toBe(-1);
  });
});

describe("filterPaletteItems", () => {
  it("returns every item, in order, for an empty query", () => {
    expect(filterPaletteItems(ITEMS, "")).toEqual(ITEMS);
  });

  it("excludes non-matching items", () => {
    const result = filterPaletteItems(ITEMS, "dark");
    expect(result.map((i) => i.id)).toEqual(["action:theme-dark"]);
  });

  it("ranks better matches first", () => {
    const result = filterPaletteItems(ITEMS, "hi");
    // "History" (prefix) beats anything matched only via keyword/subsequence.
    expect(result[0].id).toBe("screen:sessions");
  });

  it("matches by keyword as well as by label", () => {
    const result = filterPaletteItems(ITEMS, "audit log");
    expect(result.map((i) => i.id)).toContain("screen:sessions");
  });

  it("breaks score ties alphabetically by label", () => {
    const sameScore: PaletteItem[] = [
      { id: "b", label: "Bravo", group: "Actions", keywords: ["shared"] },
      { id: "a", label: "Alpha", group: "Actions", keywords: ["shared"] },
    ];
    const result = filterPaletteItems(sameScore, "shared");
    expect(result.map((i) => i.id)).toEqual(["a", "b"]);
  });
});

describe("groupPaletteItems", () => {
  it("groups in a fixed order and drops empty groups", () => {
    const grouped = groupPaletteItems(filterPaletteItems(ITEMS, ""));
    expect(grouped.map((g) => g.group)).toEqual(["Screens", "Settings", "Actions"]);
  });

  it("omits a group with no matches", () => {
    const grouped = groupPaletteItems(filterPaletteItems(ITEMS, "dark"));
    expect(grouped.map((g) => g.group)).toEqual(["Actions"]);
  });

  it("preserves item order within a group", () => {
    const grouped = groupPaletteItems(ITEMS);
    const screens = grouped.find((g) => g.group === "Screens");
    expect(screens?.items.map((i) => i.id)).toEqual(["screen:dashboard", "screen:sessions"]);
  });
});

describe("paletteShortcutLabel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the Command glyph on macOS", () => {
    vi.stubGlobal("navigator", { platform: "MacIntel" });
    expect(paletteShortcutLabel()).toBe("⌘K");
  });

  it("shows Ctrl+K elsewhere", () => {
    vi.stubGlobal("navigator", { platform: "Win32" });
    expect(paletteShortcutLabel()).toBe("Ctrl+K");
  });

  it("returns one of the two known labels on the real test environment", () => {
    expect(["⌘K", "Ctrl+K"]).toContain(paletteShortcutLabel());
  });
});

describe("isPaletteShortcut", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("requires Meta+K on macOS, not Ctrl+K", () => {
    vi.stubGlobal("navigator", { platform: "MacIntel" });
    expect(isPaletteShortcut({ key: "k", metaKey: true, ctrlKey: false })).toBe(true);
    expect(isPaletteShortcut({ key: "k", metaKey: false, ctrlKey: true })).toBe(false);
  });

  it("requires Ctrl+K elsewhere, not Meta+K", () => {
    vi.stubGlobal("navigator", { platform: "Win32" });
    expect(isPaletteShortcut({ key: "k", metaKey: false, ctrlKey: true })).toBe(true);
    expect(isPaletteShortcut({ key: "k", metaKey: true, ctrlKey: false })).toBe(false);
  });

  it("ignores every other key", () => {
    vi.stubGlobal("navigator", { platform: "Win32" });
    expect(isPaletteShortcut({ key: "j", metaKey: false, ctrlKey: true })).toBe(false);
  });

  it("is case-insensitive on the key", () => {
    vi.stubGlobal("navigator", { platform: "Win32" });
    expect(isPaletteShortcut({ key: "K", metaKey: false, ctrlKey: true })).toBe(true);
  });
});
