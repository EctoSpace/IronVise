/**
 * 6c drift gate - screens must use the primitives, not re-inline them.
 *
 * The consolidation is only worth doing if it stays done. Storybook (6d) was
 * the plan's answer to that and is deferred; this is the cheap version of the
 * same idea, and it catches the specific regression that matters: someone
 * pasting a class string back into a screen instead of importing the component.
 *
 * It reads the source rather than the rendered DOM, because the point is the
 * markup people maintain, not the pixels it produces.
 */
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";

// `__dirname` is not defined under ESM, which is how Playwright loads this.
const SCREENS = join(dirname(fileURLToPath(import.meta.url)), "../../src/lib");

/** Class strings that now belong to a primitive, and which one owns them. */
const CONSOLIDATED: Array<{ pattern: string; primitive: string }> = [
  {
    pattern: "text-xs bg-surface-elevated px-1.5 py-0.5 rounded-md",
    primitive: "InlineCode",
  },
  {
    pattern: "text-xs text-text-muted uppercase tracking-wide\"",
    primitive: "FieldLabel",
  },
  {
    pattern: "text-xs text-text-muted uppercase tracking-wider mb-1",
    primitive: "FieldLabel (spacing=\"below\")",
  },
  {
    pattern: "p-5 rounded-xl bg-surface-elevated border border-border-muted/15",
    primitive: "Panel",
  },
  {
    pattern: "text-left text-text-muted text-xs uppercase tracking-wide px-4 py-2.5",
    primitive: "Th",
  },
  {
    pattern: "px-4 py-3 border-b border-border-muted/10 text-text-primary",
    primitive: "Td",
  },
];

function screenFiles(): string[] {
  return readdirSync(SCREENS).filter((f) => f.endsWith(".svelte"));
}

test("screens do not re-inline a class string a primitive already owns", () => {
  const offences: string[] = [];
  for (const file of screenFiles()) {
    const src = readFileSync(join(SCREENS, file), "utf8");
    for (const { pattern, primitive } of CONSOLIDATED) {
      if (src.includes(pattern)) {
        offences.push(`  ${file}: use <${primitive}> instead of "${pattern}"`);
      }
    }
  }
  expect(
    offences,
    `\nA screen re-inlined styling that a primitive owns:\n\n${offences.join("\n")}\n\n` +
      `Import the component from ./ui instead. Consolidating these was 6c; the ` +
      `point was that there is one place to change them.\n`,
  ).toEqual([]);
});

test("every primitive is exported from the barrel", () => {
  // A primitive that exists but is not exported is one a screen cannot import,
  // which is how inline copies start.
  const dir = join(SCREENS, "ui");
  const components = readdirSync(dir).filter((f) => f.endsWith(".svelte"));
  const barrel = readFileSync(join(dir, "index.ts"), "utf8");
  const missing = components.filter((c) => !barrel.includes(`./${c}`));
  expect(missing, `primitives missing from ui/index.ts: ${missing.join(", ")}`).toEqual([]);
});
