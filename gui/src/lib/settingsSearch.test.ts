import { describe, expect, it } from "vitest";
import { fieldMatches, filterSettingsSections, SETTINGS_SECTIONS, type SettingsSectionMeta } from "./settingsSearch";

const SECTIONS: SettingsSectionMeta[] = [
  {
    id: "settings-ledger",
    label: "Ledger",
    fields: [{ label: "Database for the next start", keywords: ["postgres", "sqlite"] }],
  },
  {
    id: "settings-model",
    label: "Model",
    fields: [
      { label: "Provider", keywords: ["ollama", "anthropic"] },
      { label: "API key", keywords: ["credential"] },
    ],
  },
  {
    id: "settings-desktop",
    label: "Desktop",
    fields: [{ label: "Appearance", keywords: ["theme", "dark", "light"] }],
  },
];

describe("fieldMatches", () => {
  it("matches an empty query against anything", () => {
    expect(fieldMatches(SECTIONS[0].fields[0], "")).toBe(true);
    expect(fieldMatches(SECTIONS[0].fields[0], "   ")).toBe(true);
  });

  it("matches the field label, case-insensitively", () => {
    expect(fieldMatches(SECTIONS[2].fields[0], "appear")).toBe(true);
    expect(fieldMatches(SECTIONS[2].fields[0], "APPEARANCE")).toBe(true);
  });

  it("matches a keyword the label does not contain", () => {
    expect(fieldMatches(SECTIONS[2].fields[0], "dark")).toBe(true);
  });

  it("does not match unrelated text", () => {
    expect(fieldMatches(SECTIONS[2].fields[0], "postgres")).toBe(false);
  });
});

describe("filterSettingsSections", () => {
  it("shows every section with every field for an empty query", () => {
    const result = filterSettingsSections(SECTIONS, "");
    expect(result).toEqual(SECTIONS.map((s) => ({ id: s.id, visible: true, visibleFields: null })));
  });

  it("shows a section in full when the query matches its own name", () => {
    const result = filterSettingsSections(SECTIONS, "model");
    const model = result.find((r) => r.id === "settings-model");
    expect(model).toEqual({ id: "settings-model", visible: true, visibleFields: null });
  });

  it("hides a section with no matching name or field", () => {
    const result = filterSettingsSections(SECTIONS, "nothing-matches-this");
    expect(result.every((r) => !r.visible)).toBe(true);
  });

  it("shows only the matching fields when the section name itself does not match", () => {
    const result = filterSettingsSections(SECTIONS, "credential");
    const model = result.find((r) => r.id === "settings-model");
    expect(model?.visible).toBe(true);
    expect(model?.visibleFields).toEqual(new Set(["API key"]));

    const ledger = result.find((r) => r.id === "settings-ledger");
    expect(ledger?.visible).toBe(false);
  });

  it("matches a field via keyword across sections", () => {
    const result = filterSettingsSections(SECTIONS, "theme");
    const visible = result.filter((r) => r.visible).map((r) => r.id);
    expect(visible).toEqual(["settings-desktop"]);
  });

  it("is case-insensitive and trims whitespace", () => {
    const a = filterSettingsSections(SECTIONS, "  PROVIDER  ");
    const b = filterSettingsSections(SECTIONS, "provider");
    expect(a).toEqual(b);
  });
});

describe("SETTINGS_SECTIONS", () => {
  it("has a unique id per section", () => {
    const ids = SETTINGS_SECTIONS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("has at least one field per section", () => {
    for (const s of SETTINGS_SECTIONS) {
      expect(s.fields.length).toBeGreaterThan(0);
    }
  });
});
