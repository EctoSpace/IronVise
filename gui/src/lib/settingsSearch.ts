// Matching logic for the Settings search field. Kept free of Svelte so it is
// unit testable on its own; Settings.svelte owns the input, the "no settings
// match" state and wiring the result into each section.

export interface SettingsFieldMeta {
  /** Visible label text, exactly as the field renders it. */
  label: string;
  /** Extra words a query can match, invisible in the list. */
  keywords?: string[];
}

export interface SettingsSectionMeta {
  id: string;
  label: string;
  fields: SettingsFieldMeta[];
}

/** The six Settings sections and their individually-searchable fields. Kept
 *  here rather than inferred from the DOM, so a label that only ever reads
 *  from this list cannot drift from what Settings.svelte actually searches. */
export const SETTINGS_SECTIONS: SettingsSectionMeta[] = [
  {
    id: "settings-ledger",
    label: "Ledger",
    fields: [
      { label: "Database for the next start", keywords: ["postgres", "sqlite", "database", "url"] },
    ],
  },
  {
    id: "settings-model",
    label: "Model",
    fields: [
      { label: "Provider", keywords: ["ollama", "openai", "anthropic", "llm", "backend"] },
      { label: "Model", keywords: ["llm model", "chat model"] },
      { label: "API key", keywords: ["anthropic", "openai", "credential", "secret", "keychain"] },
      { label: "Address", keywords: ["base url", "endpoint", "host"] },
    ],
  },
  {
    id: "settings-guard",
    label: "Semantic guard",
    fields: [
      { label: "Guard provider", keywords: ["semantic guard", "llm guard"] },
      { label: "Guard model", keywords: ["semantic guard", "llm guard"] },
    ],
  },
  {
    id: "settings-agent",
    label: "Agent",
    fields: [
      { label: "Max steps per session", keywords: ["loop", "limit", "steps"] },
      { label: "Allowed domains (HTTP)", keywords: ["tripwire", "http", "domains"] },
    ],
  },
  {
    id: "settings-desktop",
    label: "Desktop",
    fields: [
      { label: "Appearance", keywords: ["theme", "dark", "light", "system"] },
      { label: "Show developer tools", keywords: ["testing", "prometheus", "dev hub", "sidebar", "developer"] },
    ],
  },
  {
    id: "settings-environment",
    label: "From the environment",
    fields: [
      { label: "Sandbox", keywords: ["firecracker", "docker", "podman"] },
    ],
  },
];

export interface SettingsFilterResult {
  id: string;
  visible: boolean;
  /** `null` means every field in the section should show (the section
   *  itself matched, or there is no query); otherwise only these labels. */
  visibleFields: Set<string> | null;
}

function matches(haystack: string, query: string): boolean {
  return haystack.toLowerCase().includes(query);
}

/** True when `label` or any of `keywords` contains `query` (case-insensitive). */
export function fieldMatches(field: SettingsFieldMeta, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  if (matches(field.label, q)) return true;
  return (field.keywords ?? []).some((k) => matches(k, q));
}

/** Filters every section against `query`: a section shows in full when its
 *  own name matches, shows only its matching fields when just those match,
 *  and is hidden entirely otherwise. An empty query shows everything. */
export function filterSettingsSections(
  sections: SettingsSectionMeta[],
  query: string,
): SettingsFilterResult[] {
  const q = query.trim();
  if (!q) return sections.map((s) => ({ id: s.id, visible: true, visibleFields: null }));

  return sections.map((s) => {
    if (matches(s.label, q.toLowerCase())) {
      return { id: s.id, visible: true, visibleFields: null };
    }
    const visibleFields = new Set(s.fields.filter((f) => fieldMatches(f, q)).map((f) => f.label));
    return { id: s.id, visible: visibleFields.size > 0, visibleFields };
  });
}
