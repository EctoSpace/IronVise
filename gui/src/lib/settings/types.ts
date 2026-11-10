// Shapes the Settings screen shares between its sections.

/** `GET /api/config`, as Settings edits it. Text fields are normalised to ""
 *  on load so they can be bound to inputs; Save sends "" to clear one. */
export interface Config {
  database_url?: string;
  llm_backend?: string;
  ollama_base_url?: string;
  openai_base_url?: string;
  /** The agent's model, whatever the provider (the name predates presets). */
  ollama_model?: string;
  guard_required?: boolean;
  guard_required_source?: string;
  guard_llm_backend?: string;
  guard_llm_model?: string;
  max_steps?: number;
  agent_allowed_domains?: string[];
  show_developer_tools?: boolean;
  // Read-only, computed by the server from the environment and the live pool.
  sandbox_mode?: string; // "none" | "docker" | "firecracker"
  ledger_backend?: string;
  agent_supported?: boolean;
}

/** A provider preset, served from the Rust preset table (`get_provider_presets`)
 *  rather than copied here: a copied list is how the webhook filter picker once
 *  offered ten kinds the server never emitted. */
export interface ProviderPreset {
  id: string;
  label: string;
  transport: string;
  default_base_url: string | null;
  default_model: string | null;
  api_key_env: string | null;
  api_key_required: boolean;
}

/** Section card chrome, shared so the sections cannot drift apart. */
export const SECTION_CLASS =
  "rounded-2xl bg-surface border border-border-muted/40 shadow-sm p-6 flex flex-col gap-4 min-w-0 scroll-mt-4";
export const SECTION_TITLE_CLASS =
  "text-xs font-semibold uppercase tracking-[0.1em] text-text-secondary m-0";
export const LABEL_CLASS = "block text-sm font-medium text-text-primary mb-1.5";
export const HINT_CLASS = "text-xs text-text-muted leading-relaxed mt-2 mb-0 break-words";
