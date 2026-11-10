// Which address and model list a provider gets, as the backend would use them.

import { invoke } from "@tauri-apps/api/core";
import type { Config, ProviderPreset } from "./types";

/** The address the backend uses for `providerId` (see `backend_for` in
 *  crates/host/src/llm/mod.rs): Ollama's own field for Ollama; Anthropic's
 *  preset address (the backend reads only ANTHROPIC_BASE_URL); the
 *  OpenAI-compatible field only for the agent's own preset; otherwise the
 *  preset's default. */
export function baseUrlFor(
  config: Config,
  presets: ProviderPreset[],
  providerId: string,
): string | undefined {
  const preset = presets.find((p) => p.id === providerId);
  if (providerId === "ollama") return config.ollama_base_url || undefined;
  if (providerId === "anthropic") return preset?.default_base_url || undefined;
  if (providerId === config.llm_backend) {
    const typed = (config.openai_base_url ?? "").trim();
    if (typed) return typed;
  }
  return preset?.default_base_url || undefined;
}

/** The chat models `providerId` lists (the backend leaves out embedding,
 *  speech and image models). The API key comes from the credential store or
 *  the environment on the Rust side; the page never holds it. */
export function listModels(
  config: Config,
  presets: ProviderPreset[],
  providerId: string,
): Promise<string[]> {
  return invoke<string[]>("get_provider_models", {
    args: { provider: providerId, baseUrl: baseUrlFor(config, presets, providerId), apiKey: null },
  });
}
