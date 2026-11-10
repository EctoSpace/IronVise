import { describe, it, expect, vi, beforeEach } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { baseUrlFor, listModels } from "./providers";
import type { Config, ProviderPreset } from "./types";

const presets: ProviderPreset[] = [
  {
    id: "anthropic",
    label: "Anthropic",
    transport: "anthropic",
    default_base_url: "https://api.anthropic.com",
    default_model: "claude-opus-5-5",
    api_key_env: "ANTHROPIC_API_KEY",
    api_key_required: true,
  },
  {
    id: "openai",
    label: "OpenAI",
    transport: "openai-compatible",
    default_base_url: "https://api.openai.com/v1",
    default_model: "gpt-6-astra",
    api_key_env: "OPENAI_API_KEY",
    api_key_required: true,
  },
  {
    id: "my-local-server",
    label: "My Local Server",
    transport: "openai-compatible",
    default_base_url: "http://127.0.0.1:8080/v1",
    default_model: null,
    api_key_env: null,
    api_key_required: false,
  },
];

function config(overrides: Partial<Config> = {}): Config {
  return { ...overrides };
}

beforeEach(() => {
  invoke.mockReset();
});

describe("baseUrlFor", () => {
  it("reads Ollama's own field for the ollama provider", () => {
    expect(baseUrlFor(config({ ollama_base_url: "http://127.0.0.1:11434" }), presets, "ollama")).toBe(
      "http://127.0.0.1:11434",
    );
  });

  it("is undefined for ollama when the field is empty", () => {
    expect(baseUrlFor(config({ ollama_base_url: "" }), presets, "ollama")).toBeUndefined();
  });

  it("uses the Anthropic preset's address, ignoring openai_base_url", () => {
    expect(
      baseUrlFor(config({ llm_backend: "anthropic", openai_base_url: "http://evil" }), presets, "anthropic"),
    ).toBe("https://api.anthropic.com");
  });

  it("uses the agent's own typed openai_base_url only when this preset is the active backend", () => {
    const cfg = config({ llm_backend: "openai", openai_base_url: "https://my-proxy.example/v1" });
    expect(baseUrlFor(cfg, presets, "openai")).toBe("https://my-proxy.example/v1");
  });

  it("trims the typed openai_base_url before using it", () => {
    const cfg = config({ llm_backend: "openai", openai_base_url: "  https://my-proxy.example/v1  " });
    expect(baseUrlFor(cfg, presets, "openai")).toBe("https://my-proxy.example/v1");
  });

  it("falls back to the preset's default when the active backend's typed URL is blank", () => {
    const cfg = config({ llm_backend: "openai", openai_base_url: "   " });
    expect(baseUrlFor(cfg, presets, "openai")).toBe("https://api.openai.com/v1");
  });

  it("does not use openai_base_url for a preset that is not the active backend", () => {
    const cfg = config({ llm_backend: "openai", openai_base_url: "https://my-proxy.example/v1" });
    expect(baseUrlFor(cfg, presets, "my-local-server")).toBe("http://127.0.0.1:8080/v1");
  });

  it("is undefined when the provider id matches no preset and is not active", () => {
    expect(baseUrlFor(config({ llm_backend: "openai" }), presets, "unknown-provider")).toBeUndefined();
  });
});

describe("listModels", () => {
  it("asks get_provider_models with the resolved base URL and no API key", async () => {
    invoke.mockResolvedValue(["claude-opus-5-5", "claude-sonnet-5-5"]);
    const cfg = config({ llm_backend: "anthropic" });
    const result = await listModels(cfg, presets, "anthropic");
    expect(result).toEqual(["claude-opus-5-5", "claude-sonnet-5-5"]);
    expect(invoke).toHaveBeenCalledWith("get_provider_models", {
      args: { provider: "anthropic", baseUrl: "https://api.anthropic.com", apiKey: null },
    });
  });

  it("passes an undefined baseUrl through when none can be resolved", async () => {
    invoke.mockResolvedValue([]);
    await listModels(config(), presets, "unknown-provider");
    expect(invoke).toHaveBeenCalledWith("get_provider_models", {
      args: { provider: "unknown-provider", baseUrl: undefined, apiKey: null },
    });
  });
});
