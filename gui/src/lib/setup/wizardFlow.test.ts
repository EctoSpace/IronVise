import { describe, it, expect } from "vitest";
import { usesLocalOllama, osLabel, buildSetupConfig } from "./wizardFlow";
import type { SystemState } from "./types";

const SYSTEM: SystemState = {
  os: "macOS",
  arch: "arm64",
  ram_gb: 16,
  ollama_running: true,
  ollama_installed: true,
  existing_db_path: null,
  recommended_model: "llama3.2:3b",
};

describe("usesLocalOllama", () => {
  it("express: local Ollama when it is running or installed", () => {
    expect(usesLocalOllama("express", SYSTEM, "openai")).toBe(true);
    expect(usesLocalOllama("express", { ...SYSTEM, ollama_running: false, ollama_installed: false }, "openai")).toBe(false);
  });

  it("express: a null system state has no local Ollama", () => {
    expect(usesLocalOllama("express", null, "openai")).toBe(false);
  });

  it("custom: local Ollama only for the two Ollama provider choices", () => {
    expect(usesLocalOllama("custom", SYSTEM, "ollama_install")).toBe(true);
    expect(usesLocalOllama("custom", SYSTEM, "ollama_existing")).toBe(true);
    expect(usesLocalOllama("custom", SYSTEM, "anthropic")).toBe(false);
    expect(usesLocalOllama("custom", SYSTEM, "openai")).toBe(false);
  });
});

describe("osLabel", () => {
  it("is blank before detection", () => {
    expect(osLabel(null)).toBe("");
  });

  it("includes RAM when known", () => {
    expect(osLabel(SYSTEM)).toBe("macOS / arm64 / 16 GB RAM");
  });

  it("omits RAM when unknown", () => {
    expect(osLabel({ ...SYSTEM, ram_gb: null })).toBe("macOS / arm64");
  });
});

describe("buildSetupConfig", () => {
  const base = {
    path: "custom" as const,
    dbMode: "sqlite" as const,
    llmProvider: "ollama_existing" as const,
    pgUrl: "",
    ollamaHost: "",
    selectedModel: "",
    cloudModel: "",
    isCloud: false,
    usesLocalOllama: false,
  };

  it("express uses openai as the backend label and logs the SQLite note, with no database_url", () => {
    const { config, logLines } = buildSetupConfig({ ...base, path: "express", usesLocalOllama: true, selectedModel: "llama3.2:3b" });
    expect(config).toEqual({ llm_backend: "ollama", ollama_model: "llama3.2:3b" });
    expect(logLines).toEqual([
      "Express uses embedded SQLite. Home → Run and certificate export are available once an LLM is configured.",
    ]);
  });

  it("express without a local Ollama running still configures openai", () => {
    const { config } = buildSetupConfig({ ...base, path: "express", usesLocalOllama: false });
    expect(config.llm_backend).toBe("openai");
    expect(config.ollama_model).toBeUndefined();
  });

  it("custom + local Ollama pulls the selected model and the existing host", () => {
    const { config, logLines } = buildSetupConfig({
      ...base,
      usesLocalOllama: true,
      selectedModel: "llama3.1:8b",
      ollamaHost: "http://127.0.0.1:11434",
    });
    expect(config).toEqual({
      llm_backend: "ollama",
      ollama_model: "llama3.1:8b",
      ollama_base_url: "http://127.0.0.1:11434",
    });
    expect(logLines).toEqual([
      "SQLite selected - Home → Run, History, certificate export, and webhook delivery work without a database server. Use PostgreSQL for multi-agent orchestration.",
    ]);
  });

  it("custom + postgres saves the URL and logs the restart note", () => {
    const { config, logLines } = buildSetupConfig({
      ...base,
      dbMode: "postgres",
      pgUrl: "postgres://localhost/db",
      llmProvider: "anthropic",
    });
    expect(config.database_url).toBe("postgres://localhost/db");
    expect(logLines).toEqual(["PostgreSQL URL saved - restart the app so the new ledger connection takes effect."]);
  });

  it("custom + memory sets the in-memory URL with no log line", () => {
    const { config, logLines } = buildSetupConfig({ ...base, dbMode: "memory", llmProvider: "anthropic" });
    expect(config.database_url).toBe("sqlite::memory:");
    expect(logLines).toEqual([]);
  });

  it("custom + sqlite logs the no-server note", () => {
    const { logLines } = buildSetupConfig({ ...base, dbMode: "sqlite", llmProvider: "anthropic" });
    expect(logLines).toEqual([
      "SQLite selected - Home → Run, History, certificate export, and webhook delivery work without a database server. Use PostgreSQL for multi-agent orchestration.",
    ]);
  });

  it("custom + cloud provider sends the chosen cloud model as ollama_model, never pulling one", () => {
    const { config } = buildSetupConfig({
      ...base,
      llmProvider: "anthropic",
      isCloud: true,
      cloudModel: "claude-sonnet-4-5",
      selectedModel: "llama3.2:3b", // pre-filled recommended model; must be ignored on the cloud path
      usesLocalOllama: false,
    });
    expect(config.llm_backend).toBe("anthropic");
    expect(config.ollama_model).toBe("claude-sonnet-4-5");
  });
});
