// Pure decisions the setup wizard makes, kept apart from the Svelte views so
// the express/custom/cloud branching - where two real bugs lived (pulling a
// model the cloud path never used, walking cloud through a model step it
// does not have) - can be checked without a DOM.

import type { DbMode, LlmProvider, SetupPath, SystemState } from "./types";

/** Whether this run will actually talk to a local Ollama daemon.
 *
 *  Step 4 picks an Ollama model and provisioning pulls it. Neither is any use
 *  on the cloud path, which reaches an OpenAI-compatible endpoint over HTTP. */
export function usesLocalOllama(
  path: SetupPath,
  systemState: SystemState | null,
  llmProvider: LlmProvider,
): boolean {
  return path === "express"
    ? !!(systemState?.ollama_running || systemState?.ollama_installed)
    : llmProvider === "ollama_install" || llmProvider === "ollama_existing";
}

export function osLabel(systemState: SystemState | null): string {
  return systemState
    ? `${systemState.os} / ${systemState.arch}${
        systemState.ram_gb != null ? ` / ${systemState.ram_gb.toFixed(0)} GB RAM` : ""
      }`
    : "";
}

export interface SetupConfigInput {
  path: SetupPath;
  dbMode: DbMode;
  llmProvider: LlmProvider;
  pgUrl: string;
  ollamaHost: string;
  selectedModel: string;
  cloudModel: string;
  isCloud: boolean;
  usesLocalOllama: boolean;
}

/** The `save_config` payload for the choices made so far, plus the log lines
 *  the Provisioning step should show for them. Express and Custom build
 *  mutually exclusive log lines, so the order they are pushed in does not
 *  matter - only one of the express/postgres/memory/sqlite lines ever fires
 *  for a given input. */
export function buildSetupConfig(input: SetupConfigInput): {
  config: Record<string, unknown>;
  logLines: string[];
} {
  const { path, dbMode, llmProvider, pgUrl, ollamaHost, selectedModel, cloudModel, isCloud, usesLocalOllama } = input;
  const isExpress = path === "express";
  const config: Record<string, unknown> = {
    llm_backend: usesLocalOllama ? "ollama" : isExpress ? "openai" : llmProvider,
  };
  const logLines: string[] = [];

  if (usesLocalOllama && selectedModel) config.ollama_model = selectedModel;
  if (!isExpress && isCloud && cloudModel) config.ollama_model = cloudModel;

  if (isExpress) {
    // Express uses embedded SQLite - full single-machine audits without Postgres.
    logLines.push(
      "Express uses embedded SQLite. Home → Run and certificate export are available once an LLM is configured.",
    );
  }
  if (!isExpress && dbMode === "postgres" && pgUrl) {
    config.database_url = pgUrl;
    logLines.push("PostgreSQL URL saved - restart the app so the new ledger connection takes effect.");
  }
  if (!isExpress && dbMode === "memory") config.database_url = "sqlite::memory:";
  if (!isExpress && dbMode === "sqlite") {
    logLines.push(
      "SQLite selected - Home → Run, History, certificate export, and webhook delivery work without a database server. Use PostgreSQL for multi-agent orchestration.",
    );
  }
  if (!isExpress && llmProvider === "ollama_existing" && ollamaHost) config.ollama_base_url = ollamaHost;

  return { config, logLines };
}
