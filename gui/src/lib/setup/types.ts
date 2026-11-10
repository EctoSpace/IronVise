// Shapes the setup wizard's steps share.

export type SetupPath = "express" | "custom";
export type DbMode = "sqlite" | "postgres" | "memory";
export type LlmProvider = "ollama_install" | "ollama_existing" | "anthropic" | "openai";

export interface SystemState {
  os: string;
  arch: string;
  ram_gb: number | null;
  ollama_running: boolean;
  ollama_installed: boolean;
  existing_db_path: string | null;
  recommended_model: string;
}
