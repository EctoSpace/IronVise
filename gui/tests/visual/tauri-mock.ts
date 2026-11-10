/**
 * Browser-side Tauri mock for the visual baseline.
 *
 * The app refuses to render outside Tauri: `App.svelte` calls `isTauri()` and
 * throws "Run this app via the IronVise desktop window" otherwise, so a plain
 * Playwright run against the Vite dev server only ever shows the connection
 * error card. Every screen also reads its data through `invoke()` rather than
 * `fetch`, so one seam covers both problems - install a fake
 * `window.__TAURI_INTERNALS__` before the app boots and each screen renders
 * against fixed data.
 *
 * These screenshots are a **layout** baseline, not a data one. Their job is to
 * prove that CSS work (radius scale, contrast, moving screens onto the
 * `lib/ui` primitives) changed the screens it meant to change and left the rest
 * alone. That only holds if the fixtures are byte-identical before and after,
 * which is why everything here is a constant: no clocks, no randomness, no
 * network.
 */
import type { Page } from "@playwright/test";

/** Fixed instant used for every timestamp, so nothing renders "3 minutes ago". */
const T0 = "2026-01-01T00:00:00Z";

const SESSIONS = [
  {
    id: "11111111-1111-4111-8111-111111111111",
    goal: "Audit server_config.txt for misconfigurations",
    goal_hash: "a1b2c3d4e5f6a7b8",
    status: "completed",
    llm_backend: "ollama",
    llm_model: "mistral",
    created_at: T0,
    finished_at: T0,
    policy_hash: "9f8e7d6c5b4a3928",
    session_public_key: "ed25519:AAAABBBBCCCCDDDD",
    session_did: "did:key:z6MkfrQ1example",
  },
  {
    id: "22222222-2222-4222-8222-222222222222",
    goal: "Enumerate listening services on the host",
    goal_hash: "b2c3d4e5f6a7b8c9",
    status: "running",
    llm_backend: "ollama",
    llm_model: "mistral",
    created_at: T0,
    finished_at: null,
    policy_hash: "9f8e7d6c5b4a3928",
    session_public_key: "ed25519:EEEEFFFF00001111",
    session_did: null,
  },
  {
    id: "33333333-3333-4333-8333-333333333333",
    goal: "Review TLS configuration of the public endpoint",
    goal_hash: "c3d4e5f6a7b8c9d0",
    status: "denied",
    llm_backend: "openai",
    llm_model: "gpt-6-astra",
    created_at: T0,
    finished_at: T0,
    policy_hash: "9f8e7d6c5b4a3928",
    session_public_key: "ed25519:2222333344445555",
    session_did: null,
  },
];

// Payloads use the real `EventPayload` shape (`type`-tagged, see
// crates/host/src/schema.rs). They used a `kind` field no event has, so every
// screen fell through to its raw-JSON branch and the baseline never showed
// how a refusal actually looks.
const EVENTS = [
  {
    id: 1,
    sequence: 1,
    previous_hash: "0".repeat(64),
    content_hash: "a".repeat(64),
    payload: { type: "genesis", message: "IronVise genesis" },
    created_at: T0,
  },
  {
    id: 2,
    sequence: 2,
    previous_hash: "a".repeat(64),
    content_hash: "b".repeat(64),
    payload: { type: "prompt_input", content: "Audit server_config.txt for misconfigurations" },
    created_at: T0,
  },
  {
    id: 3,
    sequence: 3,
    previous_hash: "b".repeat(64),
    content_hash: "c".repeat(64),
    payload: {
      type: "action",
      name: "read_file",
      params: { path: "server_config.txt" },
    },
    created_at: T0,
  },
  {
    id: 4,
    sequence: 4,
    previous_hash: "c".repeat(64),
    content_hash: "d".repeat(64),
    payload: { type: "observation", content: "PermitRootLogin yes\nPort 22" },
    created_at: T0,
  },
  {
    id: 5,
    sequence: 5,
    previous_hash: "d".repeat(64),
    content_hash: "5".repeat(64),
    // The hash is the real SHA-256 of the observation text above.
    payload: {
      type: "data_receipt",
      tool: "read_file",
      source: "server_config.txt",
      response_sha256: "7".repeat(64),
      text_sha256: ["32603f99b0517153dfc7d3b09eb6c6a3a0af95fb45738fd67db940e0f9295c27"],
      text_bytes: 27,
    },
    created_at: T0,
  },
  {
    id: 6,
    sequence: 6,
    previous_hash: "5".repeat(64),
    content_hash: "e".repeat(64),
    payload: {
      type: "tripwire_rejection",
      action: "run_command",
      reason: "Command matches banned pattern: curl .* | sh",
      stage: "policy",
      enforced: true,
    },
    created_at: T0,
  },
  {
    id: 7,
    sequence: 7,
    previous_hash: "e".repeat(64),
    content_hash: "f".repeat(64),
    payload: {
      type: "guard_denial",
      action: "http_get",
      reason: "Request is outside the stated audit goal.",
      enforced: true,
    },
    created_at: T0,
  },
];

const CONFIG = {
  database_url: "postgres://ectoledger:****@localhost:5432/ectoledger",
  llm_backend: "ollama",
  ollama_base_url: "http://127.0.0.1:11434",
  openai_base_url: "https://api.openai.com/v1",
  ollama_model: "mistral",
  guard_required: true,
  guard_llm_backend: "ollama",
  guard_llm_model: "qwen2.5:0.5b",
  max_steps: 25,
  agent_allowed_domains: ["example.com", "docs.example.com"],
  sandbox_mode: "docker",
  demo_mode: false,
  show_developer_tools: false,
  ledger_backend: "sqlite",
  agent_supported: true,
  exports_supported: true,
  webhooks_live: true,
};

/** Flat map - the Dashboard just renders `Object.entries(metrics)`. */
// The shape `/api/metrics/security` serves (server/observability.rs). It used
// to carry a `chain_verified` the server never sent, so Home's third tile
// was green in every baseline and "Check" in every real install.
const METRICS = {
  injection_attempts_detected_7d: 6,
  injection_attempts_by_layer: { tripwire: 2, guard_llm: 4 },
  sessions_aborted_circuit_breaker: 0,
  chain_verification_failures: 0,
  total_sessions: 3,
  total_events: 128,
  guard_denials: 4,
  tripwire_rejections: 2,
};

const PROMETHEUS_METRICS = [
  "# HELP ectoledger_sessions_total Total audit sessions created.",
  "# TYPE ectoledger_sessions_total counter",
  "ectoledger_sessions_total 3",
  "# HELP ectoledger_events_total Total ledger events appended.",
  "# TYPE ectoledger_events_total counter",
  "ectoledger_events_total 128",
  "# HELP ectoledger_guard_denials_total Intents denied by the guard.",
  "# TYPE ectoledger_guard_denials_total counter",
  "ectoledger_guard_denials_total 4",
].join("\n");

const POLICY_TOML = `# Default audit policy (same format as audit_policy.example.toml)
name = "server_config_audit"
max_steps = 25

[[allowed_actions]]
action = "read_file"
path_pattern = "/etc/**"

[[allowed_actions]]
action = "run_command"
allowed_commands = ["ls", "cat", "grep", "ss"]

[[command_rules]]
program = "rm"
arg_pattern = "^-rf"
decision = "deny"
reason = "Block destructive operations"
`;

const TRIPWIRE_CONFIG = {
  allowed_paths: ["/etc", "/var/log", "/opt/app"],
  allowed_domains: ["example.com", "docs.example.com"],
  banned_command_patterns: ["rm\\s+-rf", "curl.*\\|\\s*sh", ":\\(\\)\\{.*\\};:"],
  min_justification_length: 20,
  require_https: true,
};

/** Default `check_tripwire` result: the "try a command" panel's happy path.
 * A `run_command` intent instead gets a plausible denial - see the
 * `check_tripwire` special case in `installTauriMock`'s `invoke`, which
 * matches the real `/api/tripwire/check` response shape (`TripwireCheckResponse`
 * in `crates/host/src/server/settings.rs`). */
const TRIPWIRE_CHECK_ALLOWED = {
  allowed: true,
  reason: null,
  rule: null,
  matched: null,
};

const TOKENS = [
  {
    token_hash: "d41d8cd98f00b204e9800998ecf8427e",
    role: "admin",
    label: "CI pipeline",
    created_at: T0,
    expires_at: null,
  },
  {
    token_hash: "5eb63bbbe01eeed093cb22bb8f5acdc3",
    role: "auditor",
    label: "Observer dashboard (read-only)",
    created_at: T0,
    expires_at: T0,
  },
];

const WEBHOOKS = [
  {
    id: "44444444-4444-4444-8444-444444444444",
    label: "Splunk HEC",
    url: "https://siem.example.com/services/collector",
    siem_format: "json",
    filter_kinds: ["guard_violation", "tripwire_triggered"],
    enabled: true,
    created_at: T0,
  },
  {
    id: "55555555-5555-4555-8555-555555555555",
    label: "QRadar",
    url: "https://qradar.example.com/ingest",
    siem_format: "leef",
    filter_kinds: [],
    enabled: false,
    created_at: T0,
  },
];

const SYSTEM_STATE = {
  os: "macos",
  arch: "aarch64",
  ram_gb: 24,
  ollama_running: true,
  ollama_installed: true,
  existing_db_path: null,
  recommended_model: "qwen2.5:1.5b",
};

const OLLAMA_MODELS = {
  models: [
    { name: "mistral:latest", size: 4113301824 },
    { name: "qwen2.5:0.5b", size: 397821312 },
    { name: "llama3.2:3b", size: 2019377664 },
  ],
};

/** Command name → fixed return value. */
export const FIXTURES: Record<string, unknown> = {
  server_url: "http://127.0.0.1:3000",
  dashboard_url: "http://127.0.0.1:3000",
  observer_token: "baseline-observer-token",
  is_demo_mode: false,
  check_setup_complete: true,
  detect_system_state: SYSTEM_STATE,
  get_config: CONFIG,
  // PUT /api/config answers with the merged config; the screens ignore it.
  save_config: CONFIG,
  save_policy: "200 OK",
  get_metrics: METRICS,
  get_prometheus_metrics: PROMETHEUS_METRICS,
  get_sessions: SESSIONS,
  get_session: SESSIONS[0],
  get_events: EVENTS,
  get_policies: ["default.toml", "strict.toml", "recon.toml"],
  get_policy_content: POLICY_TOML,
  get_tripwire_config: TRIPWIRE_CONFIG,
  check_tripwire: TRIPWIRE_CHECK_ALLOWED,
  get_tokens: TOKENS,
  get_webhooks: WEBHOOKS,
  get_ollama_models: OLLAMA_MODELS,
  // Settings reads the preset table from Rust and lists models through
  // one generic command, so the baseline needs both.
  get_provider_presets: [
    { id: "ollama", label: "Ollama", transport: "ollama-native", default_base_url: "http://127.0.0.1:11434", default_model: null, api_key_env: null, api_key_required: false },
    { id: "lmstudio", label: "LM Studio", transport: "openai-compatible", default_base_url: "http://127.0.0.1:1234/v1", default_model: null, api_key_env: "OPENAI_API_KEY", api_key_required: false },
    { id: "llamacpp", label: "llama.cpp server", transport: "openai-compatible", default_base_url: "http://127.0.0.1:8080/v1", default_model: null, api_key_env: "OPENAI_API_KEY", api_key_required: false },
    { id: "vllm", label: "vLLM", transport: "openai-compatible", default_base_url: "http://127.0.0.1:8000/v1", default_model: null, api_key_env: "OPENAI_API_KEY", api_key_required: false },
    { id: "mlx", label: "MLX-LM", transport: "openai-compatible", default_base_url: "http://127.0.0.1:8080/v1", default_model: null, api_key_env: "OPENAI_API_KEY", api_key_required: false },
    { id: "localai", label: "LocalAI", transport: "openai-compatible", default_base_url: null, default_model: null, api_key_env: "OPENAI_API_KEY", api_key_required: false },
    { id: "openai", label: "OpenAI", transport: "openai-compatible", default_base_url: "https://api.openai.com/v1", default_model: "gpt-6-astra", api_key_env: "OPENAI_API_KEY", api_key_required: true },
    { id: "anthropic", label: "Anthropic", transport: "anthropic", default_base_url: "https://api.anthropic.com", default_model: "claude-opus-5-5", api_key_env: "ANTHROPIC_API_KEY", api_key_required: true },
    { id: "gemini", label: "Google Gemini", transport: "openai-compatible", default_base_url: "https://generativelanguage.googleapis.com/v1beta/openai", default_model: "gemini-flash-latest", api_key_env: "GEMINI_API_KEY", api_key_required: true },
    { id: "azure-openai", label: "Azure OpenAI", transport: "openai-compatible", default_base_url: null, default_model: null, api_key_env: "AZURE_OPENAI_API_KEY", api_key_required: true },
    { id: "mistral", label: "Mistral AI", transport: "openai-compatible", default_base_url: "https://api.mistral.ai/v1", default_model: "mistral-large-latest", api_key_env: "MISTRAL_API_KEY", api_key_required: true },
    { id: "groq", label: "Groq", transport: "openai-compatible", default_base_url: "https://api.groq.com/openai/v1", default_model: "openai/gpt-oss-120b", api_key_env: "GROQ_API_KEY", api_key_required: true },
    { id: "openrouter", label: "OpenRouter", transport: "openai-compatible", default_base_url: "https://openrouter.ai/api/v1", default_model: "openrouter/auto", api_key_env: "OPENROUTER_API_KEY", api_key_required: true },
    { id: "deepseek", label: "DeepSeek", transport: "openai-compatible", default_base_url: "https://api.deepseek.com/v1", default_model: "deepseek-chat", api_key_env: "DEEPSEEK_API_KEY", api_key_required: true },
    { id: "xai", label: "xAI", transport: "openai-compatible", default_base_url: "https://api.x.ai/v1", default_model: null, api_key_env: "XAI_API_KEY", api_key_required: true },
    { id: "openai-compatible", label: "Custom (OpenAI-compatible)", transport: "openai-compatible", default_base_url: null, default_model: null, api_key_env: "OPENAI_API_KEY", api_key_required: false },
  ],
  set_window_theme: null,
  get_provider_models: ["mistral:latest", "qwen2.5:0.5b", "llama3.2:3b"],
  test_provider_connection: "Ollama is reachable - 3 models available.",
  // API keys live in the OS credential store; Settings only sees a status.
  api_key_status: { stored: false, environment: false, store: "the macOS Keychain" },
  set_api_key: { stored: true, environment: false, store: "the macOS Keychain" },
  delete_api_key: { stored: false, environment: false, store: "the macOS Keychain" },
  verify_session_chain: {
    ok: true,
    signatures: {
      verified: true,
      verdict: "verified",
      message: "all 6 event signatures verified",
      signed: 6,
      unsigned: 0,
    },
  },
  get_session_vc: {
    vc_jwt: "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtmclExZXhhbXBsZSJ9.c2lnbmF0dXJl",
    vc_payload: { issuer: "did:key:z6MkfrQ1example", type: ["VerifiableCredential"] },
  },
  // getVersion() in the sidebar goes through invoke as well.
  "plugin:app|version": "0.8.0",
};

export interface MockOptions {
  /** Overrides merged over {@link FIXTURES} - used to force the setup wizard. */
  overrides?: Record<string, unknown>;
  /** Shallow-merged into the get_config fixture. */
  config?: Record<string, unknown>;
}

/**
 * Install the Tauri mock and freeze anything that would make a screenshot
 * differ between two runs of identical code.
 */
export async function installTauriMock(
  page: Page,
  options: MockOptions = {}
): Promise<void> {
  const baseConfig = (FIXTURES.get_config ?? {}) as Record<string, unknown>;
  const fixtures: Record<string, unknown> = {
    ...FIXTURES,
    ...(options.overrides ?? {}),
    get_config: {
      ...baseConfig,
      ...((options.overrides?.get_config as Record<string, unknown> | undefined) ?? {}),
      ...(options.config ?? {}),
    },
  };

  await page.addInitScript((data: Record<string, unknown>) => {
    const win = window as unknown as Record<string, unknown>;

    // `isTauri()` in @tauri-apps/api v2 is `!!(globalThis || window).isTauri`.
    win.isTauri = true;

    let callbackId = 0;

    win.__TAURI_INTERNALS__ = {
      invoke: async (cmd: string, args?: Record<string, unknown>) => {
        // The event plugin is reached via invoke too; App.svelte tolerates a
        // rejection here, but returning a handle keeps the console quiet.
        if (cmd.startsWith("plugin:event|")) return 0;
        // check_tripwire's result depends on what was asked, unlike every
        // other mocked command - a run_command intent gets a plausible
        // denial, anything else the fixture's allowed result.
        if (cmd === "check_tripwire") {
          const intent = (args?.intent ?? {}) as Record<string, unknown>;
          if (intent.action === "run_command") {
            // Reuse the tripwire-config fixture's own banned list rather than
            // typing a pattern here, and echo the submitted command back the
            // way the real `TripwireError::BannedCommand` message does.
            const tripwireConfig = data.get_tripwire_config as {
              banned_command_patterns: string[];
            };
            const params = (intent.params ?? {}) as Record<string, unknown>;
            return {
              allowed: false,
              reason: `banned command: ${String(params.command ?? "")}`,
              rule: "banned_command_patterns",
              matched: tripwireConfig.banned_command_patterns[0],
            };
          }
          return data[cmd];
        }
        if (cmd in data) return data[cmd];
        // Unknown command: reject the way a real missing command would, so a
        // screen's error path is exercised honestly rather than papered over.
        throw new Error(`command ${cmd} not mocked`);
      },
      transformCallback: (callback: unknown) => {
        const id = ++callbackId;
        win[`_${id}`] = callback;
        return id;
      },
    };

    // LiveDashboard opens an SSE stream. A real EventSource against a dead
    // origin retries on a timer, which makes the screen non-deterministic.
    class InertEventSource {
      static readonly CONNECTING = 0;
      static readonly OPEN = 1;
      static readonly CLOSED = 2;
      readonly readyState = 0;
      onopen: unknown = null;
      onmessage: unknown = null;
      onerror: unknown = null;
      addEventListener() {}
      removeEventListener() {}
      close() {}
    }
    win.EventSource = InertEventSource;

    // Kill animation and caret timing. Without this, a spinner or a focused
    // input can land mid-frame and diff against an otherwise identical run.
    // This runs before the app boots, so it is appended as soon as <head>
    // exists rather than via addStyleTag, which needs an already-loaded page.
    const injectStillnessCss = () => {
      const style = document.createElement("style");
      style.textContent = `
        *, *::before, *::after {
          animation-duration: 0s !important;
          animation-delay: 0s !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0s !important;
          transition-delay: 0s !important;
          caret-color: transparent !important;
        }
        html { scroll-behavior: auto !important; }
      `;
      document.head.appendChild(style);
    };
    if (document.head) {
      injectStillnessCss();
    } else {
      document.addEventListener("DOMContentLoaded", injectStillnessCss, {
        once: true,
      });
    }
  }, fixtures);
}
