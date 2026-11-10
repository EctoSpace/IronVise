/** Shared types mirroring the IronVise API response shapes. */

export interface Session {
  id: string;
  goal: string;
  goal_hash: string | null;
  status: string;
  llm_backend: string | null;
  llm_model: string | null;
  created_at: string;
  finished_at: string | null;
  policy_hash: string | null;
  session_public_key: string | null;
  session_did: string | null;
  enclave_attestation_json: string | null;
}

/**
 * No `policy_hash` or `session_did`: the server never accepted either on
 * session creation. It records the hash of the policy the run actually used
 * (or none, decided server-side) and sets `session_did` itself once the
 * session key exists - both are read-only fields on `Session`.
 */
export interface CreateSessionOptions {
  goal: string;
  /**
   * Create a recorder session: no audit loop and no server-side LLM, and the
   * session stays `running` for appends until it is sealed. Use it for any
   * session you append to yourself.
   */
  record?: boolean;
}

export interface ListSessionsOptions {
  limit?: number;
  offset?: number;
  status?: string;
}

/**
 * One row of `GET /api/events`. The server returns no per-event signature or
 * public key; `verifySession` reports the signatures.
 */
export interface LedgerEvent {
  id: number;
  sequence: number;
  previous_hash: string;
  content_hash: string;
  payload: unknown;
  created_at: string;
}

export interface AppendResult {
  id: number;
  payload_hash: string;
  sequence: number;
}

export interface SignatureVerdict {
  verified: boolean;
  verdict: string;
  message: string;
  signed: number;
  unsigned: number;
}

export interface VerifySessionResult {
  /** The hash chain alone. */
  ok: boolean;
  /** Absent on servers that predate signature verification. */
  signatures?: SignatureVerdict;
}

/**
 * The event count and each event's sequence and content hash, nothing more:
 * `verifySession` is what checks the chain and the signatures.
 */
export interface ComplianceBundle {
  session_id: string;
  event_count: number;
  events: Array<{ sequence: number; content_hash: string }>;
}

export interface MetricsSummary {
  total_sessions: number;
  total_events: number;
  [key: string]: unknown;
}

export interface SecurityMetrics {
  injection_attempts_detected_7d: number;
  injection_attempts_by_layer: Record<string, number>;
  sessions_aborted_circuit_breaker: number;
  chain_verification_failures: number;
  /** Added in 0.8.0: ledger row counts. Older servers omit them. */
  total_sessions?: number;
  total_events?: number;
  /** Added in 0.8.0: this server's denial counters since it started. */
  guard_denials?: number;
  tripwire_rejections?: number;
}

export interface PendingApproval {
  gate_id: string;
  action_name: string;
  action_params_summary: string;
  created_at: string;
}

export interface ApprovalDecision {
  gate_id: string;
  approved: boolean;
  reason?: string;
}

export interface IronViseClientOptions {
  baseUrl?: string;
  bearerToken?: string;
  /** Bounds each non-streaming attempt. Positive, finite, at most 2147483647 ms. Default `30_000`. */
  timeoutMs?: number;
  /**
   * Retries for GET requests only, on a network error or an HTTP
   * 502/503/504, with exponential backoff honouring `Retry-After`.
   * POST/PUT/DELETE and streaming methods are never retried. Default `2`.
   * Must be a non-negative safe integer.
   */
  retries?: number;
}

export interface StatusResponse {
  demo_mode: boolean;
  /** True when the server would log the insecure-demo banner. Added in 0.8.0; absent from older servers. */
  insecure_demo?: boolean;
  version: string;
  /** Live pool backend: `"postgres"` or `"sqlite"`. Added in 0.8.0; absent from older servers. */
  ledger_backend?: string;
  /** Cognitive loop (Home → Run) works on this live pool. Added in 0.8.0; absent from older servers. */
  agent_supported?: boolean;
  /** Certificate / report export works on this live pool. Added in 0.8.0; absent from older servers. */
  exports_supported?: boolean;
  /** Webhook egress worker is delivering events. Added in 0.8.0; absent from older servers. */
  webhooks_live?: boolean;
}

export interface ChatResponse {
  reply: string;
  backend: string;
  model: string;
}

/** One event of a streamed chat reply: the text as it is generated, then the
 *  whole reply once the ledger has recorded it. A failure is thrown as an
 *  `IronViseApiError`. Added in 0.8.0. */
export type ChatStreamEvent =
  | { type: "delta"; text: string }
  | ({ type: "done" } & ChatResponse);

export interface ConfigResponse {
  database_url: string;
  llm_backend: string;
  ollama_base_url: string;
  /** Added in 0.8.0; absent from older servers. */
  openai_base_url?: string;
  ollama_model: string;
  guard_required: boolean;
  /**
   * What decided `guard_required`: the environment, the settings file, both,
   * or the stricter of two that disagreed. Added in 0.8.0; absent from older
   * servers.
   */
  guard_required_source?: string;
  guard_llm_backend: string | null;
  guard_llm_model: string | null;
  max_steps: number;
  agent_allowed_domains: string[];
  sandbox_mode: string;
  demo_mode: boolean;
  /**
   * Desktop GUI: show Testing / Prometheus / Dev Hub in the sidebar. Added in
   * 0.8.0; absent from older servers.
   */
  show_developer_tools?: boolean;
  /** Live pool backend: `"postgres"` or `"sqlite"`. Added in 0.8.0; absent from older servers. */
  ledger_backend?: string;
  /** Cognitive loop (Home → Run) works on this live pool. Added in 0.8.0; absent from older servers. */
  agent_supported?: boolean;
  /** Certificate / report export works on this live pool. Added in 0.8.0; absent from older servers. */
  exports_supported?: boolean;
  /** Webhook egress worker is delivering events. Added in 0.8.0; absent from older servers. */
  webhooks_live?: boolean;
  /**
   * The policy chosen in Settings for Home → Run, by name, or `null` when
   * none is chosen. Added in 0.8.0; absent from older servers.
   */
  active_policy?: string | null;
  /**
   * `ECTO_POLICY_PATH` when set: it wins over `active_policy`, and the GUI
   * shows it instead of offering a choice. Added in 0.8.0; absent from older
   * servers.
   */
  policy_from_environment?: string | null;
}

/**
 * A text field below (`database_url`, `ollama_base_url`, `openai_base_url`,
 * `ollama_model`, `guard_llm_backend`, `guard_llm_model`, `active_policy`):
 * omit to keep the stored value, send `""` to clear it back to the
 * environment or built-in default, anything else to replace it. `active_policy`
 * is additionally validated - a name that fails to load is rejected with a
 * 422 rather than silently kept.
 */
export interface ConfigUpdate {
  database_url?: string;
  llm_backend?: string;
  ollama_base_url?: string;
  openai_base_url?: string;
  ollama_model?: string;
  guard_required?: boolean;
  guard_llm_backend?: string;
  guard_llm_model?: string;
  max_steps?: number;
  agent_allowed_domains?: string[];
  /** Desktop GUI: show Testing / Prometheus / Dev Hub in the sidebar. */
  show_developer_tools?: boolean;
  /** The policy to use for new runs, by name. `""` clears it; a name that does not load returns 422. */
  active_policy?: string;
}

export interface TripwireConfig {
  allowed_paths: string[];
  allowed_domains: string[];
  banned_command_patterns: string[];
  min_justification_length: number;
  require_https: boolean;
  /**
   * MCP tools a call may use, as `server/tool` or `server/*`. Empty: any.
   * Added in 0.8.0; absent from older servers.
   */
  allowed_mcp_tools?: string[];
  /**
   * `GET /api/tripwire` only: whether a `tripwire.json` has been saved, or
   * this is just the default view. Added in 0.8.0; absent from older
   * servers and never sent on `PUT`.
   */
  saved?: boolean;
}

export interface TripwireConfigUpdate {
  allowed_paths: string[];
  allowed_domains: string[];
  banned_command_patterns: string[];
  min_justification_length?: number;
  require_https?: boolean;
  /** Absent keeps the saved list: the desktop app does not edit it. */
  allowed_mcp_tools?: string[];
}

/**
 * `POST /api/tripwire/check` - ask whether a proposed action would pass the
 * tripwire, without recording anything: no session, no ledger event. Runs
 * only the tripwire layer (allowlists and banned patterns), not the policy
 * engine or the semantic guard - see `verifyIntent` for the full pipeline.
 */
export interface TripwireCheckRequest {
  action: string;
  params?: Record<string, unknown>;
  /** Server supplies a default when omitted; send your own for a real check. */
  justification?: string;
}

export interface TripwireCheckResponse {
  allowed: boolean;
  reason: string | null;
  /** Which setting would refuse it, e.g. `allowed_paths`, `banned_command_patterns`. */
  rule: string | null;
  /** The configured list item that decided the denial, when `allowed` is `false`. */
  matched: string | null;
}

export interface TokenListRow {
  token_hash: string;
  role: string;
  label?: string;
  created_at: string;
  expires_at?: string;
}

export interface CreateTokenRequest {
  label?: string;
  role: string;
  expires_in_days?: number;
}

export interface CreateTokenResponse {
  token: string;
  token_hash: string;
  role: string;
  label?: string;
}

export interface WebhookListRow {
  id: string;
  label: string;
  url: string;
  siem_format: string;
  filter_kinds: string[];
  enabled: boolean;
  created_at: string;
}

export interface UpsertWebhookRequest {
  label: string;
  url: string;
  bearer_token?: string;
  siem_format?: string;
  filter_kinds?: string[];
  enabled?: boolean;
}

export interface ToggleWebhookBody {
  enabled: boolean;
}

export interface StreamEvent {
  id: number;
  sequence: number;
  previous_hash: string;
  content_hash: string;
  payload: unknown | null;
  created_at: string;
}

export interface StreamOptions {
  after?: number;
  since?: number;
  session_id?: string;
  signal?: AbortSignal;
}

/**
 * The answer to "may I do this?", returned before the caller acts.
 *
 * `verifyIntent` is what separates an SDK that records what an agent did from
 * one that can stop it. The decision is made server-side by the same
 * policy → tripwire → guard pipeline the cognitive loop uses. Nothing is
 * executed and nothing is committed to the ledger by asking.
 */
export interface IntentCoverage {
  /** Layers consulted, in pipeline order: `policy`, `tripwire`, `guard`. */
  evaluated: string[];
  /** Layers not consulted on this surface. */
  skipped: string[];
  /** SHA-256 of the policy file that decided, when a policy was evaluated. */
  policy_hash?: string;
}

export interface IntentVerdict {
  decision: "allow" | "deny";
  reason?: string;
  /** Which check refused: policy, tripwire, guard, guard_unavailable. */
  stage?: string;
  session_id?: string;
  /**
   * Which checks ran, and which did not.
   *
   * An `allow` from a surface with no policy and no guard is a weaker
   * statement than one from a surface with both. `guard` is evaluated only
   * when the server requires a guard; otherwise it is in `skipped`. Absent
   * when talking to a server older than 0.8.0.
   */
  coverage?: IntentCoverage;
  /** Always `false` here: asking writes nothing to the ledger. */
  recorded?: boolean;
}

/** Thrown by `assertAllowed` when an action was refused. */
export class IntentDeniedError extends Error {
  constructor(public readonly verdict: IntentVerdict) {
    const stage = verdict.stage ? ` at the ${verdict.stage} stage` : "";
    super(`IronVise denied this action${stage}: ${verdict.reason ?? "no reason given"}`);
    this.name = "IntentDeniedError";
  }
}

/**
 * Throw unless the action was allowed.
 *
 * For callers who would rather not remember to check a boolean - an ignored
 * return value is the most common way a governance call quietly becomes a
 * logging call.
 */
export function assertAllowed(verdict: IntentVerdict): void {
  if (verdict.decision !== "allow") throw new IntentDeniedError(verdict);
}
