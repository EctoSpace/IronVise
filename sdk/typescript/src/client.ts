import type {
  IntentVerdict,
  AppendResult,
  ApprovalDecision,
  ChatResponse,
  ChatStreamEvent,
  ComplianceBundle,
  ConfigResponse,
  ConfigUpdate,
  CreateSessionOptions,
  CreateTokenRequest,
  CreateTokenResponse,
  IronViseClientOptions,
  LedgerEvent,
  ListSessionsOptions,
  MetricsSummary,
  PendingApproval,
  SecurityMetrics,
  Session,
  StatusResponse,
  StreamEvent,
  StreamOptions,
  TokenListRow,
  TripwireCheckRequest,
  TripwireCheckResponse,
  TripwireConfig,
  TripwireConfigUpdate,
  ToggleWebhookBody,
  UpsertWebhookRequest,
  VerifySessionResult,
  WebhookListRow,
} from "./models.js";

const ERROR_EXCERPT_CHARS = 300;

const excerpt = (text: string): string => {
  if (text.length <= ERROR_EXCERPT_CHARS) return text;
  let end = ERROR_EXCERPT_CHARS;
  // Ending on a high surrogate would leave half a code point in the message.
  const last = text.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return `${text.slice(0, end)}…`;
};

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRIES = 2;
const RETRY_BASE_MS = 250;
const RETRY_MAX_MS = 4_000;
const RETRIABLE_STATUSES = new Set([502, 503, 504]);

/** Milliseconds to wait before retry number `retryIndex` (0-based).
 *  Honours a `Retry-After` header, in seconds, when present and valid;
 *  otherwise backs off exponentially from `RETRY_BASE_MS`. Both are capped
 *  at `RETRY_MAX_MS`. */
const retryDelayMs = (retryIndex: number, retryAfterHeader?: string | null): number => {
  if (retryAfterHeader) {
    const seconds = Number(retryAfterHeader);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, RETRY_MAX_MS);
  }
  return Math.min(RETRY_BASE_MS * 2 ** retryIndex, RETRY_MAX_MS);
};

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** How a method reads a 2xx response body. */
type ReadMode = "json" | "text" | "blob" | "textJson" | "none";

const readBody = async <T>(res: Response, mode: ReadMode): Promise<T> => {
  switch (mode) {
    case "json":
      return (await res.json()) as T;
    case "text":
      return (await res.text()) as unknown as T;
    case "blob":
      return (await res.blob()) as unknown as T;
    case "textJson": {
      // Some PUT endpoints return 200 with no JSON body.
      const text = await res.text();
      return (text ? JSON.parse(text) : undefined) as T;
    }
    case "none":
      return undefined as T;
  }
};

/**
 * Typed error thrown when the server returns a non-2xx status. `body` is the
 * whole response text; the message carries its first 300 characters.
 */
export class IronViseApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    method: string,
    url: string,
  ) {
    super(`IronVise API ${method} ${url} → ${status}: ${excerpt(body)}`);
    this.name = "IronViseApiError";
  }
}

/**
 * Typed error thrown, before any request is sent, when a method is called with
 * an argument the client cannot turn into a valid request: an id or name of
 * `""`, `"."` or `".."`, which would otherwise address a different resource
 * once the URL is parsed.
 */
export class IronViseUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IronViseUsageError";
  }
}

/** Encodes `id` as exactly one URL path segment, rejecting ids that cannot be one. */
const segment = (id: string): string => {
  // encodeURIComponent leaves dots alone and URL parsing resolves "." and ".."
  // segments, so these ids would escape into the parent path.
  if (id === "" || id === "." || id === "..") {
    throw new IronViseUsageError(
      `IronVise id ${JSON.stringify(id)} cannot be used as a URL path segment`,
    );
  }
  return encodeURIComponent(id);
};

/**
 * REST client for IronVise.
 *
 * @example
 * ```ts
 * const client = new IronViseClient({ baseUrl: "http://localhost:3000" });
 * const sessions = await client.listSessions();
 * ```
 *
 * @remarks
 * The `baseUrl` option defaults to `http://localhost:3000`, which is suitable
 * for local development only.  In containerised or remote environments you
 * **must** supply the correct service URL:
 * ```ts
 * const client = new IronViseClient({
 *   baseUrl: "http://ironvise-host:3000",
 *   bearerToken: process.env.OBSERVER_TOKEN,
 * });
 * ```
 * Omitting `baseUrl` in Docker Compose / Kubernetes will cause every request
 * to fail with a connection-refused error against the loopback address inside
 * the calling container.
 *
 * `timeoutMs` (default 30,000) bounds every non-streaming request, per
 * attempt. `retries` (default 2) applies only to GET requests, which are
 * idempotent: a network error or an HTTP 502/503/504 is retried with
 * exponential backoff (250 ms, 500 ms, …, capped at 4 s), honouring a
 * `Retry-After` header in seconds when the server sends one (also capped at
 * 4 s). POST/PUT/DELETE are never retried, and neither is a timeout or any
 * 4xx - those reach the caller immediately. Streaming methods
 * (`streamEvents`, `askStream`, `chatStream`) are not retried either.
 */
export class IronViseClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;
  private readonly retries: number;

  constructor({
    baseUrl = "http://localhost:3000",
    bearerToken,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    retries = DEFAULT_RETRIES,
  }: IronViseClientOptions = {}) {
    if (!Number.isSafeInteger(retries) || retries < 0) {
      throw new RangeError(`retries must be a non-negative safe integer, got ${retries}`);
    }
    // Node clamps overflowing timer delays to 1 ms rather than waiting longer.
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) {
      throw new RangeError(`timeoutMs must be positive and at most 2147483647, got ${timeoutMs}`);
    }
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.headers = { "Content-Type": "application/json" };
    if (bearerToken) {
      this.headers["Authorization"] = `Bearer ${bearerToken}`;
    }
    this.timeoutMs = timeoutMs;
    this.retries = retries;
  }

  async listSessions(opts?: number | ListSessionsOptions): Promise<Session[]> {
    const params = new URLSearchParams();
    if (typeof opts === "number") {
      params.set("limit", String(opts));
    } else if (opts) {
      if (opts.limit !== undefined) params.set("limit", String(opts.limit));
      if (opts.offset !== undefined) params.set("offset", String(opts.offset));
      if (opts.status !== undefined) params.set("status", opts.status);
    } else {
      params.set("limit", "50");
    }
    return this.get<Session[]>(`/api/sessions?${params.toString()}`);
  }

  async createSession(opts: CreateSessionOptions): Promise<Session> {
    const { record, ...rest } = opts;
    return this.post<Session>("/api/sessions", record ? { ...rest, record: true } : rest);
  }

  async getSessionById(sessionId: string): Promise<Session> {
    return this.get<Session>(`/api/sessions/${segment(sessionId)}`);
  }

  async sealSession(sessionId: string): Promise<void> {
    await this.post<unknown>(`/api/sessions/${segment(sessionId)}/seal`, {});
  }

  async getEvents(sessionId: string): Promise<LedgerEvent[]> {
    return this.get<LedgerEvent[]>(`/api/events?session_id=${encodeURIComponent(sessionId)}`);
  }

  async appendEvent(sessionId: string, payload: Record<string, unknown>): Promise<AppendResult> {
    return this.post<AppendResult>(`/api/sessions/${segment(sessionId)}/events`, payload);
  }

  /**
   * Ask whether an action would be permitted - **before** performing it.
   *
   * Nothing is executed and nothing is written to the ledger by asking. The
   * verdict is only worth anything if the caller honours it:
   *
   * ```ts
   * const verdict = await client.verifyIntent(sid, {
   *   action: "run_command",
   *   params: { command: cmd },
   *   justification: "…",
   * });
   * assertAllowed(verdict);
   * ```
   */
  async verifyIntent(
    sessionId: string,
    intent: {
      action: string;
      params?: Record<string, unknown>;
      justification?: string;
      reasoning?: string;
    },
  ): Promise<IntentVerdict> {
    return this.post<IntentVerdict>(
      `/api/sessions/${segment(sessionId)}/verify-intent`,
      {
        action: intent.action,
        params: intent.params ?? {},
        justification: intent.justification ?? "",
        reasoning: intent.reasoning ?? "",
      },
    );
  }

  /** Chain intact and every signature verified. */
  async verifyChain(sessionId: string): Promise<boolean> {
    const { ok, signatures } = await this.verifySession(sessionId);
    return ok === true && (!signatures || signatures.verified === true);
  }

  /** The full verdict: the hash chain (`ok`) and, separately, the signatures. */
  async verifySession(sessionId: string): Promise<VerifySessionResult> {
    return this.get<VerifySessionResult>(`/api/sessions/${segment(sessionId)}/verify`);
  }

  async proveCompliance(sessionId: string): Promise<ComplianceBundle> {
    return this.get<ComplianceBundle>(`/api/sessions/${segment(sessionId)}/compliance`);
  }

  async exportCertificate(sessionId: string): Promise<Blob> {
    return this.request<Blob>("GET", `/api/certificates/${segment(sessionId)}`, { read: "blob" });
  }

  async getReport(sessionId: string): Promise<Record<string, unknown>> {
    return this.get<Record<string, unknown>>(`/api/reports/${segment(sessionId)}`);
  }

  async getSessionVc(sessionId: string): Promise<Record<string, unknown>> {
    return this.get<Record<string, unknown>>(`/api/sessions/${segment(sessionId)}/vc`);
  }

  /**
   * @param audience The verifier's own identifier, checked against the VC's
   * `aud` claim when given. Sent as `?audience=`.
   */
  async verifySessionVc(sessionId: string, audience?: string): Promise<Record<string, unknown>> {
    const qs = audience !== undefined ? `?audience=${encodeURIComponent(audience)}` : "";
    return this.get<Record<string, unknown>>(
      `/api/sessions/${segment(sessionId)}/vc/verify${qs}`,
    );
  }

  async getMetrics(): Promise<MetricsSummary> {
    return this.get<MetricsSummary>("/api/metrics");
  }

  async getSecurityMetrics(): Promise<SecurityMetrics> {
    return this.get<SecurityMetrics>("/api/metrics/security");
  }

  async getPrometheusMetrics(): Promise<string> {
    return this.request<string>("GET", "/metrics", { read: "text" });
  }

  async listPolicies(): Promise<string[]> {
    return this.get<string[]>("/api/policies");
  }

  async getPolicy(name: string): Promise<string> {
    return this.request<string>("GET", `/api/policies/${segment(name)}`, { read: "text" });
  }

  async savePolicy(name: string, content: string): Promise<void> {
    await this.request<void>("PUT", `/api/policies/${segment(name)}`, {
      rawBody: content,
      contentType: "text/plain",
    });
  }

  async deletePolicy(name: string): Promise<void> {
    await this.request<void>("DELETE", `/api/policies/${segment(name)}`);
  }

  async getPendingApproval(sessionId: string): Promise<PendingApproval | null> {
    const data = await this.get<{ pending: PendingApproval | null }>(
      `/api/approvals/${segment(sessionId)}/pending`,
    );
    return data.pending;
  }

  async postApprovalDecision(
    sessionId: string,
    decision: ApprovalDecision,
  ): Promise<Record<string, unknown>> {
    return this.post<Record<string, unknown>>(`/api/approvals/${segment(sessionId)}`, decision);
  }

  // Public: no auth required.
  async getStatus(): Promise<StatusResponse> {
    return this.get<StatusResponse>("/api/status");
  }

  /** Chat within a session; both messages are recorded in its ledger. */
  async chat(sessionId: string, message: string): Promise<ChatResponse> {
    return this.post<ChatResponse>(`/api/sessions/${segment(sessionId)}/chat`, { message });
  }

  /** `chat`, with the reply streamed as the model generates it. */
  chatStream(
    sessionId: string,
    message: string,
    opts?: { signal?: AbortSignal },
  ): AsyncGenerator<ChatStreamEvent, void, undefined> {
    return this.streamChat(`/api/sessions/${segment(sessionId)}/chat/stream`, message, opts?.signal);
  }

  /** Ask the configured model directly, outside any session. The exchange is
   *  still recorded in the ledger; no guard or tripwire applies. */
  async ask(message: string): Promise<ChatResponse> {
    return this.post<ChatResponse>("/api/chat", { message });
  }

  /** `ask`, with the reply streamed as the model generates it. */
  askStream(
    message: string,
    opts?: { signal?: AbortSignal },
  ): AsyncGenerator<ChatStreamEvent, void, undefined> {
    return this.streamChat("/api/chat/stream", message, opts?.signal);
  }

  private async *streamChat(
    path: string,
    message: string,
    signal?: AbortSignal,
  ): AsyncGenerator<ChatStreamEvent, void, undefined> {
    const url = `${this.baseUrl}${path}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { ...this.headers, Accept: "text/event-stream" },
      body: JSON.stringify({ message }),
      signal,
    });
    if (!res.ok) {
      throw new IronViseApiError(res.status, await res.text(), "POST", url);
    }
    for await (const { event, data } of sse(res)) {
      const body = JSON.parse(data) as Record<string, unknown>;
      if (event === "delta") yield { type: "delta", text: String(body.text ?? "") };
      else if (event === "done") yield { type: "done", ...(body as unknown as ChatResponse) };
      else if (event === "error") {
        throw new IronViseApiError(502, JSON.stringify(body), "POST", url);
      }
    }
  }

  // Admin only.
  async getConfig(): Promise<ConfigResponse> {
    return this.get<ConfigResponse>("/api/config");
  }

  async updateConfig(updates: ConfigUpdate): Promise<ConfigResponse> {
    return this.put<ConfigResponse>("/api/config", updates);
  }

  // Admin only.
  async resetDemo(): Promise<Record<string, unknown>> {
    return this.post<Record<string, unknown>>("/api/admin/reset-demo", {});
  }

  async getTripwireConfig(): Promise<TripwireConfig> {
    return this.get<TripwireConfig>("/api/tripwire");
  }

  async updateTripwireConfig(config: TripwireConfigUpdate): Promise<TripwireConfig> {
    return this.put<TripwireConfig>("/api/tripwire", config);
  }

  /**
   * Ask whether an action would pass the tripwire - **without recording
   * anything**: no session, no ledger event. Runs only the allowlists and
   * banned patterns from `getTripwireConfig()`, not the policy engine or the
   * semantic guard; use `verifyIntent` for the full pipeline against a
   * session.
   */
  async checkTripwire(req: TripwireCheckRequest): Promise<TripwireCheckResponse> {
    const body: Record<string, unknown> = { action: req.action, params: req.params ?? {} };
    if (req.justification !== undefined) body.justification = req.justification;
    return this.post<TripwireCheckResponse>("/api/tripwire/check", body);
  }

  // Admin only.
  async listTokens(): Promise<TokenListRow[]> {
    return this.get<TokenListRow[]>("/api/tokens");
  }

  async createToken(request: CreateTokenRequest): Promise<CreateTokenResponse> {
    return this.post<CreateTokenResponse>("/api/tokens", request);
  }

  async deleteToken(tokenHash: string): Promise<void> {
    await this.del(`/api/tokens/${segment(tokenHash)}`);
  }

  // Admin only.
  async listWebhooks(): Promise<WebhookListRow[]> {
    return this.get<WebhookListRow[]>("/api/webhooks");
  }

  async createWebhook(request: UpsertWebhookRequest): Promise<WebhookListRow> {
    return this.post<WebhookListRow>("/api/webhooks", request);
  }

  async deleteWebhook(webhookId: string): Promise<void> {
    await this.del(`/api/webhooks/${segment(webhookId)}`);
  }

  async toggleWebhook(webhookId: string, enabled: boolean): Promise<void> {
    await this.put<unknown>(`/api/webhooks/${segment(webhookId)}`, {
      enabled,
    } satisfies ToggleWebhookBody);
  }

  async *streamEvents(opts?: StreamOptions): AsyncGenerator<StreamEvent, void, undefined> {
    const params = new URLSearchParams();
    if (opts?.after !== undefined) params.set("after", String(opts.after));
    if (opts?.since !== undefined) params.set("since", String(opts.since));
    if (opts?.session_id) params.set("session_id", opts.session_id);
    const qs = params.toString();
    const url = `${this.baseUrl}/api/stream${qs ? `?${qs}` : ""}`;
    const res = await fetch(url, {
      headers: { ...this.headers, Accept: "text/event-stream" },
      signal: opts?.signal,
    });
    if (!res.ok) {
      throw new IronViseApiError(res.status, await res.text(), "GET", url);
    }
    for await (const { data } of sse(res)) {
      try {
        yield JSON.parse(data) as StreamEvent;
      } catch {
        // skip malformed events
      }
    }
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path, { read: "json" });
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, { body, read: "json" });
  }

  private async put<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("PUT", path, { body, read: "textJson" });
  }

  private async del(path: string): Promise<void> {
    await this.request<void>("DELETE", path);
  }

  /**
   * Every non-streaming request: builds the URL, applies `timeoutMs` per
   * attempt, retries a GET per the class doc comment, and reads the 2xx body
   * as `read` says. Throws `IronViseApiError` for a non-2xx response that
   * is not retried (or whose retries are exhausted).
   */
  private async request<T>(
    method: "GET" | "POST" | "PUT" | "DELETE",
    path: string,
    opts: { body?: unknown; rawBody?: string; contentType?: string; read?: ReadMode } = {},
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const isGet = method === "GET";
    const maxAttempts = isGet ? this.retries + 1 : 1;
    const headers = opts.contentType ? { ...this.headers, "Content-Type": opts.contentType } : this.headers;
    const body =
      opts.rawBody !== undefined ? opts.rawBody : opts.body !== undefined ? JSON.stringify(opts.body) : undefined;

    for (let attempt = 1; ; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await fetch(url, { method, headers, body, signal: controller.signal });
        if (!res.ok) {
          const text = await res.text();
          if (isGet && attempt < maxAttempts && RETRIABLE_STATUSES.has(res.status)) {
            await sleep(retryDelayMs(attempt - 1, res.headers.get("retry-after")));
            continue;
          }
          throw new IronViseApiError(res.status, text, method, url);
        }
        return await readBody<T>(res, opts.read ?? "none");
      } catch (err) {
        if (err instanceof IronViseApiError) throw err;
        if (isGet && attempt < maxAttempts && err instanceof TypeError && !controller.signal.aborted) {
          await sleep(retryDelayMs(attempt - 1));
          continue;
        }
        throw err;
      } finally {
        clearTimeout(timeout);
      }
    }
  }
}

/** The `event` name and `data` of each server-sent event in `res`'s body.
 *  Keep-alives and events without data are skipped. */
async function* sse(res: Response): AsyncGenerator<{ event: string; data: string }, void, undefined> {
  if (!res.body) return;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let line = "";
  let skipLF = false;
  let event = "message";
  let data: string[] = [];
  const consumeLine = (value: string): { event: string; data: string } | null => {
    if (value === "") {
      const frame = data.length ? { event: event || "message", data: data.join("\n") } : null;
      event = "message";
      data = [];
      return frame;
    }
    const colon = value.indexOf(":");
    const field = colon < 0 ? value : value.slice(0, colon);
    let content = colon < 0 ? "" : value.slice(colon + 1);
    if (content.startsWith(" ")) content = content.slice(1);
    if (field === "event") event = content;
    else if (field === "data") data.push(content);
    return null;
  };
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      // CR, LF and CRLF all terminate a line, even across byte chunks.
      for (const char of decoder.decode(value, { stream: true })) {
        if (skipLF) {
          skipLF = false;
          if (char === "\n") continue;
        }
        if (char === "\r" || char === "\n") {
          skipLF = char === "\r";
          const frame = consumeLine(line);
          line = "";
          if (frame) yield frame;
        } else line += char;
      }
    }
  } finally {
    // Releasing a lock alone leaves a live SSE HTTP request running when a
    // caller breaks out of for-await or a frame handler throws.
    try { await reader.cancel(); } catch { /* preserve the original stream error */ }
    reader.releaseLock();
  }
}
