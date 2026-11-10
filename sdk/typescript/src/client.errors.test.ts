/**
 * IronViseClient - failure paths, for every public method.
 *
 * One table describes each method once (HTTP verb, path, how it reads a 2xx
 * body); every failure scenario then runs against the whole table. A guard test
 * fails if a public method is added to the client without a row here, so new
 * methods cannot silently skip this suite.
 *
 * `fetch` is stubbed and timers are faked; nothing touches the network.
 *
 * GET is the one verb retried (default 2 retries, see `client.retries.test.ts`
 * for the dedicated suite): the non-2xx and transport-failure cases below
 * expect a retriable GET to hit `fetch` `1 + DEFAULT_RETRIES` times, and every
 * other case - a non-GET, or a non-retriable status/error - exactly once.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { IronViseApiError, IronViseClient } from "./client.js";

const BASE_URL = "http://localhost:3000";
const SID = "550e8400-e29b-41d4-a716-446655440000";
const TIMEOUT_MS = 30_000;
const DEFAULT_RETRIES = 2;
const RETRIABLE_STATUSES = new Set([502, 503, 504]);

/**
 * How a method treats a 2xx body:
 *  - `json`   `res.json()` (the private `get` / `post` helpers)
 *  - `put`    `res.text()`, then `JSON.parse` unless empty (the `put` helper)
 *  - `text`   returns `res.text()` as is
 *  - `blob`   returns `res.blob()`
 *  - `none`   never reads the body
 *  - `stream` Server-Sent Events, consumed through the async generator
 */
type BodyKind = "json" | "put" | "text" | "blob" | "none" | "stream";

interface MethodCase {
  name: string;
  verb: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  kind: BodyKind;
  call: (c: IronViseClient) => Promise<unknown>;
}

const METHODS: MethodCase[] = [
  { name: "listSessions", verb: "GET", path: "/api/sessions?limit=50", kind: "json", call: (c) => c.listSessions() },
  { name: "createSession", verb: "POST", path: "/api/sessions", kind: "json", call: (c) => c.createSession({ goal: "g" }) },
  { name: "getSessionById", verb: "GET", path: `/api/sessions/${SID}`, kind: "json", call: (c) => c.getSessionById(SID) },
  { name: "sealSession", verb: "POST", path: `/api/sessions/${SID}/seal`, kind: "json", call: (c) => c.sealSession(SID) },
  { name: "getEvents", verb: "GET", path: `/api/events?session_id=${SID}`, kind: "json", call: (c) => c.getEvents(SID) },
  { name: "appendEvent", verb: "POST", path: `/api/sessions/${SID}/events`, kind: "json", call: (c) => c.appendEvent(SID, { step: 1 }) },
  { name: "verifyIntent", verb: "POST", path: `/api/sessions/${SID}/verify-intent`, kind: "json", call: (c) => c.verifyIntent(SID, { action: "read_file" }) },
  { name: "verifyChain", verb: "GET", path: `/api/sessions/${SID}/verify`, kind: "json", call: (c) => c.verifyChain(SID) },
  { name: "verifySession", verb: "GET", path: `/api/sessions/${SID}/verify`, kind: "json", call: (c) => c.verifySession(SID) },
  { name: "proveCompliance", verb: "GET", path: `/api/sessions/${SID}/compliance`, kind: "json", call: (c) => c.proveCompliance(SID) },
  { name: "exportCertificate", verb: "GET", path: `/api/certificates/${SID}`, kind: "blob", call: (c) => c.exportCertificate(SID) },
  { name: "getReport", verb: "GET", path: `/api/reports/${SID}`, kind: "json", call: (c) => c.getReport(SID) },
  { name: "getSessionVc", verb: "GET", path: `/api/sessions/${SID}/vc`, kind: "json", call: (c) => c.getSessionVc(SID) },
  { name: "verifySessionVc", verb: "GET", path: `/api/sessions/${SID}/vc/verify`, kind: "json", call: (c) => c.verifySessionVc(SID) },
  { name: "getMetrics", verb: "GET", path: "/api/metrics", kind: "json", call: (c) => c.getMetrics() },
  { name: "getSecurityMetrics", verb: "GET", path: "/api/metrics/security", kind: "json", call: (c) => c.getSecurityMetrics() },
  { name: "getPrometheusMetrics", verb: "GET", path: "/metrics", kind: "text", call: (c) => c.getPrometheusMetrics() },
  { name: "listPolicies", verb: "GET", path: "/api/policies", kind: "json", call: (c) => c.listPolicies() },
  { name: "getPolicy", verb: "GET", path: "/api/policies/soc2", kind: "text", call: (c) => c.getPolicy("soc2") },
  { name: "savePolicy", verb: "PUT", path: "/api/policies/soc2", kind: "none", call: (c) => c.savePolicy("soc2", "x = 1") },
  { name: "deletePolicy", verb: "DELETE", path: "/api/policies/soc2", kind: "none", call: (c) => c.deletePolicy("soc2") },
  { name: "getPendingApproval", verb: "GET", path: `/api/approvals/${SID}/pending`, kind: "json", call: (c) => c.getPendingApproval(SID) },
  { name: "postApprovalDecision", verb: "POST", path: `/api/approvals/${SID}`, kind: "json", call: (c) => c.postApprovalDecision(SID, { gate_id: "g", approved: true }) },
  { name: "getStatus", verb: "GET", path: "/api/status", kind: "json", call: (c) => c.getStatus() },
  { name: "chat", verb: "POST", path: `/api/sessions/${SID}/chat`, kind: "json", call: (c) => c.chat(SID, "hi") },
  { name: "chatStream", verb: "POST", path: `/api/sessions/${SID}/chat/stream`, kind: "stream", call: (c) => c.chatStream(SID, "hi").next() },
  { name: "ask", verb: "POST", path: "/api/chat", kind: "json", call: (c) => c.ask("hi") },
  { name: "askStream", verb: "POST", path: "/api/chat/stream", kind: "stream", call: (c) => c.askStream("hi").next() },
  { name: "getConfig", verb: "GET", path: "/api/config", kind: "json", call: (c) => c.getConfig() },
  { name: "updateConfig", verb: "PUT", path: "/api/config", kind: "put", call: (c) => c.updateConfig({ max_steps: 5 }) },
  { name: "resetDemo", verb: "POST", path: "/api/admin/reset-demo", kind: "json", call: (c) => c.resetDemo() },
  { name: "getTripwireConfig", verb: "GET", path: "/api/tripwire", kind: "json", call: (c) => c.getTripwireConfig() },
  {
    name: "updateTripwireConfig",
    verb: "PUT",
    path: "/api/tripwire",
    kind: "put",
    call: (c) => c.updateTripwireConfig({ allowed_paths: [], allowed_domains: [], banned_command_patterns: [] }),
  },
  { name: "checkTripwire", verb: "POST", path: "/api/tripwire/check", kind: "json", call: (c) => c.checkTripwire({ action: "complete" }) },
  { name: "listTokens", verb: "GET", path: "/api/tokens", kind: "json", call: (c) => c.listTokens() },
  { name: "createToken", verb: "POST", path: "/api/tokens", kind: "json", call: (c) => c.createToken({ role: "agent" }) },
  { name: "deleteToken", verb: "DELETE", path: "/api/tokens/abc123", kind: "none", call: (c) => c.deleteToken("abc123") },
  { name: "listWebhooks", verb: "GET", path: "/api/webhooks", kind: "json", call: (c) => c.listWebhooks() },
  { name: "createWebhook", verb: "POST", path: "/api/webhooks", kind: "json", call: (c) => c.createWebhook({ label: "l", url: "https://x.example" }) },
  { name: "deleteWebhook", verb: "DELETE", path: "/api/webhooks/wh-1", kind: "none", call: (c) => c.deleteWebhook("wh-1") },
  { name: "toggleWebhook", verb: "PUT", path: "/api/webhooks/wh-1", kind: "put", call: (c) => c.toggleWebhook("wh-1", true) },
  { name: "streamEvents", verb: "GET", path: "/api/stream", kind: "stream", call: (c) => c.streamEvents().next() },
];

/** Every method that goes through the client's built-in 30-second timeout. */
const TIMED = METHODS.filter((m) => m.kind !== "stream");

const HTML_PAGE =
  "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>" +
  "<body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx</center></body></html>";
const TRUNCATED_JSON = '{"id":"550e8400-e29b-41d4-a716-446655440000","goal":"Summ';

const respond = (body: BodyInit | null, status: number, headers: Record<string, string> = {}) =>
  new Response(body, { status, headers });

/** A fetch that never answers on its own and rejects the way undici does when its signal aborts. */
const hangUntilAborted = (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
  new Promise((_resolve, reject) => {
    const signal = init?.signal;
    if (!signal) return;
    signal.addEventListener("abort", () => reject(signal.reason), { once: true });
  });

/** Track a promise's state without awaiting it. */
const watch = (p: Promise<unknown>) => {
  const s: { state: "pending" | "fulfilled" | "rejected"; value?: unknown } = { state: "pending" };
  p.then(
    (value) => Object.assign(s, { state: "fulfilled", value }),
    (value) => Object.assign(s, { state: "rejected", value }),
  );
  return s;
};

let client: IronViseClient;
let fetchSpy: MockInstance<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  client = new IronViseClient({ baseUrl: BASE_URL, bearerToken: "tok" });
  // Anything a test did not script is a test bug, never a real request.
  fetchSpy = vi
    .spyOn(globalThis, "fetch")
    .mockImplementation(() => Promise.reject(new Error("unscripted fetch in test")));
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("method table", () => {
  it("has one row for every public method of IronViseClient", () => {
    const privateHelpers = new Set(["constructor", "get", "post", "put", "del", "request", "streamChat"]);
    const publicMethods = Object.getOwnPropertyNames(IronViseClient.prototype)
      .filter((n) => !privateHelpers.has(n))
      .sort();
    expect(METHODS.map((m) => m.name).sort()).toEqual(publicMethods);
  });
});

describe.each(METHODS)("$name", (m) => {
  const url = `${BASE_URL}${m.path}`;

  describe("non-2xx response", () => {
    it.each([
      [401, "missing or invalid bearer token"],
      [403, "Auditor role cannot seal sessions"],
      [429, "rate limit exceeded"],
      [500, '{"detail":"internal error"}'],
      [502, HTML_PAGE],
      [503, "LLM backend not ready"],
      [504, ""],
    ])("%i rejects with IronViseApiError carrying status, body and request", async (status, body) => {
      // A fresh Response per call: a retried GET reads the body each attempt.
      fetchSpy.mockImplementation(() =>
        Promise.resolve(respond(body, status, { "Content-Type": "text/plain" })),
      );
      const retried = m.kind !== "stream" && m.verb === "GET" && RETRIABLE_STATUSES.has(status);
      const expectedCalls = retried ? 1 + DEFAULT_RETRIES : 1;
      const call = watch(m.call(client));
      await vi.advanceTimersByTimeAsync(60_000);
      expect(call.state).toBe("rejected");
      const err = call.value;
      expect(err).toBeInstanceOf(IronViseApiError);
      expect(err).toBeInstanceOf(Error);
      const api = err as IronViseApiError;
      expect(api.name).toBe("IronViseApiError");
      expect(api.status).toBe(status);
      expect(api.body).toBe(body);
      expect(api.message).toBe(`IronVise API ${m.verb} ${url} → ${status}: ${body}`);
      expect(fetchSpy).toHaveBeenCalledTimes(expectedCalls);
      expect(vi.getTimerCount()).toBe(0);
    });

    it("429 with Retry-After is not retried; the error carries status and body only", async () => {
      fetchSpy.mockResolvedValueOnce(respond("slow down", 429, { "Retry-After": "1" }));
      const err = (await m.call(client).catch((e: unknown) => e)) as IronViseApiError;
      expect(err).toBeInstanceOf(IronViseApiError);
      expect(err.status).toBe(429);
      expect(err.body).toBe("slow down");
      await vi.advanceTimersByTimeAsync(5_000);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    it("sends the bearer token, so a 401/403 is the server's verdict on it", async () => {
      fetchSpy.mockResolvedValueOnce(respond("forbidden", 403));
      await m.call(client).catch(() => undefined);
      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer tok");
    });
  });

  describe("transport failure", () => {
    it("propagates a fetch rejection unchanged; a GET retries first, without leaking a timer", async () => {
      const cause = new TypeError("fetch failed", { cause: new Error("connect ECONNREFUSED 127.0.0.1:3000") });
      fetchSpy.mockImplementation(() => Promise.reject(cause));
      const expectedCalls = m.kind !== "stream" && m.verb === "GET" ? 1 + DEFAULT_RETRIES : 1;
      const call = watch(m.call(client));
      await vi.advanceTimersByTimeAsync(60_000);
      expect(call.state).toBe("rejected");
      expect(call.value).toBe(cause);
      expect(fetchSpy).toHaveBeenCalledTimes(expectedCalls);
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  describe("2xx with a body the method cannot use", () => {
    const bodies = [
      ["an HTML page", HTML_PAGE],
      ["truncated JSON", TRUNCATED_JSON],
      ["an empty body", ""],
    ] as const;

    it.each(bodies)("%s", async (_label, body) => {
      fetchSpy.mockResolvedValueOnce(respond(body, 200));
      const outcome = await m.call(client).then(
        (value) => ({ ok: true as const, value }),
        (error: unknown) => ({ ok: false as const, error }),
      );
      expect(vi.getTimerCount()).toBe(0);

      switch (m.kind) {
        case "json":
          // A 2xx is not an API error: the parser's SyntaxError surfaces as is.
          expect(outcome.ok).toBe(false);
          if (!outcome.ok) {
            expect(outcome.error).toBeInstanceOf(SyntaxError);
            expect(outcome.error).not.toBeInstanceOf(IronViseApiError);
          }
          break;
        case "put":
          if (body === "") {
            expect(outcome).toEqual({ ok: true, value: undefined });
          } else {
            expect(outcome.ok).toBe(false);
            if (!outcome.ok) expect(outcome.error).toBeInstanceOf(SyntaxError);
          }
          break;
        case "text":
          expect(outcome).toEqual({ ok: true, value: body });
          break;
        case "blob":
          expect(outcome.ok).toBe(true);
          if (outcome.ok) {
            expect(outcome.value).toBeInstanceOf(Blob);
            expect(await (outcome.value as Blob).text()).toBe(body);
          }
          break;
        case "none":
          expect(outcome).toEqual({ ok: true, value: undefined });
          break;
        case "stream":
          // No `data:` frame, so nothing to yield and nothing to throw.
          expect(outcome).toEqual({ ok: true, value: { done: true, value: undefined } });
          break;
      }
    });
  });
});

describe.each(TIMED)("$name timeout", (m) => {
  it(`aborts a request that has no response after ${TIMEOUT_MS / 1000} s`, async () => {
    fetchSpy.mockImplementationOnce(hangUntilAborted);
    const call = watch(m.call(client));

    await vi.advanceTimersByTimeAsync(TIMEOUT_MS - 1);
    expect(call.state).toBe("pending");

    await vi.advanceTimersByTimeAsync(1);
    expect(call.state).toBe("rejected");
    expect((call.value as DOMException).name).toBe("AbortError");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  // The timeout should also bound reading the body: a server that sends headers
  // and then stalls is as stuck as one that never answers.
  const stallsBody = m.kind !== "none";
  if (stallsBody) it("also aborts a response whose body stalls", async () => {
    fetchSpy.mockImplementationOnce(async (_input, init) => {
      const signal = init!.signal!;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          signal.addEventListener("abort", () => controller.error(signal.reason), { once: true });
        },
      });
      return new Response(body, { status: 200 });
    });
    const call = watch(m.call(client));
    await vi.advanceTimersByTimeAsync(TIMEOUT_MS);
    await vi.advanceTimersByTimeAsync(0);
    expect(call.state).toBe("rejected");
    expect((call.value as DOMException).name).toBe("AbortError");
  });
});

describe("streamEvents cancellation", () => {
  it("forwards the caller's signal and rejects when it aborts", async () => {
    fetchSpy.mockImplementationOnce(hangUntilAborted);
    const controller = new AbortController();
    const next = watch(client.streamEvents({ signal: controller.signal }).next());
    await vi.advanceTimersByTimeAsync(0);
    expect((fetchSpy.mock.calls[0][1] as RequestInit).signal).toBe(controller.signal);

    controller.abort();
    await vi.advanceTimersByTimeAsync(0);
    expect(next.state).toBe("rejected");
    expect((next.value as DOMException).name).toBe("AbortError");
  });

  it("has no built-in timeout: a long-lived stream is the caller's to cancel", async () => {
    fetchSpy.mockImplementationOnce(hangUntilAborted);
    const next = watch(client.streamEvents().next());
    await vi.advanceTimersByTimeAsync(TIMEOUT_MS * 4);
    expect(next.state).toBe("pending");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("skips a malformed data frame and keeps reading", async () => {
    const sse =
      'data: {"id":1,"sequ\n\n' +
      "data: <html>oops</html>\n\n" +
      'data: {"id":2,"sequence":2}\n\n';
    fetchSpy.mockResolvedValueOnce(respond(sse, 200, { "Content-Type": "text/event-stream" }));
    const seen = [];
    for await (const ev of client.streamEvents()) seen.push(ev);
    expect(seen).toEqual([{ id: 2, sequence: 2 }]);
  });
});
