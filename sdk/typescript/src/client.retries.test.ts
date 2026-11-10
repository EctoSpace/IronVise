/**
 * IronViseClient - GET retry policy (`timeoutMs` / `retries` options and the
 * private `request` helper in client.ts).
 *
 * `fetch` is stubbed and timers are faked; nothing touches the network or
 * waits out a real backoff delay.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { IronViseApiError, IronViseClient } from "./client.js";

const BASE_URL = "http://localhost:3000";

const respond = (body: BodyInit | null, status: number, headers: Record<string, string> = {}) =>
  new Response(body, { status, headers });

/** Track a promise's state without awaiting it. */
const watch = (p: Promise<unknown>) => {
  const s: { state: "pending" | "fulfilled" | "rejected"; value?: unknown } = { state: "pending" };
  p.then(
    (value) => Object.assign(s, { state: "fulfilled", value }),
    (value) => Object.assign(s, { state: "rejected", value }),
  );
  return s;
};

/** A fetch that never answers on its own and rejects the way undici does when its signal aborts. */
const hangUntilAborted = (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
  new Promise((_resolve, reject) => {
    const signal = init?.signal;
    if (!signal) return;
    signal.addEventListener("abort", () => reject(signal.reason), { once: true });
  });

let fetchSpy: MockInstance<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  fetchSpy = vi
    .spyOn(globalThis, "fetch")
    .mockImplementation(() => Promise.reject(new Error("unscripted fetch in test")));
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("timeoutMs", () => {
  it("defaults to 30s", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    fetchSpy.mockImplementationOnce(hangUntilAborted);
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(29_999);
    expect(call.state).toBe("pending");
    await vi.advanceTimersByTimeAsync(1);
    expect(call.state).toBe("rejected");
    expect((call.value as DOMException).name).toBe("AbortError");
  });

  it("is applied per attempt when given a custom value", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL, timeoutMs: 5_000, retries: 0 });
    fetchSpy.mockImplementationOnce(hangUntilAborted);
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(4_999);
    expect(call.state).toBe("pending");
    await vi.advanceTimersByTimeAsync(1);
    expect(call.state).toBe("rejected");
    expect((call.value as DOMException).name).toBe("AbortError");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});

describe("retries", () => {
  it("retries a GET on 503 then succeeds", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    fetchSpy
      .mockResolvedValueOnce(respond("not ready", 503))
      .mockResolvedValueOnce(respond("not ready", 503))
      .mockResolvedValueOnce(respond(JSON.stringify([]), 200));
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(10_000);
    expect(call.state).toBe("fulfilled");
    expect(call.value).toEqual([]);
    expect(fetchSpy).toHaveBeenCalledTimes(3);
  });

  it("honours Retry-After, in seconds, between attempts", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    fetchSpy
      .mockResolvedValueOnce(respond("slow down", 503, { "Retry-After": "2" }))
      .mockResolvedValueOnce(respond(JSON.stringify([]), 200));
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(1_999);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(call.state).toBe("pending");
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(0);
    expect(call.state).toBe("fulfilled");
  });

  it("caps a very large Retry-After instead of waiting it out", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    fetchSpy
      .mockResolvedValueOnce(respond("slow down", 503, { "Retry-After": "600" }))
      .mockResolvedValueOnce(respond(JSON.stringify([]), 200));
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(4_000);
    expect(call.state).toBe("fulfilled");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("does not retry a POST on 503", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    fetchSpy.mockResolvedValueOnce(respond("not ready", 503));
    const err = await client.createSession({ goal: "g" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IronViseApiError);
    expect((err as IronViseApiError).status).toBe(503);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("does not retry a GET on a 4xx", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    fetchSpy.mockResolvedValueOnce(respond("not found", 404));
    const err = await client.getSessionById("x").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IronViseApiError);
    expect((err as IronViseApiError).status).toBe(404);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("does not retry a timeout: the attempt already waited", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    fetchSpy.mockImplementationOnce(hangUntilAborted);
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(30_000);
    expect(call.state).toBe("rejected");
    expect((call.value as DOMException).name).toBe("AbortError");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("surfaces the last error once retries are exhausted", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    fetchSpy
      .mockResolvedValueOnce(respond("attempt 1", 503))
      .mockResolvedValueOnce(respond("attempt 2", 503))
      .mockResolvedValueOnce(respond("attempt 3", 503));
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(10_000);
    expect(call.state).toBe("rejected");
    expect((call.value as IronViseApiError).body).toBe("attempt 3");
    expect(fetchSpy).toHaveBeenCalledTimes(3); // the default of 2 retries: 1 + 2 attempts
  });

  it("retries: 0 disables retrying", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL, retries: 0 });
    fetchSpy.mockResolvedValueOnce(respond("not ready", 503));
    const err = await client.listSessions().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IronViseApiError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("a custom retries count changes the attempt budget", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL, retries: 5 });
    fetchSpy.mockImplementation(() => Promise.resolve(respond("not ready", 503)));
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(30_000);
    expect(call.state).toBe("rejected");
    expect(fetchSpy).toHaveBeenCalledTimes(6); // 1 + 5 retries
  });

  it("rejects a negative retries count at construction", () => {
    expect(() => new IronViseClient({ baseUrl: BASE_URL, retries: -1 })).toThrow(RangeError);
  });

  it("retries a GET on a network error, not only on an HTTP status", async () => {
    const client = new IronViseClient({ baseUrl: BASE_URL });
    const cause = new TypeError("fetch failed", { cause: new Error("connect ECONNREFUSED") });
    fetchSpy.mockRejectedValueOnce(cause).mockResolvedValueOnce(respond(JSON.stringify([]), 200));
    const call = watch(client.listSessions());
    await vi.advanceTimersByTimeAsync(10_000);
    expect(call.state).toBe("fulfilled");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });
});


describe("invalid retry and timeout settings", () => {
  it.each([NaN, Infinity, -Infinity, -1, 0.5, Number.MAX_SAFE_INTEGER + 1])("rejects retries=%s before fetching", (retries) => {
    expect(() => new IronViseClient({retries})).toThrow(RangeError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
  it.each([NaN, Infinity, -Infinity, -1, 0, 2 ** 31])("rejects timeoutMs=%s before fetching", (timeoutMs) => {
    expect(() => new IronViseClient({timeoutMs})).toThrow(RangeError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
