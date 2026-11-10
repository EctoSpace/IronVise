// Unit tests for backend.ts. @tauri-apps/api/core is mocked so the same
// module can be exercised in both "running inside Tauri" and "browser
// preview" modes without a real Tauri runtime.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { isTauri, invoke } = vi.hoisted(() => ({
  isTauri: vi.fn(() => false),
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ isTauri, invoke }));

import {
  detectDemoMode,
  fetchCapabilities,
  fetchSessionVc,
  verifySessionVc,
} from "./backend";

function jsonResponse(body: unknown, ok = true, status = 200) {
  return {
    ok,
    status,
    json: () => Promise.resolve(body),
  } as Response;
}

beforeEach(() => {
  isTauri.mockReturnValue(false);
  invoke.mockReset();
  vi.stubGlobal("fetch", vi.fn());
  vi.useFakeTimers();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("detectDemoMode", () => {
  it("returns false when there is no serverUrl and we are not in Tauri", async () => {
    await expect(detectDemoMode()).resolves.toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("asks Tauri's is_demo_mode command first when running inside Tauri", async () => {
    isTauri.mockReturnValue(true);
    invoke.mockResolvedValue(true);
    await expect(detectDemoMode("http://x")).resolves.toBe(true);
    expect(invoke).toHaveBeenCalledWith("is_demo_mode");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("falls through to the status endpoint when the Tauri command is unavailable", async () => {
    isTauri.mockReturnValue(true);
    invoke.mockRejectedValue(new Error("command not found"));
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(jsonResponse({ demo_mode: true }));
    await expect(detectDemoMode("http://x")).resolves.toBe(true);
    expect(fetch).toHaveBeenCalledWith("http://x/api/status", expect.anything());
  });

  it("reads demo_mode off the status body", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(jsonResponse({ demo_mode: false }));
    await expect(detectDemoMode("http://x")).resolves.toBe(false);
  });

  it("retries once after 2s when the first status check fails, then succeeds", async () => {
    (fetch as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(new Error("network down"))
      .mockResolvedValueOnce(jsonResponse({ demo_mode: true }));
    const result = detectDemoMode("http://x");
    await vi.advanceTimersByTimeAsync(2000);
    await expect(result).resolves.toBe(true);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("returns false when both the first and retried status check fail", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("network down"));
    const result = detectDemoMode("http://x");
    await vi.advanceTimersByTimeAsync(2000);
    await expect(result).resolves.toBe(false);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("treats a non-OK status response as a failure and retries", async () => {
    (fetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(jsonResponse({}, false, 503))
      .mockResolvedValueOnce(jsonResponse({ demo_mode: true }));
    const result = detectDemoMode("http://x");
    await vi.advanceTimersByTimeAsync(2000);
    await expect(result).resolves.toBe(true);
  });

  it("treats a non-JSON body as a failure and retries", async () => {
    const badBody = { ok: true, status: 200, json: () => Promise.reject(new Error("bad json")) } as Response;
    (fetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(badBody)
      .mockResolvedValueOnce(jsonResponse({ demo_mode: true }));
    const result = detectDemoMode("http://x");
    await vi.advanceTimersByTimeAsync(2000);
    await expect(result).resolves.toBe(true);
  });
});

describe("fetchCapabilities", () => {
  const SQLITE_CAPS = {
    ledger_backend: "sqlite",
    agent_supported: true,
    exports_supported: true,
    webhooks_live: true,
  };

  it("defaults to the SQLite capability set with no serverUrl and no Tauri", async () => {
    await expect(fetchCapabilities()).resolves.toEqual(SQLITE_CAPS);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("uses get_config over Tauri when it reports a boolean agent_supported", async () => {
    isTauri.mockReturnValue(true);
    invoke.mockResolvedValue({
      ledger_backend: "postgres",
      agent_supported: true,
      exports_supported: false,
      webhooks_live: true,
    });
    await expect(fetchCapabilities("http://x")).resolves.toEqual({
      ledger_backend: "postgres",
      agent_supported: true,
      exports_supported: false,
      webhooks_live: true,
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("falls through to /api/status when get_config's agent_supported is not boolean", async () => {
    isTauri.mockReturnValue(true);
    invoke.mockResolvedValue({ ledger_backend: "postgres" });
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse({
        ledger_backend: "postgres",
        agent_supported: true,
        exports_supported: true,
        webhooks_live: false,
      }),
    );
    await expect(fetchCapabilities("http://x")).resolves.toEqual({
      ledger_backend: "postgres",
      agent_supported: true,
      exports_supported: true,
      webhooks_live: false,
    });
  });

  it("falls through to /api/status when invoke throws", async () => {
    isTauri.mockReturnValue(true);
    invoke.mockRejectedValue(new Error("no such command"));
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(jsonResponse(SQLITE_CAPS));
    await expect(fetchCapabilities("http://x")).resolves.toEqual(SQLITE_CAPS);
  });

  it("falls back to SQLITE_CAPS when the status response is not OK", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(jsonResponse({}, false, 500));
    await expect(fetchCapabilities("http://x")).resolves.toEqual(SQLITE_CAPS);
  });

  it("falls back to SQLITE_CAPS when fetch rejects", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("offline"));
    await expect(fetchCapabilities("http://x")).resolves.toEqual(SQLITE_CAPS);
  });

  it("falls back to SQLITE_CAPS when the body is not valid JSON", async () => {
    const badBody = { ok: true, status: 200, json: () => Promise.reject(new Error("bad json")) } as Response;
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(badBody);
    await expect(fetchCapabilities("http://x")).resolves.toEqual(SQLITE_CAPS);
  });

  it("defaults ledger_backend to sqlite when the status body omits it", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse({ agent_supported: true, exports_supported: true, webhooks_live: true }),
    );
    const caps = await fetchCapabilities("http://x");
    expect(caps.ledger_backend).toBe("sqlite");
  });
});

describe("fetchSessionVc / verifySessionVc", () => {
  it("passes the session id through to get_session_vc and returns its result", async () => {
    invoke.mockResolvedValue({ jwt: "abc" });
    await expect(fetchSessionVc("sess-1")).resolves.toEqual({ jwt: "abc" });
    expect(invoke).toHaveBeenCalledWith("get_session_vc", { sessionId: "sess-1" });
  });

  it("passes the session id through to verify_session_vc and returns its result", async () => {
    invoke.mockResolvedValue({ valid: true });
    await expect(verifySessionVc("sess-2")).resolves.toEqual({ valid: true });
    expect(invoke).toHaveBeenCalledWith("verify_session_vc", { sessionId: "sess-2" });
  });
});
