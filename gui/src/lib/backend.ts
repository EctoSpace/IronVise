// Backend helpers shared by every view.

import { invoke, isTauri } from "@tauri-apps/api/core";

/**
 * Detect demo mode: ask the Tauri process for the env var first, then fall
 * back to the backend's public /api/status endpoint (the authoritative path
 * on Windows, where the launcher's spawn chain can lose process-scope env
 * vars). The status check is retried once after 2 s for slow cold starts.
 */
export async function detectDemoMode(serverUrl?: string): Promise<boolean> {
  if (isTauri()) {
    try {
      if (await invoke<boolean>("is_demo_mode")) return true;
    } catch {
      // Command unavailable (browser preview) - fall through to status check.
    }
  }
  if (!serverUrl) return false;
  const check = () =>
    fetch(`${serverUrl}/api/status`, { signal: AbortSignal.timeout(5000) })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`status ${r.status}`))))
      .then((body: { demo_mode?: boolean }) => !!body?.demo_mode);
  try {
    return await check();
  } catch {
    await new Promise((r) => setTimeout(r, 2000));
    try {
      return await check();
    } catch {
      return false;
    }
  }
}

/** What the live ledger pool can do - from `/api/status`, not settings.json. */
export interface BackendCapabilities {
  ledger_backend: "postgres" | "sqlite" | string;
  agent_supported: boolean;
  exports_supported: boolean;
  webhooks_live: boolean;
}

const SQLITE_CAPS: BackendCapabilities = {
  ledger_backend: "sqlite",
  agent_supported: true,
  exports_supported: true,
  webhooks_live: true,
};

/**
 * Read capability flags from the public status endpoint (or get_config when
 * already authenticated via Tauri). Defaults to the SQLite set (agent,
 * exports and webhooks all on) so a failed probe does not invent capabilities
 * neither backend currently has.
 */
export async function fetchCapabilities(serverUrl?: string): Promise<BackendCapabilities> {
  if (isTauri()) {
    try {
      const cfg = await invoke<Partial<BackendCapabilities>>("get_config");
      if (typeof cfg?.agent_supported === "boolean") {
        return {
          ledger_backend: cfg.ledger_backend ?? "sqlite",
          agent_supported: !!cfg.agent_supported,
          exports_supported: !!cfg.exports_supported,
          webhooks_live: !!cfg.webhooks_live,
        };
      }
    } catch {
      // Fall through to /api/status.
    }
  }
  if (!serverUrl) return SQLITE_CAPS;
  try {
    const res = await fetch(`${serverUrl}/api/status`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return SQLITE_CAPS;
    const body = (await res.json()) as Partial<BackendCapabilities>;
    return {
      ledger_backend: body.ledger_backend ?? "sqlite",
      agent_supported: !!body.agent_supported,
      exports_supported: !!body.exports_supported,
      webhooks_live: !!body.webhooks_live,
    };
  } catch {
    return SQLITE_CAPS;
  }
}

/** Fetch the Verifiable Credential for a completed session. */
export async function fetchSessionVc(sessionId: string): Promise<Record<string, unknown>> {
  const data = await invoke<unknown>("get_session_vc", { sessionId });
  return data as Record<string, unknown>;
}

export interface VcVerifyResult {
  valid?: boolean;
  message?: string;
  error?: string;
}

/** Verify the Verifiable Credential of a session server-side. */
export async function verifySessionVc(sessionId: string): Promise<VcVerifyResult> {
  const data = await invoke<unknown>("verify_session_vc", { sessionId });
  return data as VcVerifyResult;
}

/** A row of `GET /api/sessions`, shared by every screen that lists sessions. */
export interface SessionSummary {
  id: string;
  goal: string;
  goal_hash?: string;
  status: string;
  created_at: string;
  finished_at: string | null;
  llm_backend?: string;
  llm_model?: string;
  /** SHA-256 of the policy the run was checked against; null when none. */
  policy_hash?: string | null;
}

/** Sessions, newest first. A non-array answer counts as none. */
export async function listSessions(
  opts: { status?: string | null; limit?: number; offset?: number } = {},
): Promise<SessionSummary[]> {
  const data = await invoke<unknown>("get_sessions", {
    status: opts.status || null,
    limit: opts.limit ?? 100,
    offset: opts.offset ?? 0,
  });
  return Array.isArray(data) ? (data as SessionSummary[]) : [];
}

/** A session's ledger events, in order. A non-array answer counts as none. */
export async function sessionEvents(sessionId: string): Promise<unknown[]> {
  const data = await invoke<unknown>("get_events", { sessionId });
  return Array.isArray(data) ? data : [];
}
