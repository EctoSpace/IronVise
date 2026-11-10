// Shapes and pure helpers the Observer panel's session timeline builds on.
// Kept separate from the Svelte views so the initial load and the SSE handler
// share one definition and it can be unit tested without a DOM.

import { parsePayload, type EventTone } from "../events";
import type { SessionSummary } from "../backend";

export interface EventRow {
  id?: number;
  sequence: number;
  previous_hash: string;
  content_hash: string;
  payload: Record<string, unknown> | string;
  created_at: string;
}

/** A raw ledger row, as `get_events` or an SSE frame delivers it: payload may
 *  arrive pre-serialised as JSON text, and a malformed one is kept as-is
 *  rather than thrown away. `fallbackCreatedAt` lets the SSE path stamp "now"
 *  when the server omits it, while the initial load leaves it blank. */
export function toEventRow(e: Record<string, unknown>, fallbackCreatedAt = ""): EventRow {
  return {
    id: e.id as number | undefined,
    sequence: (e.sequence as number) ?? 0,
    previous_hash: (e.previous_hash as string) ?? "",
    content_hash: (e.content_hash as string) ?? "",
    payload:
      typeof e.payload === "string"
        ? (() => {
            try {
              return JSON.parse(e.payload as string);
            } catch {
              return e.payload;
            }
          })()
        : (e.payload as Record<string, unknown>),
    created_at: (e.created_at as string) ?? fallbackCreatedAt,
  };
}

/** A non-array answer counts as no events. */
export function normaliseEvents(data: unknown): EventRow[] {
  if (!Array.isArray(data)) return [];
  return (data as Record<string, unknown>[]).map((e) => toEventRow(e));
}

export function shortHash(h: unknown): string {
  if (typeof h !== "string" || !h) return "-";
  return h.substring(0, 8);
}

export function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function sevClass(s: string): string {
  const lower = (s ?? "").toLowerCase();
  if (lower === "critical") return "text-danger font-bold";
  if (lower === "high") return "text-caution font-semibold";
  if (lower === "medium") return "text-warning";
  return "text-text-secondary";
}

/** The findings table for a "complete" action event, or null for any other. */
export function getFindings(ev: EventRow): Record<string, unknown>[] | null {
  const p = parsePayload(ev.payload);
  if ((p.type as string) !== "action" || (p.name as string) !== "complete") return null;
  const params = p.params as Record<string, unknown> | undefined;
  if (!params || !Array.isArray(params.findings)) return null;
  return params.findings as Record<string, unknown>[];
}

/** Sessions whose id or goal contains the (case-insensitive) query. */
export function filterSessions(sessions: SessionSummary[], query: string): SessionSummary[] {
  if (!query.trim()) return sessions;
  const q = query.toLowerCase();
  return sessions.filter(
    (s) => s.id.toLowerCase().includes(q) || (s.goal ?? "").toLowerCase().includes(q),
  );
}

// Keyed by tone rather than by type, so a new event kind gets a sensible
// colour from `describeEvent`.
// CSS custom properties, not Tailwind classes: these feed `style:` bindings
// (border-left, background, color), not `class`, so a var() is what makes
// them follow the light/dark palette in app.css.
export const TONE_COLORS: Record<EventTone, { border: string; dot: string; bg?: string }> = {
  neutral: { border: "var(--color-text-muted)", dot: "var(--color-text-muted)" },
  info: { border: "var(--color-accent-text)", dot: "var(--color-accent-text)" },
  action: { border: "var(--color-warning)", dot: "var(--color-warning)" },
  success: { border: "var(--color-success)", dot: "var(--color-success)" },
  warning: { border: "var(--color-caution)", dot: "var(--color-caution)" },
  blocked: { border: "var(--color-danger)", dot: "var(--color-danger)", bg: "var(--color-danger-muted)" },
  error: { border: "var(--color-danger)", dot: "var(--color-danger)", bg: "var(--color-danger-muted)" },
  evidence: { border: "var(--color-evidence)", dot: "var(--color-evidence)" },
  chat: { border: "var(--color-text-muted)", dot: "var(--color-text-muted)" },
};
