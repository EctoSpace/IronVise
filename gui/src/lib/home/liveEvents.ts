// Turning a raw ledger row (from `run_prompt`'s SSE stream or its polling
// fallback) into the shape LiveFeed renders.

import { describeEvent } from "../events";
import type { LiveEvent } from "./LiveFeed.svelte";

export function parseLiveEventItem(ev: unknown): LiveEvent | null {
  if (!ev || typeof ev !== "object") return null;
  const e = ev as Record<string, unknown>;
  const rawPayload = e.payload;
  if (!rawPayload) return null;
  let p: Record<string, unknown>;
  if (typeof rawPayload === "string") {
    try {
      p = JSON.parse(rawPayload);
    } catch {
      return null;
    }
  } else if (typeof rawPayload === "object" && !Array.isArray(rawPayload)) {
    p = rawPayload as Record<string, unknown>;
  } else return null;

  const view = describeEvent(p);
  const typeLabel = view.label;
  const content = view.text;
  const isComplete = view.type === "action" && p.name === "complete";
  const isError = view.tone === "error" || view.tone === "blocked";
  const colorHint: LiveEvent["colorHint"] =
    view.tone === "blocked" ? "tripwire"
    : view.tone === "chat" ? "chat"
    : view.tone === "action" ? "action"
    : null;
  return { typeLabel, content, isError, isComplete, colorHint };
}
