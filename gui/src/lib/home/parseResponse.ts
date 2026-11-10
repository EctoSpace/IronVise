/**
 * Extract a human-readable string from an arbitrary JSON response.
 * Tries common agent schema fields first, then falls back to a
 * key-value summary, finally to pretty-printed JSON.
 */
export function parseResponse(raw: unknown): string {
  if (raw == null) return "";
  if (typeof raw === "string") return raw;
  if (Array.isArray(raw)) return JSON.stringify(raw, null, 2);
  if (typeof raw !== "object") return String(raw);

  const obj = raw as Record<string, unknown>;

  // Agent thought / action / observation fields
  for (const key of ["justification", "observation", "thought", "message", "content", "result", "answer"]) {
    if (typeof obj[key] === "string" && (obj[key] as string).length > 0) {
      return obj[key] as string;
    }
  }

  // Session creation response (goal + status present)
  if (typeof obj.goal === "string" && obj.status) {
    const id = typeof obj.id === "string" ? `\nSession ID: ${(obj.id as string).slice(0, 8)}…` : "";
    return `Session started.\nGoal: ${obj.goal}\nStatus: ${obj.status}${id}`;
  }

  // Generic: join top-level scalar values as key: value lines
  const lines = Object.entries(obj)
    .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
    .map(([k, v]) => `${k}: ${v}`);
  if (lines.length > 0) return lines.join("\n");

  return JSON.stringify(raw, null, 2);
}
