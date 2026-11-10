/**
 * One description of every ledger event, shared by Home (live feed and
 * Observer timeline) and History.
 *
 * The variants mirror `EventPayload` in `crates/host/src/schema.rs`; add a
 * case when that enum grows.
 */

/** Visual weight of an event. Screens map a tone to their own colours. */
export type EventTone =
  | "neutral"
  | "info"
  | "action"
  | "success"
  | "warning"
  | "blocked"
  | "error"
  | "evidence"
  | "chat";

export interface EventView {
  /** Raw `payload.type`, e.g. `guard_denial`. */
  type: string;
  /** Short human label, e.g. "Blocked by guard". */
  label: string;
  /** The readable body. Multi-line text is allowed. */
  text: string;
  tone: EventTone;
}

/** Payloads arrive as objects or as pre-serialised JSON strings. */
export function parsePayload(raw: unknown): Record<string, unknown> {
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      /* fall through */
    }
    return { type: "unknown", content: raw };
  }
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  return { type: "unknown", content: String(raw) };
}

export function formatEventType(t: string): string {
  return t.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function short(h: unknown, n = 12): string {
  const s = typeof h === "string" ? h : "";
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function str(v: unknown): string {
  return typeof v === "string" ? v : v == null ? "" : String(v);
}

/** The one argument a reader needs to recognise an action. */
function actionTarget(params: unknown): string {
  if (params == null) return "";
  if (typeof params !== "object") return String(params);
  const p = params as Record<string, unknown>;
  for (const k of ["command", "path", "file_path", "url", "pattern", "query"]) {
    if (typeof p[k] === "string" && p[k]) return p[k] as string;
  }
  return JSON.stringify(params, null, 2);
}

const STAGE_LABELS: Record<string, string> = {
  prompt_scan: "prompt scan",
  validation: "validation",
  policy: "policy",
};

/**
 * Pre-0.8 ledgers recorded refusals as prose inside a `thought`. They still
 * verify, so they still render, and they should still read as refusals.
 */
const LEGACY_REFUSAL = /^(Guard denied|Tripwire rejected|Policy rejected|Security):/;

export function describeEvent(payload: unknown): EventView {
  const p = parsePayload(payload);
  const type = str(p.type) || "unknown";
  const view = (label: string, text: string, tone: EventTone): EventView => ({
    type,
    label,
    text,
    tone,
  });

  switch (type) {
    case "genesis":
      return view("Ledger opened", str(p.message) || "Ledger initialised.", "neutral");
    case "prompt_input":
      return view("Goal", str(p.content), "info");
    case "thought": {
      const c = str(p.content);
      if (LEGACY_REFUSAL.test(c)) return view("Refused", c, "blocked");
      if (c.startsWith("SCHEMA ERROR")) return view("Invalid model output", c, "error");
      return view("Thought", c, "info");
    }
    case "schema_error":
      return view(
        "Invalid model output",
        `Attempt ${str(p.attempt) || "?"} of ${str(p.max_attempts) || "?"}: ${str(p.message)}`,
        "error",
      );
    case "circuit_breaker":
      return view(
        "Circuit breaker",
        `${str(p.reason)} (${str(p.consecutive_failures) || "?"} consecutive failures)`,
        "error",
      );
    case "action": {
      const name = str(p.name);
      if (name === "complete") {
        const params = (p.params ?? {}) as Record<string, unknown>;
        const findings = Array.isArray(params.findings) ? params.findings : null;
        if (!findings) return view("Finished", "Agent finished.", "success");
        const titles = findings
          .map((f) => str((f as Record<string, unknown>)?.title))
          .filter(Boolean)
          .join(", ");
        return view(
          "Finished",
          `${findings.length} finding${findings.length === 1 ? "" : "s"}${titles ? `: ${titles}` : "."}`,
          "success",
        );
      }
      const target = actionTarget(p.params);
      return view("Action", target ? `${name}: ${target}` : name, "action");
    }
    case "observation": {
      const c = p.content;
      return view("Result", typeof c === "string" ? c : JSON.stringify(c ?? ""), "neutral");
    }
    case "approval_required":
      return view(
        "Approval requested",
        `${str(p.action_name)}${p.action_params_summary ? `: ${str(p.action_params_summary)}` : ""}`,
        "warning",
      );
    case "approval_decision":
      return p.approved
        ? view("Approved", str(p.reason) || "A reviewer approved the action.", "success")
        : view("Rejected by reviewer", str(p.reason) || "A reviewer rejected the action.", "blocked");
    case "guard_denial": {
      // `enforced` is recorded because "denied" alone is not evidence that
      // nothing ran. Say which one this was.
      const enforced = p.enforced !== false;
      const subject = str(p.action) || "Action";
      return view(
        enforced ? "Blocked by guard" : "Flagged by guard, not enforced",
        `${subject}: ${str(p.reason)}`,
        enforced ? "blocked" : "warning",
      );
    }
    case "tripwire_rejection": {
      const enforced = p.enforced !== false;
      const stage = STAGE_LABELS[str(p.stage)] ?? (str(p.stage) || "policy");
      const subject = str(p.action) || (p.stage === "prompt_scan" ? "Prompt" : "Action");
      return view(
        enforced ? `Blocked at ${stage}` : `Flagged at ${stage}, not enforced`,
        `${subject}: ${str(p.reason)}`,
        enforced ? "blocked" : "warning",
      );
    }
    case "cross_ledger_seal":
      return view("Sub-agent seal", `Seal ${short(p.seal_hash)}`, "evidence");
    case "anchor":
      return view(
        "Anchored",
        p.bitcoin_block_height != null
          ? `Ledger tip ${short(p.ledger_tip_hash)} in Bitcoin block ${str(p.bitcoin_block_height)}`
          : `Ledger tip ${short(p.ledger_tip_hash)} submitted; not yet confirmed in a block`,
        "evidence",
      );
    case "key_rotation":
      return view(
        "Signing key rotated",
        `Rotation ${str(p.rotation_index)}: new key ${short(p.new_public_key)}`,
        "evidence",
      );
    case "key_revocation":
      return view(
        "Signing key revoked",
        `${short(p.revoked_public_key)}: ${str(p.reason)}`,
        "error",
      );
    case "verifiable_credential":
      return view("Credential issued", `JWT ${short(p.vc_jwt, 40)}`, "evidence");
    case "data_receipt": {
      // Hashes only: which bytes the agent received, never the bytes.
      const hashes = Array.isArray(p.text_sha256) ? p.text_sha256 : [];
      const target = [str(p.tool), str(p.source)].filter(Boolean).join(": ");
      const first = hashes.length ? `, SHA-256 ${short(hashes[0])}` : "";
      return view(
        "Data received",
        `${target}\n${hashes.length} text(s), ${str(p.text_bytes) || "0"} bytes${first}`,
        "evidence",
      );
    }
    case "chat_message": {
      const role = str(p.role) || "unknown";
      const who =
        role === "user"
          ? "You"
          : [str(p.backend), str(p.model)].filter(Boolean).join(" / ") || "Model";
      return view(who, str(p.content), "chat");
    }
    default: {
      const rest = Object.fromEntries(Object.entries(p).filter(([k]) => k !== "type"));
      return view(formatEventType(type), JSON.stringify(rest, null, 2), "neutral");
    }
  }
}

/** True for events that record a refused or rejected action. */
export function isRefusal(v: EventView): boolean {
  return v.tone === "blocked";
}
