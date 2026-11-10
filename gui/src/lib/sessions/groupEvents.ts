// Grouping ledger rows into the collapsed timeline History shows: identical
// events (same label and body) fold into one entry with an occurrence count,
// so a loop that fires the same action a dozen times reads as one line
// instead of a dozen.

import { describeEvent, type EventTone } from "../events";

export interface RawEvent {
  id?: number;
  sequence?: number;
  payload?: string | { type?: string; [k: string]: unknown };
  created_at?: string;
}

export interface GroupedEvent {
  key: string;
  label: string;
  content: string;
  tone: EventTone;
  /** Pretty-printed payload of the first occurrence, for the raw view. */
  raw: string;
  count: number;
  occurrences: { seq: number; timestamp: string; type: string }[];
}

export function rawPayloadJson(ev: RawEvent): string {
  const raw = ev.payload;
  if (typeof raw === "string") {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }
  return JSON.stringify(raw ?? ev, null, 2);
}

export function groupEvents(evs: RawEvent[]): GroupedEvent[] {
  const byKey = new Map<string, GroupedEvent>();
  for (const ev of evs) {
    const view = describeEvent(ev.payload);
    const content = view.text;
    const key = `${view.label}\n${content}`;
    const occ = {
      seq: (ev.sequence as number) ?? 0,
      timestamp: (ev.created_at as string) ?? "",
      type:
        (typeof ev.payload === "object" && ev.payload != null
          ? (ev.payload as { type?: string }).type
          : undefined) ?? "event",
    };
    if (byKey.has(key)) {
      const g = byKey.get(key)!;
      g.count += 1;
      g.occurrences.push(occ);
    } else {
      byKey.set(key, {
        key,
        label: view.label,
        content,
        tone: view.tone,
        raw: rawPayloadJson(ev),
        count: 1,
        occurrences: [occ],
      });
    }
  }
  return Array.from(byKey.values());
}
