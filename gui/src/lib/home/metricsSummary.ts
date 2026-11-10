/** Three numbers a first-time evaluator can read. Everything else stays in
 *  Prometheus. Sessions and events are ledger rows (`/api/metrics/security`
 *  counts them); denials are this server's counters. There is no whole-chain
 *  verdict here: nothing verifies every session on a timer, and a tile that
 *  said "OK" without measuring it was the previous design. Verify is per
 *  session, in History. */
export interface MetricsSummary {
  sessions: number;
  denials: number;
  events: number;
}

export function summarizeMetrics(metrics: Record<string, unknown> | null): MetricsSummary | null {
  if (!metrics) return null;
  const num = (k: string) => {
    const v = metrics[k];
    return typeof v === "number" ? v : Number(v) || 0;
  };
  return {
    sessions: num("total_sessions"),
    denials: num("guard_denials") + num("tripwire_rejections"),
    events: num("total_events"),
  };
}
