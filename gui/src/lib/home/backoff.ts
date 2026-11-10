// Backoff schedules for Home's two pollers: the metrics tile (always
// running) and the live-session fallback poll (only while SSE is down).

/** Metrics poll delay: steady at 10s, then doubling from the 3rd consecutive
 *  error up to a 60s ceiling, so a backend outage does not hammer it. */
export function metricsPollDelay(errorCount: number): number {
  return errorCount >= 3 ? Math.min(10_000 * Math.pow(2, errorCount - 2), 60_000) : 10_000;
}

/** Session event poll delay: 2s base, doubling on consecutive empty
 *  responses, capped at 16s. */
export function sessionPollDelay(noNewEventsCount: number): number {
  const baseMs = 2000;
  return Math.min(baseMs * Math.pow(2, noNewEventsCount), 16000);
}
