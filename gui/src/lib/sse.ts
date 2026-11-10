// Shared Server-Sent-Events connection with exponential-backoff reconnect.
//
// Reconnect policy: 2 s initial delay, doubling on each failure, capped at 30 s, reset
// on a successful open. A new `connect()` always closes the previous
// EventSource first, so a connection can never leak.

export const SSE_BACKOFF_INITIAL_MS = 2_000;
export const SSE_BACKOFF_MAX_MS = 30_000;

export interface SSEOptions {
  /** Absolute URL of the stream (including any ?token=… query parameter). */
  url: string;
  /** Handler for bare `message` frames. */
  onMessage?: (e: MessageEvent) => void;
  /** Handlers for named SSE event types (e.g. "event"). */
  events?: Record<string, (e: MessageEvent) => void>;
  onOpen?: () => void;
  /**
   * Called after the connection errors (the EventSource is already closed).
   * Return `false` to suppress the automatic backoff reconnect - e.g. to
   * fall back to polling instead. Any other return value keeps the default
   * reconnect behaviour.
   */
  onError?: () => boolean | void;
  /** Gate checked before every (re)connect attempt; return false to skip. */
  shouldConnect?: () => boolean;
  /** Notified when a reconnect has been scheduled, with the delay in ms. */
  onReconnectScheduled?: (delayMs: number) => void;
}

export class SSEConnection {
  private source: EventSource | null = null;
  private backoffMs = SSE_BACKOFF_INITIAL_MS;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private closed = false;

  constructor(private opts: SSEOptions) {}

  get isOpen(): boolean {
    return this.source !== null;
  }

  /** Open the stream, closing any previous EventSource first. */
  connect(): void {
    if (this.closed) return;
    if (this.opts.shouldConnect && !this.opts.shouldConnect()) return;
    this.clearTimer();
    this.disconnect();

    let es: EventSource;
    try {
      es = new EventSource(this.opts.url);
    } catch {
      // EventSource unavailable (e.g. restrictive CSP) - treat as an error
      // with no reconnect; the caller's onError may switch to polling.
      this.opts.onError?.();
      return;
    }
    this.source = es;

    es.onopen = () => {
      if (this.source !== es) return;
      this.backoffMs = SSE_BACKOFF_INITIAL_MS;
      this.opts.onOpen?.();
    };
    if (this.opts.onMessage) es.onmessage = (event) => {
      if (this.source === es) this.opts.onMessage?.(event);
    };
    for (const [name, fn] of Object.entries(this.opts.events ?? {})) {
      es.addEventListener(name, ((event: MessageEvent) => {
        if (this.source === es) fn(event);
      }) as EventListener);
    }
    es.onerror = () => {
      if (this.source !== es) return;
      this.disconnect();
      const keep = this.opts.onError?.();
      if (keep === false || this.closed || this.source !== null) return;
      const delay = this.backoffMs;
      this.backoffMs = Math.min(this.backoffMs * 2, SSE_BACKOFF_MAX_MS);
      this.opts.onReconnectScheduled?.(delay);
      if (this.closed || this.source !== null) return;
      this.timer = setTimeout(() => this.connect(), delay);
    };
  }

  /** Reset backoff and reconnect immediately (e.g. tab became visible). */
  reconnectNow(): void {
    if (this.closed) return;
    this.backoffMs = SSE_BACKOFF_INITIAL_MS;
    this.connect();
  }

  /**
   * Close the current EventSource and cancel any pending reconnect, but keep
   * the connection reusable via `connect()`/`reconnectNow()` (e.g. tab
   * hidden).
   */
  suspend(): void {
    this.clearTimer();
    this.disconnect();
  }

  /** Permanently close the stream and cancel any scheduled reconnect. */
  close(): void {
    this.closed = true;
    this.clearTimer();
    this.disconnect();
  }

  private disconnect(): void {
    this.source?.close();
    this.source = null;
  }

  private clearTimer(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
