// Unit tests for SSEConnection.
//
// sse.ts wraps the browser's native EventSource rather than parsing
// `text/event-stream` bytes itself, so frame-level concerns (UTF-8 split
// across chunks, CRLF line endings, malformed `data:` JSON, comment/keepalive
// lines) are the browser's responsibility, not this module's - there is no
// parser here to exercise. What *is* this module's contract is the backoff,
// reconnect, and lifecycle policy around EventSource, which is what these
// tests cover. A 401 (or any other failure) reaches this code only as
// EventSource's generic `onerror`, so that is modelled as a plain error.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SSEConnection, SSE_BACKOFF_INITIAL_MS, SSE_BACKOFF_MAX_MS } from "./sse";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  static throwOnConstruct = false;

  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  private listeners = new Map<string, EventListener[]>();

  constructor(url: string) {
    if (FakeEventSource.throwOnConstruct) {
      throw new Error("EventSource disabled by CSP");
    }
    this.url = url;
    FakeEventSource.instances.push(this);
  }

  addEventListener(name: string, fn: EventListener): void {
    const list = this.listeners.get(name) ?? [];
    list.push(fn);
    this.listeners.set(name, list);
  }

  close(): void {
    this.closed = true;
  }

  emitOpen(): void {
    this.onopen?.();
  }

  emitMessage(data: string): void {
    this.onmessage?.(new MessageEvent("message", { data }));
  }

  emitNamed(name: string, data: string): void {
    for (const fn of this.listeners.get(name) ?? []) {
      fn(new MessageEvent(name, { data }));
    }
  }

  emitError(): void {
    this.onerror?.();
  }
}

function lastInstance(): FakeEventSource {
  const inst = FakeEventSource.instances[FakeEventSource.instances.length - 1];
  if (!inst) throw new Error("no EventSource instance was created");
  return inst;
}

beforeEach(() => {
  vi.useFakeTimers();
  FakeEventSource.instances = [];
  FakeEventSource.throwOnConstruct = false;
  vi.stubGlobal("EventSource", FakeEventSource);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("SSEConnection.connect", () => {
  it("opens an EventSource at the given url", () => {
    const conn = new SSEConnection({ url: "https://host/api/events" });
    conn.connect();
    expect(lastInstance().url).toBe("https://host/api/events");
    expect(conn.isOpen).toBe(true);
  });

  it("wires onMessage to the bare message handler", () => {
    const onMessage = vi.fn();
    const conn = new SSEConnection({ url: "u", onMessage });
    conn.connect();
    lastInstance().emitMessage("hello");
    expect(onMessage).toHaveBeenCalledTimes(1);
    expect(onMessage.mock.calls[0][0].data).toBe("hello");
  });

  it("wires named events via addEventListener", () => {
    const onEvent = vi.fn();
    const conn = new SSEConnection({ url: "u", events: { tick: onEvent } });
    conn.connect();
    lastInstance().emitNamed("tick", "42");
    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(onEvent.mock.calls[0][0].data).toBe("42");
  });

  it("calls onOpen and resets backoff when the stream opens", () => {
    const onOpen = vi.fn();
    const conn = new SSEConnection({ url: "u", onOpen });
    conn.connect();
    lastInstance().emitOpen();
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it("does not connect when shouldConnect returns false", () => {
    const conn = new SSEConnection({ url: "u", shouldConnect: () => false });
    conn.connect();
    expect(FakeEventSource.instances).toHaveLength(0);
    expect(conn.isOpen).toBe(false);
  });

  it("closes any previous EventSource before opening a new one", () => {
    const conn = new SSEConnection({ url: "u" });
    conn.connect();
    const first = lastInstance();
    conn.connect();
    expect(first.closed).toBe(true);
    expect(FakeEventSource.instances).toHaveLength(2);
  });

  it("treats a constructor failure (e.g. CSP) as an error with no reconnect", () => {
    FakeEventSource.throwOnConstruct = true;
    const onError = vi.fn();
    const onReconnectScheduled = vi.fn();
    const conn = new SSEConnection({ url: "u", onError, onReconnectScheduled });
    conn.connect();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onReconnectScheduled).not.toHaveBeenCalled();
    expect(conn.isOpen).toBe(false);
  });
});

describe("SSEConnection error / reconnect backoff", () => {
  it("schedules a reconnect at the initial backoff after the first error", () => {
    const onReconnectScheduled = vi.fn();
    const conn = new SSEConnection({ url: "u", onReconnectScheduled });
    conn.connect();
    lastInstance().emitError();
    expect(conn.isOpen).toBe(false);
    expect(onReconnectScheduled).toHaveBeenCalledWith(SSE_BACKOFF_INITIAL_MS);
  });

  it("doubles the backoff on each consecutive error, capped at the max", () => {
    const delays: number[] = [];
    const conn = new SSEConnection({
      url: "u",
      onReconnectScheduled: (ms) => delays.push(ms),
    });
    conn.connect();
    // Fail repeatedly without ever opening, letting each scheduled retry fire.
    for (let i = 0; i < 6; i++) {
      lastInstance().emitError();
      vi.advanceTimersByTime(delays[delays.length - 1]);
    }
    expect(delays).toEqual([2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
    expect(Math.max(...delays)).toBe(SSE_BACKOFF_MAX_MS);
  });

  it("resets backoff to the initial delay after a successful open", () => {
    const delays: number[] = [];
    const conn = new SSEConnection({
      url: "u",
      onReconnectScheduled: (ms) => delays.push(ms),
    });
    conn.connect();
    lastInstance().emitError();
    vi.advanceTimersByTime(delays[0]);
    lastInstance().emitOpen();
    lastInstance().emitError();
    expect(delays).toEqual([2_000, 2_000]);
  });

  it("suppresses the automatic reconnect when onError returns false", () => {
    const onReconnectScheduled = vi.fn();
    const conn = new SSEConnection({
      url: "u",
      onError: () => false,
      onReconnectScheduled,
    });
    conn.connect();
    lastInstance().emitError();
    expect(onReconnectScheduled).not.toHaveBeenCalled();
    vi.advanceTimersByTime(SSE_BACKOFF_MAX_MS);
    expect(FakeEventSource.instances).toHaveLength(1);
  });

  it("still reconnects when onError returns true or nothing", () => {
    const conn = new SSEConnection({ url: "u", onError: () => true });
    conn.connect();
    lastInstance().emitError();
    vi.advanceTimersByTime(SSE_BACKOFF_INITIAL_MS);
    expect(FakeEventSource.instances).toHaveLength(2);
  });
});

describe("SSEConnection lifecycle", () => {
  it("reconnectNow resets backoff and reconnects immediately, cancelling any pending timer", () => {
    const delays: number[] = [];
    const conn = new SSEConnection({
      url: "u",
      onReconnectScheduled: (ms) => delays.push(ms),
    });
    conn.connect();
    lastInstance().emitError();
    lastInstance(); // no-op; just keeping intent explicit
    conn.reconnectNow();
    expect(FakeEventSource.instances).toHaveLength(2);
    // The cancelled timer must not fire a second, unexpected reconnect.
    vi.advanceTimersByTime(SSE_BACKOFF_MAX_MS);
    expect(FakeEventSource.instances).toHaveLength(2);
  });

  it("suspend closes the stream and cancels a pending reconnect, but connect() still works afterwards", () => {
    const conn = new SSEConnection({ url: "u" });
    conn.connect();
    lastInstance().emitError();
    conn.suspend();
    vi.advanceTimersByTime(SSE_BACKOFF_MAX_MS);
    expect(FakeEventSource.instances).toHaveLength(1); // no reconnect fired
    conn.connect();
    expect(FakeEventSource.instances).toHaveLength(2);
    expect(conn.isOpen).toBe(true);
  });

  it("close is permanent: no further connect() calls open a new EventSource", () => {
    const conn = new SSEConnection({ url: "u" });
    conn.connect();
    conn.close();
    expect(lastInstance().closed).toBe(true);
    expect(conn.isOpen).toBe(false);
    conn.connect();
    expect(FakeEventSource.instances).toHaveLength(1);
  });

  it("close cancels a pending reconnect timer", () => {
    const conn = new SSEConnection({ url: "u" });
    conn.connect();
    lastInstance().emitError();
    conn.close();
    vi.advanceTimersByTime(SSE_BACKOFF_MAX_MS);
    expect(FakeEventSource.instances).toHaveLength(1);
  });

  it("a manual connect() cancels a pending reconnect", () => {
    const conn = new SSEConnection({ url: "u" });
    conn.connect();
    lastInstance().emitError();
    conn.connect();
    expect(FakeEventSource.instances).toHaveLength(2);
    vi.advanceTimersByTime(SSE_BACKOFF_MAX_MS);
    expect(FakeEventSource.instances).toHaveLength(2);
  });
});


describe("stale EventSource callbacks", () => {
  it("an error queued by an old source cannot close its replacement", () => {
    const onError = vi.fn();
    const connection = new SSEConnection({url: "u", onError});
    connection.connect();
    const old = lastInstance();
    connection.reconnectNow();
    const current = lastInstance();
    old.emitError();
    expect(current.closed).toBe(false);
    expect(onError).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
    connection.close();
  });
  it("late messages and opens from an old source are ignored", () => {
    const onMessage = vi.fn(), onOpen = vi.fn(), named = vi.fn();
    const connection = new SSEConnection({url: "u", onMessage, onOpen, events: {event: named}});
    connection.connect();
    const old = lastInstance();
    connection.reconnectNow();
    old.emitOpen();old.emitMessage("stale");old.emitNamed("event", "stale");
    expect(onMessage).not.toHaveBeenCalled();expect(onOpen).not.toHaveBeenCalled();expect(named).not.toHaveBeenCalled();
    connection.close();
  });
});
