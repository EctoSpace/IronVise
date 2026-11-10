/**
 * The server streams ledger rows as *named* SSE frames (`event: event`, see
 * crates/host/src/server/stream.rs). A browser delivers those only to
 * `addEventListener("event", …)` listeners; `onmessage` sees unnamed frames
 * alone. Home once subscribed with `onmessage`, so its live feed never
 * received a row and silently fell back to nothing.
 *
 * The recording EventSource below keeps that delivery rule, which is why these
 * tests can fail for the right reason: `emit` on an unnamed frame never
 * reaches a named listener, and the reverse.
 */
import { expect, test, type Page } from "@playwright/test";

import { installTauriMock } from "./tauri-mock";

const SESSION_ID = "66666666-6666-4666-8666-666666666666";

async function installRecordingEventSource(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const win = window as unknown as Record<string, unknown>;
    const instances: RecordingEventSource[] = [];

    class RecordingEventSource {
      onopen: ((e: Event) => void) | null = null;
      onmessage: ((e: MessageEvent) => void) | null = null;
      onerror: ((e: Event) => void) | null = null;
      private listeners: Record<string, Array<(e: MessageEvent) => void>> = {};
      constructor(readonly url: string) {
        instances.push(this);
      }
      addEventListener(type: string, fn: (e: MessageEvent) => void) {
        (this.listeners[type] ??= []).push(fn);
      }
      removeEventListener() {}
      close() {}
      emit(type: string, data: string) {
        const e = new MessageEvent(type, { data });
        if (type === "message") this.onmessage?.(e);
        else for (const fn of this.listeners[type] ?? []) fn(e);
      }
    }

    win.EventSource = RecordingEventSource;
    win.__sseStreams = instances;
  });
}

async function emitToStream(page: Page, type: string, data: unknown): Promise<void> {
  await page.waitForFunction(
    () => ((window as unknown as { __sseStreams: unknown[] }).__sseStreams ?? []).length > 0,
  );
  await page.evaluate(
    ([t, payload]) => {
      const streams = (window as unknown as {
        __sseStreams: Array<{ emit(type: string, data: string): void }>;
      }).__sseStreams;
      streams[streams.length - 1].emit(t, payload);
    },
    [type, JSON.stringify(data)] as const,
  );
}

const OBSERVATION_ROW = {
  id: 8,
  sequence: 8,
  previous_hash: "f".repeat(64),
  content_hash: "1".repeat(64),
  payload: { type: "observation", content: "PermitRootLogin yes (streamed)" },
  created_at: "2026-01-01T00:00:00Z",
};

test.describe("live SSE feeds receive named `event` frames", () => {
  test("Home appends a streamed ledger row to the live feed", async ({ page }) => {
    await installTauriMock(page, {
      overrides: { run_prompt: { id: SESSION_ID, goal: "Audit", status: "running" } },
    });
    await installRecordingEventSource(page);
    await page.goto("/");

    await page.getByRole("button", { name: "Home", exact: true }).click();
    await page.getByPlaceholder("Enter agent goal…").fill("Audit server_config.txt");
    const run = page.getByRole("button", { name: "Run", exact: true });
    await expect(run).toBeEnabled();
    await run.click();

    await emitToStream(page, "event", OBSERVATION_ROW);

    await expect(page.getByText("PermitRootLogin yes (streamed)")).toBeVisible();
  });

  test("Live Feed lists a streamed ledger row", async ({ page }) => {
    await installTauriMock(page, { config: { show_developer_tools: true } });
    await installRecordingEventSource(page);
    await page.goto("/");

    await page.getByRole("button", { name: "Live Feed", exact: true }).click();

    await emitToStream(page, "event", OBSERVATION_ROW);

    await expect(page.getByText("PermitRootLogin yes (streamed)")).toBeVisible();
  });
});
