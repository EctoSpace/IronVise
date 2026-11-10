/**
 * The Observer page (crates/host/src/index.html) takes its API token from a
 * postMessage when it is embedded without one in the URL. That message must
 * only be honoured from the Tauri webview that embeds it: any other page can
 * frame the Observer or open it, and would otherwise pick the token it runs
 * with.
 *
 * The real page is served from a routed 127.0.0.1 origin and framed by routed
 * parent origins, so no server or Tauri runtime is needed.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Frame, type Page } from "@playwright/test";

const OBSERVER_ORIGIN = "http://127.0.0.1:3000";
const TAURI_ORIGIN = "http://tauri.localhost";
const FOREIGN_ORIGIN = "http://evil.example";

const OBSERVER_HTML = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../../../crates/host/src/index.html"),
  "utf8",
);

const SESSION = {
  id: "77777777-7777-4777-8777-777777777777",
  goal: "Goal listed once a token is accepted",
  status: "completed",
  created_at: "2026-01-01T00:00:00Z",
};

/** Serve the Observer and record the Authorization header of each session listing. */
async function serveObserver(page: Page): Promise<string[]> {
  const listings: string[] = [];
  await page.route(`${OBSERVER_ORIGIN}/**`, async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/") {
      return route.fulfill({ contentType: "text/html", body: OBSERVER_HTML });
    }
    if (pathname === "/api/sessions") {
      listings.push(route.request().headers()["authorization"] ?? "");
      return route.fulfill({ contentType: "application/json", body: JSON.stringify([SESSION]) });
    }
    if (pathname === "/api/ping") {
      return route.fulfill({ body: "ok" });
    }
    return route.abort();
  });
  return listings;
}

interface Frames {
  page: Page;
  observer: Frame;
  sibling: Frame;
}

/** A page on `origin` that frames the Observer next to a same-origin sibling frame. */
async function openParent(page: Page, origin: string): Promise<Frames> {
  await page.route(`${origin}/`, (route) =>
    route.fulfill({
      contentType: "text/html",
      body: `<iframe id="observer" src="${OBSERVER_ORIGIN}/"></iframe><iframe id="sibling" srcdoc=""></iframe>`,
    }),
  );
  await page.goto(`${origin}/`);
  const observer = await (await page.waitForSelector("#observer")).contentFrame();
  const sibling = await (await page.waitForSelector("#sibling")).contentFrame();
  if (!observer || !sibling) throw new Error("frames did not attach");
  await observer.waitForLoadState("domcontentloaded");
  return { page, observer, sibling };
}

/**
 * Deliver the token message from the parent page or its sibling frame, then a
 * marker message. The marker's listener is registered after the Observer's
 * own, so once it has fired the token message has been handled.
 */
async function sendToken({ page, observer, sibling }: Frames, from: "parent" | "sibling"): Promise<void> {
  await observer.evaluate(() => {
    (window as unknown as { synced: Promise<void> }).synced = new Promise((resolve) => {
      window.addEventListener("message", (e) => {
        if (e.data?.type === "sync") resolve();
      });
    });
  });
  const sender = from === "parent" ? page.mainFrame() : sibling;
  await sender.evaluate(() => {
    const observerWindow = (window.parent === window ? window : window.parent).frames[0];
    observerWindow.postMessage({ type: "ectoledgerSetToken", token: "injected-token" }, "*");
    observerWindow.postMessage({ type: "sync" }, "*");
  });
  await observer.evaluate(() => (window as unknown as { synced: Promise<void> }).synced);
  await observer.evaluate(() => fetch("/api/ping"));
}

test.describe("Observer token postMessage", () => {
  test("is accepted from a Tauri webview origin", async ({ page }) => {
    const listings = await serveObserver(page);
    const frames = await openParent(page, TAURI_ORIGIN);

    await sendToken(frames, "parent");

    await expect(frames.observer.getByText(SESSION.goal)).toBeVisible();
    expect(listings).toEqual(["Bearer injected-token"]);
  });

  test("is ignored from any other origin", async ({ page }) => {
    const listings = await serveObserver(page);
    const frames = await openParent(page, FOREIGN_ORIGIN);

    await sendToken(frames, "parent");

    expect(listings).toEqual([]);
    await expect(frames.observer.getByText(SESSION.goal)).toHaveCount(0);
  });

  test("is ignored from a sibling frame, even on a trusted origin", async ({ page }) => {
    const listings = await serveObserver(page);
    const frames = await openParent(page, TAURI_ORIGIN);

    await sendToken(frames, "sibling");

    expect(listings).toEqual([]);
  });
});
