/**
 * IronViseClient - non-ASCII and URL-sensitive input.
 *
 * Ids, names and query values go into URLs, so each must arrive as exactly one
 * percent-encoded component: a `/`, `?`, `#` or `%` inside an id must not
 * change which resource is addressed. Goals, payloads and messages go into JSON
 * bodies and must survive the round trip byte for byte. `fetch` is stubbed.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { IronViseApiError, IronViseClient, IronViseUsageError } from "./client.js";

const BASE_URL = "http://localhost:3000";

const AWKWARD_IDS: Array<[label: string, id: string]> = [
  ["Latin-1 accents", "über-sessión"],
  ["emoji with ZWJ sequence", "🔥🚀-👩‍💻"],
  ["RTL text with an override mark", "שלום-مرحبا-\u202Eabc"],
  ["CJK", "日本語のセッション"],
  ["URL delimiters", "a b/c?d#e%f&g=h+i;j,k"],
  ["something that already looks encoded", "%2e%2e%2F%20"],
];

/** A placeholder that survives encodeURIComponent unchanged. */
const SLOT = "__ID__";

interface IdCase {
  name: string;
  /** The URL path (and query) with the id replaced by {@link SLOT}. */
  template: string;
  call: (c: IronViseClient, id: string) => Promise<unknown>;
}

const ID_METHODS: IdCase[] = [
  { name: "getSessionById", template: `/api/sessions/${SLOT}`, call: (c, id) => c.getSessionById(id) },
  { name: "sealSession", template: `/api/sessions/${SLOT}/seal`, call: (c, id) => c.sealSession(id) },
  { name: "getEvents", template: `/api/events?session_id=${SLOT}`, call: (c, id) => c.getEvents(id) },
  { name: "appendEvent", template: `/api/sessions/${SLOT}/events`, call: (c, id) => c.appendEvent(id, {}) },
  { name: "verifyIntent", template: `/api/sessions/${SLOT}/verify-intent`, call: (c, id) => c.verifyIntent(id, { action: "a" }) },
  { name: "verifyChain", template: `/api/sessions/${SLOT}/verify`, call: (c, id) => c.verifyChain(id) },
  { name: "verifySession", template: `/api/sessions/${SLOT}/verify`, call: (c, id) => c.verifySession(id) },
  { name: "proveCompliance", template: `/api/sessions/${SLOT}/compliance`, call: (c, id) => c.proveCompliance(id) },
  { name: "exportCertificate", template: `/api/certificates/${SLOT}`, call: (c, id) => c.exportCertificate(id) },
  { name: "getReport", template: `/api/reports/${SLOT}`, call: (c, id) => c.getReport(id) },
  { name: "getSessionVc", template: `/api/sessions/${SLOT}/vc`, call: (c, id) => c.getSessionVc(id) },
  { name: "verifySessionVc", template: `/api/sessions/${SLOT}/vc/verify`, call: (c, id) => c.verifySessionVc(id) },
  { name: "getPolicy", template: `/api/policies/${SLOT}`, call: (c, id) => c.getPolicy(id) },
  { name: "savePolicy", template: `/api/policies/${SLOT}`, call: (c, id) => c.savePolicy(id, "") },
  { name: "deletePolicy", template: `/api/policies/${SLOT}`, call: (c, id) => c.deletePolicy(id) },
  { name: "getPendingApproval", template: `/api/approvals/${SLOT}/pending`, call: (c, id) => c.getPendingApproval(id) },
  { name: "postApprovalDecision", template: `/api/approvals/${SLOT}`, call: (c, id) => c.postApprovalDecision(id, { gate_id: "g", approved: true }) },
  { name: "chat", template: `/api/sessions/${SLOT}/chat`, call: (c, id) => c.chat(id, "m") },
  { name: "deleteToken", template: `/api/tokens/${SLOT}`, call: (c, id) => c.deleteToken(id) },
  { name: "deleteWebhook", template: `/api/webhooks/${SLOT}`, call: (c, id) => c.deleteWebhook(id) },
  { name: "toggleWebhook", template: `/api/webhooks/${SLOT}`, call: (c, id) => c.toggleWebhook(id, true) },
];

/** A body every method in the tables accepts, whatever it reads. */
const anyOk = () =>
  new Response('{"ok":true,"pending":null}', { status: 200, headers: { "Content-Type": "application/json" } });

let client: IronViseClient;
let fetchSpy: MockInstance<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>;

beforeEach(() => {
  client = new IronViseClient({ baseUrl: BASE_URL });
  fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => anyOk());
});

afterEach(() => {
  vi.restoreAllMocks();
});

const requestedUrl = (): string => fetchSpy.mock.calls[0][0] as string;
const requestInit = (): RequestInit => fetchSpy.mock.calls[0][1] as RequestInit;
const sentJson = (): unknown => JSON.parse(requestInit().body as string);

describe.each(ID_METHODS)("$name encodes its id as one URL component", (m) => {
  it.each(AWKWARD_IDS)("%s", async (_label, id) => {
    await m.call(client, id);
    const url = requestedUrl();
    expect(url).toBe(`${BASE_URL}${m.template.replace(SLOT, encodeURIComponent(id))}`);

    // Parsed the way fetch parses it, the id is still one segment / one value.
    const parsed = new URL(url);
    const expected = new URL(`${BASE_URL}${m.template}`);
    expect(parsed.hash).toBe("");
    if (expected.search.includes(SLOT)) {
      expect(parsed.pathname).toBe(expected.pathname);
      expect(parsed.searchParams.get("session_id")).toBe(id);
    } else {
      const segments = parsed.pathname.split("/");
      const slot = expected.pathname.split("/").indexOf(SLOT);
      expect(segments).toHaveLength(expected.pathname.split("/").length);
      expect(decodeURIComponent(segments[slot])).toBe(id);
    }
  });
});

describe("ids that cannot be encoded or that URL parsing rewrites", () => {
  it("rejects a lone surrogate with URIError before any request is made", async () => {
    await expect(client.getSessionById("bad-\uD800-id")).rejects.toBeInstanceOf(URIError);
    await expect(client.deleteWebhook("\uDFFF")).rejects.toBeInstanceOf(URIError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // URL parsing resolves "." and ".." segments, so these ids would address the parent resource.
  it("rejects an id of '', '.' or '..' with IronViseUsageError before any request is made", async () => {
    for (const m of ID_METHODS) {
      if (m.template.includes("?")) continue;
      for (const id of ["", ".", ".."]) {
        await expect(m.call(client, id), `${m.name}(${JSON.stringify(id)})`).rejects.toBeInstanceOf(
          IronViseUsageError,
        );
      }
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("keeps an id that merely contains dots inside its own resource", async () => {
    for (const m of ID_METHODS) {
      if (m.template.includes("?")) continue;
      for (const id of ["a.b", "...", ".hidden", "..x", "x.."]) {
        fetchSpy.mockClear();
        await m.call(client, id);
        const expected = new URL(`${BASE_URL}${m.template}`).pathname;
        const segments = new URL(requestedUrl()).pathname.split("/");
        expect(segments).toHaveLength(expected.split("/").length);
        expect(decodeURIComponent(segments[expected.split("/").indexOf(SLOT)])).toBe(id);
      }
    }
  });
});

describe("query parameters", () => {
  it("listSessions round-trips a non-ASCII status filter", async () => {
    const status = "läuft / 実行中 & more";
    await client.listSessions({ status, limit: 5 });
    const parsed = new URL(requestedUrl());
    expect(parsed.searchParams.get("status")).toBe(status);
    expect(parsed.searchParams.get("limit")).toBe("5");
    expect([...parsed.searchParams.keys()]).toEqual(["limit", "status"]);
  });

  it("verifySessionVc encodes an audience full of URL delimiters", async () => {
    const audience = "https://verifier.example/a b?x=1&y=2#frag 🔐";
    await client.verifySessionVc("s", audience);
    const parsed = new URL(requestedUrl());
    expect(parsed.hash).toBe("");
    expect(parsed.searchParams.get("audience")).toBe(audience);
    expect([...parsed.searchParams.keys()]).toEqual(["audience"]);
  });

  it("streamEvents encodes a non-ASCII session_id filter", async () => {
    fetchSpy.mockResolvedValueOnce(new Response("", { status: 200 }));
    const sessionId = "séance #1 / 🧪";
    for await (const _ of client.streamEvents({ session_id: sessionId })) {
      // drain
    }
    const parsed = new URL(requestedUrl());
    expect(parsed.pathname).toBe("/api/stream");
    expect(parsed.hash).toBe("");
    expect(parsed.searchParams.get("session_id")).toBe(sessionId);
  });
});

const TRICKY_TEXT =
  "Prüfe 🔥 שלום مرحبا 日本語 \u202E rtl-override, \"quotes\" \\backslash\\ " +
  "</script> \u2028\u2029 line separators, NUL\u0000, combining e\u0301, 👩‍👩‍👧‍👦";

describe("JSON request bodies round-trip non-ASCII text", () => {
  it.each([
    ["createSession", (c: IronViseClient) => c.createSession({ goal: TRICKY_TEXT }), { goal: TRICKY_TEXT }],
    ["chat", (c: IronViseClient) => c.chat("s", TRICKY_TEXT), { message: TRICKY_TEXT }],
    [
      "verifyIntent",
      (c: IronViseClient) =>
        c.verifyIntent("s", { action: "read_file", params: { path: `/tmp/${TRICKY_TEXT}` }, justification: TRICKY_TEXT }),
      { action: "read_file", params: { path: `/tmp/${TRICKY_TEXT}` }, justification: TRICKY_TEXT, reasoning: "" },
    ],
    [
      "checkTripwire",
      (c: IronViseClient) => c.checkTripwire({ action: "run_command", params: { command: `echo ${TRICKY_TEXT}` } }),
      { action: "run_command", params: { command: `echo ${TRICKY_TEXT}` } },
    ],
    [
      "postApprovalDecision",
      (c: IronViseClient) => c.postApprovalDecision("s", { gate_id: "g-✓", approved: false, reason: TRICKY_TEXT }),
      { gate_id: "g-✓", approved: false, reason: TRICKY_TEXT },
    ],
    ["createToken", (c: IronViseClient) => c.createToken({ role: "agent", label: TRICKY_TEXT }), { role: "agent", label: TRICKY_TEXT }],
    [
      "createWebhook",
      (c: IronViseClient) => c.createWebhook({ label: TRICKY_TEXT, url: "https://xn--bcher-kva.example/hook" }),
      { label: TRICKY_TEXT, url: "https://xn--bcher-kva.example/hook" },
    ],
    ["updateConfig", (c: IronViseClient) => c.updateConfig({ active_policy: "politique-é" }), { active_policy: "politique-é" }],
  ])("%s", async (_name, call, expected) => {
    await call(client);
    expect(sentJson()).toEqual(expected);
    expect(requestInit().body).toBe(JSON.stringify(expected));
  });

  it("appendEvent sends a payload with non-ASCII keys and nested values unchanged", async () => {
    const payload = {
      "κλειδί 🔑": TRICKY_TEXT,
      nested: { "路径": ["/données/ファイル.txt", "C:\\Users\\Zoë"], n: 1.5, ok: true, nothing: null },
      "a/b?c#d%e": "url-ish key",
    };
    await client.appendEvent("s", payload);
    expect(sentJson()).toEqual(payload);
  });

  it("savePolicy sends non-ASCII TOML verbatim as text/plain", async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));
    const toml = `name = "règle-🔒"\ndescription = "${"\u05E9\u05DC\u05D5\u05DD"}"\n`;
    await client.savePolicy("règle-🔒", toml);
    expect(requestInit().body).toBe(toml);
    expect((requestInit().headers as Record<string, string>)["Content-Type"]).toBe("text/plain");
  });
});

describe("responses decode non-ASCII text", () => {
  it("parses raw UTF-8 and \\u escapes, surrogate pairs included, to the same strings", async () => {
    const goal = "Prüfe 🚀 שלום 日本語";
    const escaped = '{"id":"s","goal":"Pr\\u00fcfe \\ud83d\\ude80 \\u05e9\\u05dc\\u05d5\\u05dd \\u65e5\\u672c\\u8a9e"}';
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ id: "s", goal }), { status: 200 }));
    fetchSpy.mockResolvedValueOnce(new Response(escaped, { status: 200 }));
    expect((await client.getSessionById("s")).goal).toBe(goal);
    expect((await client.getSessionById("s")).goal).toBe(goal);
  });

  it("getPolicy and exportCertificate keep UTF-8 text and bytes intact", async () => {
    const text = `name = "règle-🔒"\n# שלום\n`;
    fetchSpy.mockResolvedValueOnce(new Response(text, { status: 200 }));
    fetchSpy.mockResolvedValueOnce(new Response(new TextEncoder().encode(text), { status: 200 }));
    expect(await client.getPolicy("p")).toBe(text);
    const blob = await client.exportCertificate("s");
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(new TextEncoder().encode(text));
  });

  it("streamEvents reassembles a multi-byte character split across chunks", async () => {
    const frame = new TextEncoder().encode('data: {"id":1,"payload":{"msg":"🔥 שלום"}}\n\n');
    // Cut inside the four bytes of the emoji, and again inside a Hebrew letter.
    const emojiAt = frame.indexOf(0xf0);
    const hebrewAt = frame.indexOf(0xd7);
    const cuts = [emojiAt + 2, hebrewAt + 1];
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(frame.slice(0, cuts[0]));
        controller.enqueue(frame.slice(cuts[0], cuts[1]));
        controller.enqueue(frame.slice(cuts[1]));
        controller.close();
      },
    });
    fetchSpy.mockResolvedValueOnce(new Response(body, { status: 200 }));
    const seen = [];
    for await (const ev of client.streamEvents()) seen.push(ev);
    expect(seen).toEqual([{ id: 1, payload: { msg: "🔥 שלום" } }]);
  });

  it("IronViseApiError keeps a non-ASCII error body whole", async () => {
    const body = "Sitzung nicht gefunden: 🔍 לא נמצא";
    fetchSpy.mockResolvedValueOnce(new Response(body, { status: 404 }));
    const err = (await client.getSessionById("über").catch((e: unknown) => e)) as IronViseApiError;
    expect(err.body).toBe(body);
    expect(err.message).toBe(
      `IronVise API GET ${BASE_URL}/api/sessions/${encodeURIComponent("über")} → 404: ${body}`,
    );
  });

  it("does not split a surrogate pair when it truncates the message", async () => {
    const body = `${"x".repeat(299)}🔥${"y".repeat(50)}`;
    fetchSpy.mockResolvedValueOnce(new Response(body, { status: 500 }));
    const err = (await client.getStatus().catch((e: unknown) => e)) as IronViseApiError;
    expect(err.body).toBe(body);
    const loneSurrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
    expect(err.message).not.toMatch(loneSurrogate);
  });
});
