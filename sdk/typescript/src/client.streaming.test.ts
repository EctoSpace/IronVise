import { afterEach, expect, it, vi } from "vitest";
import { IronViseClient } from "./client.js";

afterEach(() => vi.restoreAllMocks());

it.each(["\n", "\r\n", "\r"])("reads SSE with %j line endings across byte boundaries", async (nl) => {
  const body = `: keepalive${nl}${nl}event: delta${nl}data: {"text":${nl}data: "hé👋"}${nl}${nl}event: done${nl}data: {"reply":"hé👋","backend":"test","model":"test"}${nl}${nl}`;
  const bytes = new TextEncoder().encode(body);
  const response = new Response(new ReadableStream({start(c) {
    for (const byte of bytes) c.enqueue(Uint8Array.of(byte));
    c.close();
  }}));
  vi.spyOn(globalThis, "fetch").mockResolvedValue(response);
  const events = [];
  for await (const event of new IronViseClient().askStream("hi")) events.push(event);
  expect(events).toEqual([
    {type: "delta", text: "hé👋"},
    {type: "done", reply: "hé👋", backend: "test", model: "test"},
  ]);
});

it("preserves data line boundaries instead of turning malformed JSON into different values", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response('data: {"n":1\ndata: 2}\n\ndata: {"n":3}\n\n'));
  const events = [];
  for await (const event of new IronViseClient().streamEvents()) events.push(event);
  expect(events).toEqual([{n:3}]);
});

it("cancels the HTTP response body when the caller stops reading", async () => {
  const cancel = vi.fn();
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(new ReadableStream({
    start(c) {c.enqueue(new TextEncoder().encode('data: {"n":1}\n\n'));}, cancel,
  })));
  const events = new IronViseClient().streamEvents();
  expect((await events.next()).value).toEqual({n:1});
  await events.return();
  expect(cancel).toHaveBeenCalledOnce();
});
