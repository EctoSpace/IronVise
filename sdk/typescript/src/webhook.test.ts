/**
 * Webhook verifier - Vitest test suite.
 *
 * The cases come from `sdk/fixtures/webhook-v1.json`, which the Rust server's
 * own test generates and pins. The Python SDK reads the same file, so the
 * server and both verifiers agree on the scheme by construction rather than by
 * three people reading the same paragraph. Nothing here needs a network.
 */

import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { MemoryReplayCache, deriveReceiverKey, verifyWebhook } from "./webhook.js";
import type { ReplayCache, VerifyWebhookOptions, WebhookVerdict } from "./webhook.js";

interface FixtureCase {
  name: string;
  receiver_url: string;
  receiver_key: string;
  headers: Record<string, string>;
  body: string;
  now: number;
  expect: "ok" | "missing_headers" | "stale" | "bad_signature" | "replayed";
}

interface Fixture {
  scheme: string;
  secret: string;
  tolerance_secs: number;
  cases: FixtureCase[];
  replay: { case: string; presentations: number; expect: string[] };
}

const fixturePath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../fixtures/webhook-v1.json",
);
const fixture: Fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

const byName = (name: string): FixtureCase => {
  const found = fixture.cases.find((c) => c.name === name);
  if (!found) throw new Error(`fixture has no case named ${JSON.stringify(name)}`);
  return found;
};

/** A cache whose clock is pinned, so a fixed fixture timestamp never ages out. */
const cacheAt = (now: number): MemoryReplayCache => new MemoryReplayCache(() => now);

const run = (c: FixtureCase, cache: ReplayCache): WebhookVerdict =>
  verifyWebhook({
    receiverKey: c.receiver_key,
    receiverUrl: c.receiver_url,
    headers: c.headers,
    body: c.body,
    now: c.now,
    toleranceSecs: fixture.tolerance_secs,
    cache,
  });

/** The reason a verdict was refused, or "ok". */
const outcome = (v: WebhookVerdict): string => (v.ok ? "ok" : v.reason);

describe("webhook fixture", () => {
  it("is the v1 scheme and has cases to run", () => {
    expect(fixture.scheme).toBe("ectoledger-webhook-v1");
    expect(fixture.cases.length).toBeGreaterThanOrEqual(6);
    expect(fixture.tolerance_secs).toBe(300);
  });

  it.each(fixture.cases.map((c) => [c.name, c] as const))(
    "%s",
    (_name, c) => {
      const verdict = run(c, cacheAt(c.now));
      expect(outcome(verdict)).toBe(c.expect);
      if (verdict.ok) {
        expect(verdict.deliveryId).toBe(c.headers["X-EctoLedger-Delivery"]);
      }
    },
  );

  it("derives every receiver key the server derived", () => {
    for (const c of fixture.cases) {
      expect(deriveReceiverKey(fixture.secret, c.receiver_url)).toBe(c.receiver_key);
    }
    // ...and the same bytes give the same key.
    const bytes = new TextEncoder().encode(fixture.secret);
    const c = byName("valid");
    expect(deriveReceiverKey(bytes, c.receiver_url)).toBe(c.receiver_key);
  });

  it("gives two receivers two different keys", () => {
    expect(byName("valid").receiver_key).not.toBe(
      byName("presented to another receiver").receiver_key,
    );
  });

  it("refuses the second presentation of the same delivery", () => {
    const c = byName(fixture.replay.case);
    const cache = cacheAt(c.now);
    const seen: string[] = [];
    for (let i = 0; i < fixture.replay.presentations; i += 1) {
      seen.push(outcome(run(c, cache)));
    }
    expect(seen).toEqual(fixture.replay.expect);
    expect(seen).toEqual(["ok", "replayed"]);
  });
});

// Behaviour the fixture does not spell out.
describe("verifyWebhook", () => {
  const valid = byName("valid");

  it("does not let a forged delivery block the genuine one", () => {
    const cache = cacheAt(valid.now);
    const forged = {
      ...valid.headers,
      "X-EctoLedger-Signature-V1": "00".repeat(32),
    };
    // Same delivery id as the genuine delivery, signature made up.
    const first = verifyWebhook({
      receiverKey: valid.receiver_key,
      receiverUrl: valid.receiver_url,
      headers: forged,
      body: valid.body,
      now: valid.now,
      cache,
    });
    expect(first).toEqual({ ok: false, reason: "bad_signature" });
    expect(cache.size).toBe(0);
    expect(outcome(run(valid, cache))).toBe("ok");
  });

  it("does not spend the id on a stale delivery either", () => {
    const cache = cacheAt(valid.now);
    const stale = { ...valid, now: valid.now + 10_000 };
    expect(outcome(run(stale, cache))).toBe("stale");
    expect(cache.size).toBe(0);
    expect(outcome(run(valid, cache))).toBe("ok");
  });

  it("finds headers whatever case the framework gave them", () => {
    const lower = Object.fromEntries(
      Object.entries(valid.headers).map(([k, v]) => [k.toLowerCase(), v]),
    );
    const shouting = Object.fromEntries(
      Object.entries(valid.headers).map(([k, v]) => [k.toUpperCase(), v]),
    );
    for (const headers of [lower, shouting]) {
      const verdict = verifyWebhook({
        receiverKey: valid.receiver_key,
        receiverUrl: valid.receiver_url,
        headers,
        body: valid.body,
        now: valid.now,
        cache: cacheAt(valid.now),
      });
      expect(verdict).toEqual({
        ok: true,
        deliveryId: valid.headers["X-EctoLedger-Delivery"],
      });
    }
  });

  it("accepts a fetch Headers object", () => {
    const verdict = verifyWebhook({
      receiverKey: valid.receiver_key,
      receiverUrl: valid.receiver_url,
      headers: new Headers(valid.headers),
      body: valid.body,
      now: valid.now,
      cache: cacheAt(valid.now),
    });
    expect(verdict.ok).toBe(true);
  });

  it("accepts Node-style single-element array values, refuses repeated ones", () => {
    const wrapped = Object.fromEntries(
      Object.entries(valid.headers).map(([k, v]) => [k.toLowerCase(), [v]]),
    );
    const verify = (headers: Record<string, string[] | undefined>) =>
      verifyWebhook({
        receiverKey: valid.receiver_key,
        receiverUrl: valid.receiver_url,
        headers,
        body: valid.body,
        now: valid.now,
        cache: cacheAt(valid.now),
      });
    expect(verify(wrapped).ok).toBe(true);
    expect(
      verify({ ...wrapped, "x-ectoledger-delivery": ["a", "b"] }),
    ).toEqual({ ok: false, reason: "missing_headers" });
  });

  it.each(["X-EctoLedger-Delivery", "X-EctoLedger-Timestamp", "X-EctoLedger-Signature-V1"])(
    "reports missing_headers when %s is absent",
    (name) => {
      const headers: Record<string, string | undefined> = { ...valid.headers };
      delete headers[name];
      expect(
        verifyWebhook({
          receiverKey: valid.receiver_key,
          receiverUrl: valid.receiver_url,
          headers,
          body: valid.body,
          now: valid.now,
          cache: cacheAt(valid.now),
        }),
      ).toEqual({ ok: false, reason: "missing_headers" });
    },
  );

  it.each([
    "",
    "abc",
    "1.5",
    "1e9",
    "0x10",
    " 1790700000",
    "1790700000 ",
    "1".repeat(5000),
  ])(
    "reports missing_headers for a timestamp that is not an i64 (%#)",
    (timestamp) => {
      expect(
        verifyWebhook({
          receiverKey: valid.receiver_key,
          receiverUrl: valid.receiver_url,
          headers: { ...valid.headers, "X-EctoLedger-Timestamp": timestamp },
          body: valid.body,
          now: valid.now,
          cache: cacheAt(valid.now),
        }),
      ).toEqual({ ok: false, reason: "missing_headers" });
    },
  );

  it("checks the timestamp before the signature", () => {
    // A tampered body *and* an old timestamp: the cheap check answers first.
    const c = { ...valid, body: "{}", now: valid.now + 10_000 };
    expect(outcome(run(c, cacheAt(c.now)))).toBe("stale");
  });

  it("accepts exactly the tolerance and refuses one second more", () => {
    const sentAt = Number(valid.headers["X-EctoLedger-Timestamp"]);
    const tol = fixture.tolerance_secs;
    expect(outcome(run({ ...valid, now: sentAt + tol }, cacheAt(sentAt + tol)))).toBe("ok");
    expect(outcome(run({ ...valid, now: sentAt - tol }, cacheAt(sentAt - tol)))).toBe("ok");
    expect(outcome(run({ ...valid, now: sentAt + tol + 1 }, cacheAt(sentAt)))).toBe("stale");
  });

  it("honours a custom tolerance", () => {
    const verify = (toleranceSecs: number) =>
      verifyWebhook({
        receiverKey: valid.receiver_key,
        receiverUrl: valid.receiver_url,
        headers: valid.headers,
        body: valid.body,
        now: valid.now, // ten seconds after the delivery was signed
        toleranceSecs,
        cache: cacheAt(valid.now),
      });
    expect(verify(5)).toEqual({ ok: false, reason: "stale" });
    expect(verify(10).ok).toBe(true);
  });

  it("compares the signature exactly: case and length both matter", () => {
    const sig = valid.headers["X-EctoLedger-Signature-V1"];
    for (const bad of [sig.toUpperCase(), sig.slice(0, -2), `${sig}00`, sig.replace(/^./, "0")]) {
      const verdict = verifyWebhook({
        receiverKey: valid.receiver_key,
        receiverUrl: valid.receiver_url,
        headers: { ...valid.headers, "X-EctoLedger-Signature-V1": bad },
        body: valid.body,
        now: valid.now,
        cache: cacheAt(valid.now),
      });
      expect(verdict).toEqual({ ok: false, reason: "bad_signature" });
    }
  });

  it("binds the signature to the id and the timestamp", () => {
    const swapped = [
      { "X-EctoLedger-Delivery": "3f2b8c1e-5d4a-4c3b-9e8f-7a6b5c4d3e30" },
      { "X-EctoLedger-Timestamp": "1790700001" },
    ];
    for (const change of swapped) {
      const verdict = verifyWebhook({
        receiverKey: valid.receiver_key,
        receiverUrl: valid.receiver_url,
        headers: { ...valid.headers, ...change },
        body: valid.body,
        now: valid.now,
        cache: cacheAt(valid.now),
      });
      expect(verdict).toEqual({ ok: false, reason: "bad_signature" });
    }
  });

  it("remembers an accepted id until timestamp + tolerance", () => {
    const added: Array<[string, number]> = [];
    const cache: ReplayCache = {
      has: () => false,
      add: (id, expiresAt) => void added.push([id, expiresAt]),
    };
    expect(outcome(run(valid, cache))).toBe("ok");
    expect(added).toEqual([
      [valid.headers["X-EctoLedger-Delivery"], 1790700000 + fixture.tolerance_secs],
    ]);
  });

  it("uses the system clock when `now` is not given", () => {
    // Signed here, independently of the module under test, following the spec.
    const url = "https://siem.example/ectoledger";
    const key = deriveReceiverKey(fixture.secret, url);
    const id = "clock-test-delivery";
    const ts = String(Math.floor(Date.now() / 1000));
    const body = '{"live":true}';
    const sig = createHmac("sha256", Buffer.from(key, "hex"))
      .update(["ectoledger-webhook-v1", id, ts, url, body].join("\n"))
      .digest("hex");
    const headers = {
      "X-EctoLedger-Delivery": id,
      "X-EctoLedger-Timestamp": ts,
      "X-EctoLedger-Signature-V1": sig,
    };
    const cache = new MemoryReplayCache();
    const verify = () =>
      verifyWebhook({ receiverKey: key, receiverUrl: url, headers, body, cache });
    expect(verify()).toEqual({ ok: true, deliveryId: id });
    expect(verify()).toEqual({ ok: false, reason: "replayed" });
  });

  it("throws on a receiver key that is not 64 hex characters", () => {
    for (const receiverKey of ["", "abc", "zz".repeat(32), valid.receiver_key + "00"]) {
      expect(() =>
        verifyWebhook({
          receiverKey,
          receiverUrl: valid.receiver_url,
          headers: valid.headers,
          body: valid.body,
          now: valid.now,
          cache: cacheAt(valid.now),
        }),
      ).toThrow(TypeError);
    }
  });
});

describe("MemoryReplayCache", () => {
  it("remembers an id until its expiry, then forgets it", () => {
    let now = 1000;
    const cache = new MemoryReplayCache(() => now);
    cache.add("a", 1300);
    expect(cache.has("a")).toBe(true);
    expect(cache.has("b")).toBe(false);

    now = 1300; // the expiry second itself still counts: the delivery is still fresh
    expect(cache.has("a")).toBe(true);

    now = 1301;
    expect(cache.has("a")).toBe(false);
  });

  it("evicts expired ids so memory does not grow without bound", () => {
    let now = 1000;
    const cache = new MemoryReplayCache(() => now);
    cache.add("a", 1100);
    cache.add("b", 1200);
    cache.add("c", 1300);
    expect(cache.size).toBe(3);

    now = 1150;
    expect(cache.size).toBe(2);
    now = 1250;
    expect(cache.size).toBe(1);
    now = 5000;
    expect(cache.size).toBe(0);
  });

  it("sweeps on add, so a receiver that never asks for size stays bounded", () => {
    let now = 0;
    const cache = new MemoryReplayCache(() => now);
    for (let i = 0; i < 100; i += 1) {
      now = i * 10;
      cache.add(`id-${i}`, now + 300);
    }
    // Only the ids from the last 300 seconds are still held.
    expect(cache.size).toBeLessThanOrEqual(31);
  });

  it("forgets an accepted id once its window has passed", () => {
    // In practice the timestamp check refuses a delivery that old first; the
    // cache alone must not hold ids forever.
    const c = byName("valid");
    let now = c.now;
    const cache = new MemoryReplayCache(() => now);
    expect(outcome(run(c, cache))).toBe("ok");
    expect(outcome(run(c, cache))).toBe("replayed");
    now = c.now + 400;
    expect(cache.has(c.headers["X-EctoLedger-Delivery"])).toBe(false);
  });

  it("defaults to the system clock", () => {
    const cache = new MemoryReplayCache();
    const nowSecs = Math.floor(Date.now() / 1000);
    cache.add("future", nowSecs + 60);
    cache.add("past", nowSecs - 60);
    expect(cache.has("future")).toBe(true);
    expect(cache.has("past")).toBe(false);
  });
});

describe("verifyWebhook edge cases", () => {
  const url = "https://siem.example/ectoledger";
  const key = deriveReceiverKey(fixture.secret, url);
  const NOW = 1_790_700_000;

  /** Sign a delivery independently of the module under test, following the spec. */
  const sign = (body: string, opts: { id?: string; ts?: number; signingKey?: string; signedUrl?: string } = {}) => {
    const id = opts.id ?? "edge-delivery-1";
    const ts = String(opts.ts ?? NOW);
    const sig = createHmac("sha256", Buffer.from(opts.signingKey ?? key, "hex"))
      .update(["ectoledger-webhook-v1", id, ts, opts.signedUrl ?? url, body].join("\n"))
      .digest("hex");
    return {
      "X-EctoLedger-Delivery": id,
      "X-EctoLedger-Timestamp": ts,
      "X-EctoLedger-Signature-V1": sig,
    } as Record<string, string | string[] | undefined>;
  };

  const verify = (
    headers: VerifyWebhookOptions["headers"],
    body: string,
    over: Partial<VerifyWebhookOptions> = {},
  ) =>
    verifyWebhook({
      receiverKey: key,
      receiverUrl: url,
      headers,
      body,
      now: NOW,
      cache: cacheAt(NOW),
      ...over,
    });

  it.each([
    ["emoji and ZWJ sequences", '{"msg":"🔥 👩‍💻 deploy"}'],
    ["RTL text and an override mark", '{"msg":"שלום مرحبا ‮evil.exe"}'],
    ["CJK", '{"msg":"日本語のイベント"}'],
    ["raw line and paragraph separators", '{"msg":"a b c"}'],
    ["newlines, which also separate the signed fields", "line1\nline2\n\nline4\n"],
    ["an empty body", ""],
  ])("accepts a correctly signed body with %s", (_label, body) => {
    expect(verify(sign(body), body)).toEqual({ ok: true, deliveryId: "edge-delivery-1" });
  });

  it("refuses a unicode body re-normalised in transit (NFC signed, NFD received)", () => {
    const signed = '{"name":"Zoë Café"}'.normalize("NFC");
    const received = signed.normalize("NFD");
    expect(received).not.toBe(signed);
    expect(verify(sign(signed), received)).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("refuses a body that was parsed and re-serialised", () => {
    const body = '{"event_kind":"tripwire_rejection","session_id":"s1"}';
    const headers = sign(body);
    for (const reserialised of [
      JSON.stringify(JSON.parse(body), null, 2),
      `${body}\n`,
      ` ${body}`,
      body.replace("s1", "s1 "),
    ]) {
      expect(verify(headers, reserialised)).toEqual({ ok: false, reason: "bad_signature" });
    }
  });

  it("refuses a delivery signed under a key derived from another secret", () => {
    const wrongKey = deriveReceiverKey(`${fixture.secret}-rotated`, url);
    expect(wrongKey).not.toBe(key);
    const cache = cacheAt(NOW);
    const body = '{"x":1}';
    expect(verify(sign(body, { signingKey: wrongKey }), body, { cache })).toEqual({
      ok: false,
      reason: "bad_signature",
    });
    expect(cache.size).toBe(0);
  });

  it("refuses when the receiver is configured with the wrong secret's key", () => {
    const body = '{"x":1}';
    const wrongKey = deriveReceiverKey("not-the-server-secret", url);
    expect(verify(sign(body), body, { receiverKey: wrongKey })).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it.each([`${url}/`, url.toUpperCase(), url.replace("https", "http"), `${url}?a=1`])(
    "binds the signature to the exact receiver URL (%s)",
    (otherUrl) => {
      const body = '{"x":1}';
      expect(verify(sign(body), body, { receiverUrl: otherUrl })).toEqual({
        ok: false,
        reason: "bad_signature",
      });
    },
  );

  it("accepts a receiver key written in upper-case hex", () => {
    const body = '{"x":1}';
    expect(verify(sign(body), body, { receiverKey: key.toUpperCase() }).ok).toBe(true);
  });

  it.each([
    ["an empty signature", { "X-EctoLedger-Signature-V1": "" }],
    ["an empty delivery id", { "X-EctoLedger-Delivery": "" }],
    ["an undefined header value", { "X-EctoLedger-Signature-V1": undefined }],
    ["an empty header array", { "X-EctoLedger-Timestamp": [] }],
  ])("reports missing_headers for %s", (_label, change) => {
    const body = '{"x":1}';
    expect(verify({ ...sign(body), ...change }, body)).toEqual({
      ok: false,
      reason: "missing_headers",
    });
  });

  it.each([
    ["64 characters that are not hex", "g".repeat(64)],
    ["64 bytes of non-ASCII (32 × 'é')", "é".repeat(32)],
    ["the right signature for a different body", null],
  ])("reports bad_signature, without throwing, for %s", (_label, sig) => {
    const body = '{"x":1}';
    const forged = sig ?? (sign('{"x":2}')["X-EctoLedger-Signature-V1"] as string);
    expect(() => verify({ ...sign(body), "X-EctoLedger-Signature-V1": forged }, body)).not.toThrow();
    expect(verify({ ...sign(body), "X-EctoLedger-Signature-V1": forged }, body)).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it.each([
    ["from the future, past the tolerance", NOW + 301],
    ["negative", -1],
    ["the epoch", 0],
    ["the largest i64", "9223372036854775807"],
    ["the smallest i64", "-9223372036854775808"],
  ])("reports stale for a timestamp %s", (_label, ts) => {
    const body = '{"x":1}';
    const headers = { ...sign(body, { ts: Number(ts) }), "X-EctoLedger-Timestamp": String(ts) };
    expect(verify(headers, body)).toEqual({ ok: false, reason: "stale" });
  });

  it("with toleranceSecs 0 accepts only the exact second", () => {
    const body = '{"x":1}';
    const headers = sign(body);
    expect(verify(headers, body, { toleranceSecs: 0 }).ok).toBe(true);
    expect(verify(headers, body, { toleranceSecs: 0, now: NOW + 1 })).toEqual({
      ok: false,
      reason: "stale",
    });
  });

  it("refuses a tampered body even when every header is genuine and fresh", () => {
    const body = '{"event_kind":"guard_denial","enforced":true}';
    const tampered = body.replace("true", "false");
    const cache = cacheAt(NOW);
    expect(verify(sign(body), tampered, { cache })).toEqual({ ok: false, reason: "bad_signature" });
    expect(verify(sign(body), body, { cache }).ok).toBe(true);
  });
});
