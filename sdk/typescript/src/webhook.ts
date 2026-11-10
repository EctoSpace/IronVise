/**
 * Receiver-side verification of IronVise webhook deliveries
 * (scheme `ectoledger-webhook-v1`).
 *
 * When the server has `WEBHOOK_HMAC_SECRET` set, every POST carries:
 *
 *  - `X-EctoLedger-Delivery`     a unique id for this delivery,
 *  - `X-EctoLedger-Timestamp`    unix seconds, as a decimal string,
 *  - `X-EctoLedger-Signature-V1` 64 lowercase hex characters.
 *
 * The signature is `HMAC-SHA256` under the *receiver's own key* over
 * `"ectoledger-webhook-v1" \n id \n timestamp \n receiverUrl \n body`. That key
 * is derived from the server secret and the receiver's URL, so a delivery
 * captured at one receiver fails at every other, and no receiver can sign a
 * delivery for another. Get yours with `ironvise webhook-key --url <url>`.
 *
 * Pinned to `sdk/fixtures/webhook-v1.json`, which the Rust server generates.
 *
 * Node, Deno and Bun only: it uses `node:crypto`. A webhook receiver is a
 * server, so nothing here is meant to run in a browser.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/** Domain separation for the two uses of the server secret. */
const RECEIVER_KEY_CONTEXT = "ectoledger-webhook-key-v1";
const SIGNATURE_CONTEXT = "ectoledger-webhook-v1";

/** How far `X-EctoLedger-Timestamp` may drift from the receiver's clock. */
const DEFAULT_TOLERANCE_SECS = 300;

const HEADER_DELIVERY = "x-ectoledger-delivery";
const HEADER_TIMESTAMP = "x-ectoledger-timestamp";
const HEADER_SIGNATURE = "x-ectoledger-signature-v1";

/** Why a delivery was refused. */
export type WebhookRejection =
  | "missing_headers"
  | "stale"
  | "bad_signature"
  | "replayed";

/** The outcome of {@link verifyWebhook}. */
export type WebhookVerdict =
  | { ok: true; deliveryId: string }
  | { ok: false; reason: WebhookRejection };

/**
 * Remembers delivery ids so a captured delivery cannot be presented twice.
 *
 * Both methods are synchronous on purpose: {@link verifyWebhook} checks and
 * then records the id with no `await` in between, so two concurrent requests
 * with the same id cannot both pass. A shared store (Redis, a database) needs
 * an atomic set-if-absent behind an implementation that is still synchronous
 * from the caller's side, or a check of its own before calling.
 */
export interface ReplayCache {
  /** True if `id` was added and has not yet expired. */
  has(id: string): boolean;
  /** Remember `id` until `expiresAt` (unix seconds). */
  add(id: string, expiresAt: number): void;
}

const unixNow = (): number => Math.floor(Date.now() / 1000);

/**
 * In-process {@link ReplayCache}. Expired ids are evicted, so memory is bounded
 * by the deliveries seen inside one tolerance window.
 *
 * It does not survive a restart and is not shared between processes; run more
 * than one receiver instance behind a load balancer and each needs a shared
 * cache instead.
 *
 * @param now clock in unix seconds, for tests. Defaults to the system clock.
 */
export class MemoryReplayCache implements ReplayCache {
  private readonly seen = new Map<string, number>();
  private lastSweep = Number.NEGATIVE_INFINITY;

  constructor(private readonly now: () => number = unixNow) {}

  has(id: string): boolean {
    const expiresAt = this.seen.get(id);
    return expiresAt !== undefined && expiresAt >= this.now();
  }

  add(id: string, expiresAt: number): void {
    this.sweep();
    this.seen.set(id, expiresAt);
  }

  /** Number of ids currently remembered (expired ones are evicted first). */
  get size(): number {
    this.sweep(true);
    return this.seen.size;
  }

  /** Drop expired ids, at most once a second unless `force`d. */
  private sweep(force = false): void {
    const now = this.now();
    if (!force && now - this.lastSweep < 1) return;
    this.lastSweep = now;
    for (const [id, expiresAt] of this.seen) {
      if (expiresAt < now) this.seen.delete(id);
    }
  }
}

/**
 * Derive the key one receiver verifies with:
 * `HMAC-SHA256(secret, "ectoledger-webhook-key-v1\n" + receiverUrl)`, as 64
 * lowercase hex characters.
 *
 * This is what `ironvise webhook-key --url <url>` prints. It is for
 * operators: it needs the server secret, which a receiver must never hold.
 * `receiverUrl` must be exactly the URL the webhook is configured with.
 */
export function deriveReceiverKey(
  secret: string | Uint8Array,
  receiverUrl: string,
): string {
  return createHmac("sha256", secret)
    .update(`${RECEIVER_KEY_CONTEXT}\n${receiverUrl}`)
    .digest("hex");
}

export interface VerifyWebhookOptions {
  /** This receiver's key, 64 hex characters (`ironvise webhook-key --url`). */
  receiverKey: string;
  /** This receiver's URL, exactly as the webhook is configured on the server. */
  receiverUrl: string;
  /**
   * The request's headers: a plain object as Node, Express or Fastify give you
   * (any name casing; a header that arrived more than once counts as missing),
   * or a fetch `Headers`.
   */
  headers: Record<string, string | string[] | undefined> | Headers;
  /** The raw request body, exactly as received. Not re-serialised JSON. */
  body: string;
  /** The current time in unix seconds. Defaults to the system clock. */
  now?: number;
  /** Largest accepted clock difference in seconds. Defaults to 300. */
  toleranceSecs?: number;
  /** Where seen delivery ids are kept. Share one across requests. */
  cache: ReplayCache;
}

/** Case-insensitive header lookup over a plain object or a `Headers`. */
function header(
  headers: VerifyWebhookOptions["headers"],
  lowerName: string,
): string | undefined {
  if (typeof (headers as Headers).get === "function") {
    return (headers as Headers).get(lowerName) ?? undefined;
  }
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() !== lowerName) continue;
    if (Array.isArray(value)) return value.length === 1 ? value[0] : undefined;
    return value;
  }
  return undefined;
}

/**
 * Verify one webhook delivery.
 *
 * Checks run in this order, and the order matters: the delivery id is
 * remembered only after the signature has passed, so a forged request cannot
 * fill the replay cache or use up a genuine delivery's id.
 *
 *  1. a header is missing, or the timestamp is not an integer: `missing_headers`
 *  2. the timestamp is more than `toleranceSecs` from `now`:   `stale`
 *  3. the signature does not match (constant-time compare):    `bad_signature`
 *  4. the delivery id was already seen:                        `replayed`
 *
 * Throws a `TypeError` if `receiverKey` is not 64 hex characters: that is a
 * configuration mistake, not something a sender can cause.
 *
 * @example
 * ```ts
 * const cache = new MemoryReplayCache();
 * const verdict = verifyWebhook({
 *   receiverKey: process.env.WEBHOOK_KEY!,
 *   receiverUrl: "https://siem.example/ectoledger",
 *   headers: req.headers,
 *   body: rawBody,
 *   cache,
 * });
 * if (!verdict.ok) return res.status(401).end(verdict.reason);
 * ```
 */
export function verifyWebhook(opts: VerifyWebhookOptions): WebhookVerdict {
  const { receiverKey, receiverUrl, headers, body, cache } = opts;
  if (!/^[0-9a-fA-F]{64}$/.test(receiverKey)) {
    throw new TypeError("receiverKey must be 64 hex characters");
  }

  const deliveryId = header(headers, HEADER_DELIVERY);
  const timestamp = header(headers, HEADER_TIMESTAMP);
  const signature = header(headers, HEADER_SIGNATURE);
  if (
    !deliveryId ||
    !signature ||
    timestamp === undefined ||
    !/^-?[0-9]{1,19}$/.test(timestamp)
  ) {
    return { ok: false, reason: "missing_headers" };
  }

  const now = opts.now ?? unixNow();
  const toleranceSecs = opts.toleranceSecs ?? DEFAULT_TOLERANCE_SECS;
  const sentAt = Number(timestamp);
  if (Math.abs(now - sentAt) > toleranceSecs) {
    return { ok: false, reason: "stale" };
  }

  const expected = createHmac("sha256", Buffer.from(receiverKey, "hex"))
    .update(
      [SIGNATURE_CONTEXT, deliveryId, timestamp, receiverUrl, body].join("\n"),
    )
    .digest("hex");
  const given = Buffer.from(signature, "utf8");
  const want = Buffer.from(expected, "utf8");
  // timingSafeEqual throws on unequal lengths; the length is not a secret.
  if (given.length !== want.length || !timingSafeEqual(given, want)) {
    return { ok: false, reason: "bad_signature" };
  }

  if (cache.has(deliveryId)) return { ok: false, reason: "replayed" };
  cache.add(deliveryId, sentAt + toleranceSecs);
  return { ok: true, deliveryId };
}
