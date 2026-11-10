/**
 * `verifyIntent` must return a deny through the TypeScript client, not just
 * from curl.
 *
 * The endpoint being correct and the client being correct are different
 * claims, and only the second is what someone using the SDK depends on.
 *
 * Skipped unless a live Observer is pointed at:
 *
 *   ECTOLEDGER_LIVE_URL=http://127.0.0.1:3201 \
 *   ECTOLEDGER_LIVE_TOKEN=gate \
 *   npm test -- verify-intent-live
 *
 * Note what is asserted about the ledger: `verify-intent` commits nothing and
 * executes nothing by design, so a denial here does *not* appear in the
 * chain. The surface that records a refusal is the Claude Code hook. Pinning
 * the event count is how that stays a fact rather than a sentence in a doc.
 */
import { describe, expect, it } from "vitest";

import { IronViseClient } from "../src/client";

const URL = process.env.ECTOLEDGER_LIVE_URL;
const TOKEN = process.env.ECTOLEDGER_LIVE_TOKEN;

const live = URL ? describe : describe.skip;

live("verifyIntent against a live Observer", () => {
  const client = () =>
    new IronViseClient({ baseUrl: URL!, bearerToken: TOKEN });

  /**
   * Wait until the session stops growing, then return its event count.
   *
   * Creating a session over the API *starts an agent run*, so events keep
   * arriving after the call returns. Measuring before/after around
   * `verifyIntent` without waiting for that measures the agent loop rather
   * than the call under test.
   */
  const settled = async (c: IronViseClient, id: string): Promise<number> => {
    let last = -1;
    for (let i = 0; i < 40; i += 1) {
      const now = (await c.getEvents(id)).length;
      if (now === last) return now;
      last = now;
      await new Promise((r) => setTimeout(r, 250));
    }
    return last;
  };

  it("denies a banned command, names the stage, and commits nothing", async () => {
    const c = client();
    const session = await c.createSession({ goal: "TS SDK verifyIntent round-trip", record: true });
    const id = session.id ?? (session as unknown as { session_id: string }).session_id;

    const before = await settled(c, id);

    const verdict = await c.verifyIntent(id, {
      action: "run_command",
      params: { command: "rm -rf /" },
      justification: "checking that the SDK surfaces a refusal",
    });

    expect(verdict.decision).toBe("deny");
    expect(verdict.reason, "a refusal with no reason is not auditable").toBeTruthy();
    expect(
      verdict.stage,
      "a refusal that will not say which check refused is half a verdict",
    ).toBeTruthy();

    const after = (await c.getEvents(id)).length; // no settle: nothing should have moved
    expect(
      after,
      "verifyIntent committed an event; it is specified to commit nothing",
    ).toBe(before);
  });

  it("allows a permitted action", async () => {
    const c = client();
    const session = await c.createSession({ goal: "TS SDK verifyIntent allow path", record: true });
    const id = session.id ?? (session as unknown as { session_id: string }).session_id;

    const verdict = await c.verifyIntent(id, {
      action: "read_file",
      params: { path: "README.md" },
      justification: "a permitted read, to prove deny is not the only answer",
    });

    expect(verdict.decision).toBe("allow");
  });
});
