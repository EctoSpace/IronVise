/**
 * What `GET /api/sessions/{id}/verify` means, in words, for every screen that
 * shows it (Home's timeline and History).
 *
 * Two separate facts come back. `ok` is the hash chain: every event links to
 * the one before and matches its own hash. `signatures` is whether those
 * events are bound to the session's key. A chain can link perfectly after its
 * signatures were stripped, so a green banner needs both.
 */

export interface VerifyResponse {
  ok?: boolean;
  signatures?: {
    verified: boolean;
    verdict: string;
    message: string;
    signed: number;
    unsigned: number;
  };
}

export interface VerificationView {
  tone: "pass" | "warn" | "fail";
  title: string;
  detail: string;
}

const plural = (n: number, one: string, many = one + "s") => `${n} ${n === 1 ? one : many}`;

export function describeVerification(res: VerifyResponse, sessionId: string): VerificationView {
  const cli = `ironvise verify-session ${sessionId}`;
  if (res.ok !== true) {
    return {
      tone: "fail",
      title: "Hash chain broken",
      detail: `An event no longer matches its hash or its place in the chain. Run \`${cli}\` to see which.`,
    };
  }
  const sig = res.signatures;
  if (!sig) {
    // An older server that only reports the chain.
    return { tone: "pass", title: "Hash chain intact", detail: "Signatures were not checked by this server." };
  }
  if (sig.verdict === "unsigned") {
    return {
      tone: "warn",
      title: "Consistent, but unsigned",
      detail: "The chain links, but no event is signed, so nothing ties these events to anyone.",
    };
  }
  if (!sig.verified) {
    return {
      tone: "fail",
      title: "Signatures do not hold",
      detail: `The chain links, but ${sig.message}.`,
    };
  }
  const extra =
    sig.unsigned > 0
      ? ` ${plural(sig.unsigned, "further event")} ${sig.unsigned === 1 ? "is" : "are"} unsigned by design (client notes, seals, anchors) and covered by the chain only.`
      : "";
  return {
    tone: "pass",
    title: "Intact and signed",
    detail: `The chain links and ${plural(sig.signed, "signature")} verified.${extra}`,
  };
}
