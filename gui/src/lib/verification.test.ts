import { describe, it, expect } from "vitest";
import { describeVerification } from "./verification";

describe("describeVerification", () => {
  it("reports a broken hash chain when ok is not strictly true", () => {
    const v = describeVerification({ ok: false }, "sess-1");
    expect(v.tone).toBe("fail");
    expect(v.title).toBe("Hash chain broken");
    expect(v.detail).toContain("ironvise verify-session sess-1");
  });

  it("treats a missing ok field the same as false", () => {
    const v = describeVerification({}, "sess-1");
    expect(v.tone).toBe("fail");
  });

  it("reports an intact but unchecked chain when the server has no signatures field", () => {
    const v = describeVerification({ ok: true }, "sess-1");
    expect(v).toEqual({
      tone: "pass",
      title: "Hash chain intact",
      detail: "Signatures were not checked by this server.",
    });
  });

  it("reports consistent-but-unsigned when the verdict is 'unsigned'", () => {
    const v = describeVerification(
      { ok: true, signatures: { verified: false, verdict: "unsigned", message: "", signed: 0, unsigned: 3 } },
      "sess-1",
    );
    expect(v.tone).toBe("warn");
    expect(v.title).toBe("Consistent, but unsigned");
  });

  it("reports failed signatures with the server's message when not verified", () => {
    const v = describeVerification(
      {
        ok: true,
        signatures: { verified: false, verdict: "invalid", message: "key not found", signed: 2, unsigned: 0 },
      },
      "sess-1",
    );
    expect(v.tone).toBe("fail");
    expect(v.title).toBe("Signatures do not hold");
    expect(v.detail).toBe("The chain links, but key not found.");
  });

  it("reports intact and signed with no extra note when nothing is unsigned", () => {
    const v = describeVerification(
      { ok: true, signatures: { verified: true, verdict: "ok", message: "", signed: 1, unsigned: 0 } },
      "sess-1",
    );
    expect(v.tone).toBe("pass");
    expect(v.title).toBe("Intact and signed");
    expect(v.detail).toBe("The chain links and 1 signature verified.");
  });

  it("pluralises the signed count", () => {
    const v = describeVerification(
      { ok: true, signatures: { verified: true, verdict: "ok", message: "", signed: 5, unsigned: 0 } },
      "sess-1",
    );
    expect(v.detail).toBe("The chain links and 5 signatures verified.");
  });

  it("appends a note about unsigned-by-design events, singular", () => {
    const v = describeVerification(
      { ok: true, signatures: { verified: true, verdict: "ok", message: "", signed: 1, unsigned: 1 } },
      "sess-1",
    );
    expect(v.detail).toBe(
      "The chain links and 1 signature verified. 1 further event is unsigned by design (client notes, seals, anchors) and covered by the chain only.",
    );
  });

  it("appends a note about unsigned-by-design events, plural", () => {
    const v = describeVerification(
      { ok: true, signatures: { verified: true, verdict: "ok", message: "", signed: 1, unsigned: 2 } },
      "sess-1",
    );
    expect(v.detail).toContain("2 further events are unsigned by design");
  });
});
