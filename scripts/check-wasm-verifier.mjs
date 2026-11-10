#!/usr/bin/env node
// The browser verifier must say exactly what verify-cert says.
//
//     make test-wasm-verifier
//
// Both are built from ectoledger_elc::verify::verify, so agreement is by
// construction. This checks the construction: it loads the module embedded in
// site/verify-bundle.js (the bytes a visitor actually runs, not a fresh build)
// and compares its verdict with the verify-cert binary on every certificate
// under examples/ and on a set of mutations of each, in inspection and strict
// mode. It also fails if an embedded sample stops matching its file, or if the
// Rust sources the module is built from changed after it was built.
//
// VERIFY_CERT overrides the binary (default: target/debug/verify-cert, .exe on Windows).

import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { sourceHash } from "./build-verify-page.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const BIN =
  process.env.VERIFY_CERT ||
  join(ROOT, "target/debug/verify-cert" + (process.platform === "win32" ? ".exe" : ""));
const failures = [];
const fail = (m) => failures.push(m);

// Load the bundle the page loads.
const sandbox = { window: {} };
vm.runInNewContext(readFileSync(join(ROOT, "site/verify-bundle.js"), "utf8"), sandbox);
const B = sandbox.window.ELC_BUNDLE;
const wasmBytes = Buffer.from(B.wasm, "base64");
const sha = (b) => createHash("sha256").update(b).digest("hex");

if (sha(wasmBytes) !== B.wasmSha256) fail("bundle: embedded module does not match its own recorded sha256");
if (sourceHash() !== B.sourceSha256) {
  fail("bundle: crates/elc, crates/elc-wasm or crates/core changed since site/verify-bundle.js was built; run `make wasm-verifier`");
}
for (const s of B.samples) {
  if (readFileSync(join(ROOT, s.path), "utf8") !== s.text) {
    fail(`bundle: embedded sample ${s.path} no longer matches the file; run \`make wasm-verifier\``);
  }
}
const answer = readFileSync(join(ROOT, "examples/challenge/ANSWER.sha256"), "utf8").trim();
if (answer !== B.challengeAnswerSha256) fail("bundle: challenge answer hash is stale");

const { instance } = await WebAssembly.instantiate(wasmBytes, {});
const e = instance.exports;

function wasmVerify(bytes, flags) {
  const p = e.elc_alloc(bytes.length);
  new Uint8Array(e.memory.buffer, p, bytes.length).set(bytes);
  const r = e.elc_verify(p, bytes.length, flags, 0, 0, 0, 0);
  const len = new DataView(e.memory.buffer).getUint32(r, true);
  const json = Buffer.from(new Uint8Array(e.memory.buffer, r + 4, len)).toString("utf8");
  e.elc_free(r, len + 4);
  e.elc_free(p, bytes.length);
  return JSON.parse(json);
}

const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
function cliVerify(path, strict) {
  const args = strict ? ["--strict", path] : [path];
  const r = spawnSync(BIN, args, { encoding: "utf8" });
  const lines = strip(r.stdout || "").trim().split("\n");
  return { code: r.status, last: lines[lines.length - 1] || "", stderr: strip(r.stderr || "") };
}

// Mutations: each one a tamper someone would actually try.
function mutations(text) {
  let cert;
  try {
    cert = JSON.parse(text);
  } catch {
    return [];
  }
  const out = [];
  const add = (name, f) => {
    const c = structuredClone(cert);
    if (f(c) !== false) out.push([name, JSON.stringify(c, null, 2)]);
  };
  const flip = (h) => (h[0] === "0" ? "1" : "0") + h.slice(1);
  if (cert.events?.length > 1) {
    add("edit-first-event-hash", (c) => { c.events[0].content_hash = flip(c.events[0].content_hash); });
    add("edit-interior-event-hash", (c) => { const i = Math.floor(c.events.length / 2); c.events[i].content_hash = flip(c.events[i].content_hash); });
    add("swap-first-two-events", (c) => { [c.events[0], c.events[1]] = [c.events[1], c.events[0]]; });
    add("drop-last-event", (c) => { c.events.pop(); });
    add("drop-last-event-and-fix-count-and-tip", (c) => { c.events.pop(); c.event_count = c.events.length; c.ledger_tip_hash = c.events.at(-1).content_hash; });
    add("renumber-sequence", (c) => { c.events.at(-1).sequence += 5; });
  }
  add("edit-goal", (c) => { c.goal = c.goal + " (edited)"; });
  add("edit-goal-and-hash", (c) => { c.goal = c.goal + " (edited)"; c.goal_hash = sha(Buffer.from(c.goal)); });
  add("strip-signature", (c) => { if (!c.signature) return false; delete c.signature; });
  add("strip-public-key", (c) => { if (!c.session_public_key) return false; delete c.session_public_key; });
  add("edit-merkle-root", (c) => { c.merkle_root = flip(c.merkle_root); });
  add("bitcoin-marker-as-stamp", (c) => { c.ots_proof_hex = "0588960d73d71901".repeat(4); });
  add("not-json", () => false);
  out.push(["truncated-file", text.slice(0, Math.floor(text.length / 2))]);
  return out;
}

if (!existsSync(BIN)) {
  console.error(`verify-cert not found at ${BIN}; build it or set VERIFY_CERT`);
  process.exit(2);
}

function* elcFiles(dir) {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) yield* elcFiles(p);
    else if (n.endsWith(".elc")) yield p;
  }
}

const tmp = mkdtempSync(join(tmpdir(), "elc-agree-"));
let compared = 0;
try {
  for (const path of elcFiles(join(ROOT, "examples"))) {
    const text = readFileSync(path, "utf8");
    const cases = [["as-shipped", text], ...mutations(text)];
    for (const [name, body] of cases) {
      const file = join(tmp, "case.elc");
      writeFileSync(file, body);
      for (const strict of [false, true]) {
        const w = wasmVerify(Buffer.from(body), strict ? 1 : 0);
        const c = cliVerify(file, strict);
        const label = `${relative(ROOT, path)} [${name}${strict ? ", strict" : ""}]`;
        compared++;
        if (w.error) {
          if (c.code !== 1 || !c.stderr.includes("Could not read certificate")) {
            fail(`${label}: wasm could not read it, verify-cert exited ${c.code}`);
          }
          continue;
        }
        const wantCode = w.valid ? 0 : 1;
        if (c.code !== wantCode) fail(`${label}: wasm valid=${w.valid}, verify-cert exited ${c.code}`);
        if (c.last !== w.verdict_line) fail(`${label}: verdicts differ\n    wasm: ${w.verdict_line}\n    cli:  ${c.last}`);
      }
    }
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (failures.length) {
  console.error(`check-wasm-verifier: ${failures.length} problem(s)\n  ` + failures.join("\n  "));
  process.exit(1);
}
console.log(`check-wasm-verifier: OK, ${compared} verdicts agree (module sha256 ${B.wasmSha256.slice(0, 16)}…)`);
