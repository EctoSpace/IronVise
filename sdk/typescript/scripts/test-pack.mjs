#!/usr/bin/env node
// test-pack.mjs - install the packed tarball and use it the way a consumer does.
//
// The unit suite imports `src/`, so it cannot see a packaging fault: the 0.8.0
// CommonJS build exported four `undefined` values and 67 green tests said
// nothing. This script builds, packs, installs the tarball into a scratch
// directory outside the repository, and then:
//
//   1. `require()`s it from CommonJS and checks every runtime export,
//   2. `import`s it from ESM and checks the same,
//   3. type-checks a CommonJS and an ESM consumer under `moduleResolution:
//      node16`, which is where a missing `.d.cts` shows up.
//
// Exit code 0 only if all four pass.

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readdirSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const sdk = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
// On Windows `npm` is npm.cmd, which execFileSync cannot start without a
// shell (ENOENT, or EINVAL on current Node). Under `npm run`, npm_execpath is
// npm's own CLI script, so run that with this Node instead, on every platform.
const npmCli = process.env.npm_execpath;
const npm = (args, cwd) =>
  npmCli && /\.c?js$/.test(npmCli)
    ? run(process.execPath, [npmCli, ...args], cwd)
    : run(process.platform === "win32" ? "npm.cmd" : "npm", args, cwd);

const scratch = mkdtempSync(join(tmpdir(), "ironvise-pack-"));
let failed = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "  ok  " : "  FAIL"}  ${name}${detail ? " - " + detail : ""}`);
  if (!ok) failed++;
};

try {
  console.log("building…");
  npm(["run", "build"], sdk);

  console.log("packing…");
  const tarball = npm(["pack", "--pack-destination", scratch], sdk).trim().split("\n").pop();
  const tarballPath = join(scratch, tarball);
  console.log(`  ${tarball}`);

  const consumer = join(scratch, "consumer");
  mkdirSync(consumer, { recursive: true });
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({ name: "consumer", version: "1.0.0", private: true, type: "module" }, null, 2),
  );
  console.log("installing the tarball into a clean consumer…");
  npm(["install", "--no-audit", "--no-fund", tarballPath], consumer);

  const EXPECTED = [
    "IronViseClient",
    "IronViseApiError",
    "IronViseUsageError",
    "IntentDeniedError",
    "assertAllowed",
    "verifyWebhook",
    "deriveReceiverKey",
    "MemoryReplayCache",
  ];

  // 1. CommonJS runtime.
  writeFileSync(
    join(consumer, "cjs-consumer.cjs"),
    `const m = require("ironvise");
const missing = ${JSON.stringify(EXPECTED)}.filter((k) => typeof m[k] === "undefined");
if (missing.length) { console.error("undefined exports: " + missing.join(", ")); process.exit(1); }
if (Object.keys(m).some(k => k.startsWith("EctoLedger"))) throw new Error("legacy API alias in package");
const c = new m.IronViseClient({ baseUrl: "http://127.0.0.1:1", bearerToken: "t" });
if (typeof c.verifyIntent !== "function") { console.error("verifyIntent missing"); process.exit(1); }
try { m.assertAllowed({ decision: "deny", reason: "r" }); console.error("assertAllowed did not throw"); process.exit(1); }
catch (e) { if (!(e instanceof m.IntentDeniedError)) { console.error("wrong error type"); process.exit(1); } }
console.log("cjs ok");
`,
  );
  try {
    run("node", ["cjs-consumer.cjs"], consumer);
    check("CommonJS require() exposes every runtime export", true);
  } catch {
    check("CommonJS require() exposes every runtime export", false);
  }

  // 2. ESM runtime.
  writeFileSync(
    join(consumer, "esm-consumer.mjs"),
    `import * as m from "ironvise";
const missing = ${JSON.stringify(EXPECTED)}.filter((k) => typeof m[k] === "undefined");
if (missing.length) { console.error("undefined exports: " + missing.join(", ")); process.exit(1); }
if (Object.keys(m).some(k => k.startsWith("EctoLedger"))) throw new Error("legacy API alias in package");
new m.IronViseClient({ baseUrl: "http://127.0.0.1:1" });
console.log("esm ok");
`,
  );
  try {
    run("node", ["esm-consumer.mjs"], consumer);
    check("ESM import exposes every runtime export", true);
  } catch {
    check("ESM import exposes every runtime export", false);
  }

  // 3/4. Declaration resolution, both module systems, node16 resolution.
  cpSync(join(sdk, "node_modules", "typescript"), join(consumer, "node_modules", "typescript"), {
    recursive: true,
  });
  const tscBin = join(consumer, "node_modules", "typescript", "bin", "tsc");

  for (const [label, moduleKind, ext, body] of [
    [
      "CommonJS consumer type-checks (moduleResolution node16)",
      "node16",
      "cts",
      `import { IronViseClient, assertAllowed, IntentDeniedError, IronViseApiError } from "ironvise";
import type { IntentVerdict, Session, CreateSessionOptions, VerifySessionResult } from "ironvise";
const c: IronViseClient = new IronViseClient({ baseUrl: "http://x" });
const o: CreateSessionOptions = { goal: "g", record: true };
export async function f(): Promise<Session> { return c.createSession(o); }
export async function v(): Promise<VerifySessionResult> { return c.verifySession("s"); }
export function g(v: IntentVerdict) { try { assertAllowed(v); } catch (e) { if (e instanceof IntentDeniedError) throw e; } }
export const E = IronViseApiError;
`,
    ],
    [
      "ESM consumer type-checks (moduleResolution node16)",
      "node16",
      "mts",
      `import { IronViseClient, assertAllowed } from "ironvise";
import type { IntentVerdict, Session } from "ironvise";
const c = new IronViseClient({ baseUrl: "http://x" });
export async function f(): Promise<Session> { return c.createSession({ goal: "g" }); }
export function g(v: IntentVerdict) { assertAllowed(v); }
`,
    ],
  ]) {
    const file = `check.${ext}`;
    writeFileSync(join(consumer, file), body);
    writeFileSync(
      join(consumer, `tsconfig.${ext}.json`),
      JSON.stringify(
        {
          compilerOptions: {
            module: moduleKind,
            moduleResolution: "node16",
            target: "ES2022",
            strict: true,
            noEmit: true,
            skipLibCheck: false,
            types: [],
          },
          files: [file],
        },
        null,
        2,
      ),
    );
    try {
      run("node", [tscBin, "-p", `tsconfig.${ext}.json`], consumer);
      check(label, true);
    } catch {
      check(label, false);
    }
  }

  console.log(`\npacked-artifact checks: ${failed === 0 ? "all passed" : failed + " failed"}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

process.exit(failed === 0 ? 0 : 1);
