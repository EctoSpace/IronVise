// esbuild.mjs - produce the CommonJS half of the dual-module package.
//
// `npm run build` runs `tsc` first, which emits the ESM entry points
// (`dist/*.js`) and the declarations (`dist/*.d.ts`). This script adds the
// CommonJS ones: `dist/*.cjs` and the matching `dist/*.d.cts`.
//
// `npm run test:pack` installs the packed tarball and uses it from a CommonJS
// consumer, so a broken transform cannot ship unnoticed.
//
// The modules are emitted one-to-one rather than bundled into a single file so
// every `.d.cts` has a real `.cjs` beside it - a declaration with no
// implementation is the kind of inconsistency that type-checks in one resolver
// and fails in the next.

import { build } from "esbuild";
import { readFileSync, writeFileSync, readdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const root = dirname(fileURLToPath(import.meta.url));
const src = join(root, "src");
const dist = join(root, "dist");

/** Keep sibling modules as separate files, pointing at their `.cjs` names. */
const siblingsStayExternal = {
  name: "siblings-stay-external",
  setup(b) {
    b.onResolve({ filter: /^\.\.?\// }, (args) => {
      if (args.kind === "entry-point") return undefined;
      return { path: args.path.replace(/\.js$/, ".cjs"), external: true };
    });
  },
};

await build({
  entryPoints: ["index.ts", "client.ts", "models.ts", "webhook.ts"].map((f) => join(src, f)),
  outdir: dist,
  outbase: src,
  outExtension: { ".js": ".cjs" },
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node18",
  sourcemap: true,
  plugins: [siblingsStayExternal],
  logLevel: "warning",
});

// TypeScript picks the types for a `require()` through the `require` condition,
// and under `moduleResolution: node16` a `.d.ts` inside a `"type": "module"`
// package is read as an ESM declaration - which a CommonJS consumer cannot
// re-export from. These are the same declarations, resolved as CommonJS.
let declarations = 0;
for (const entry of readdirSync(dist)) {
  if (!entry.endsWith(".d.ts")) continue;
  const text = readFileSync(join(dist, entry), "utf8")
    .replace(/(from\s+"\.\.?\/[^"]+)\.js"/g, '$1.cjs"')
    .replace(/^\/\/# sourceMappingURL=.*$/m, "")
    .trimEnd();
  writeFileSync(join(dist, entry.replace(/\.d\.ts$/, ".d.cts")), text + "\n");
  declarations++;
}

console.log(`esbuild.mjs: CommonJS build written (${declarations} declaration files)`);
