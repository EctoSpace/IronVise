// Render the Article 12 one-pager to PDF.
//
// Uses the Chromium that Playwright already installed for the GUI visual
// baseline (gui/playwright.config.ts) rather than adding pandoc, wkhtmltopdf or
// a LaTeX toolchain as a dependency for one page.
//
//   node scripts/build-article12-pdf.mjs
//
// Source:  docs/assets/article12-onepager.html
// Output:  docs/assets/ironvise-article12-mapping.pdf
//
// The output is committed: the point of this page is that it can be handed to
// someone who will never clone the repo.

import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, resolve } from "node:path";
import { access } from "node:fs/promises";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");

// Playwright is a devDependency of the GUI workspace, not of the repo root, so
// resolve it from there explicitly. This keeps the script runnable from any
// working directory instead of only from gui/.
const requireFromGui = createRequire(
  pathToFileURL(resolve(repoRoot, "gui/package.json")),
);
// @playwright/test resolves to a CJS entry, so dynamic import wraps its exports
// in `default`. Accept either shape rather than depending on the interop.
const playwright = await import(
  pathToFileURL(requireFromGui.resolve("@playwright/test")).href
);
const { chromium } = playwright.chromium ? playwright : playwright.default;
const src = resolve(repoRoot, "docs/assets/article12-onepager.html");
const out = resolve(repoRoot, "docs/assets/ironvise-article12-mapping.pdf");

await access(src);

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  // `waitUntil: load` is enough - the page is self-contained, with no remote
  // fonts or images, which is also what keeps the PDF reproducible.
  await page.goto(pathToFileURL(src).href, { waitUntil: "load" });

  await page.pdf({
    path: out,
    format: "A4",
    printBackground: true,
    preferCSSPageSize: true,
  });

  // A one-pager that silently becomes a two-pager is the failure mode worth
  // catching, since nobody re-reads a generated PDF before sending it.
  const pageCount = await page.evaluate(() => {
    const el = document.documentElement;
    // A4 at 96dpi minus the 12mm/10mm @page margins declared in the stylesheet.
    const printableHeightPx = (297 - 12 - 10) * (96 / 25.4);
    return Math.ceil(el.scrollHeight / printableHeightPx);
  });

  console.log(`wrote ${out}`);
  if (pageCount > 1) {
    console.error(
      `WARNING: content overflows to roughly ${pageCount} pages. ` +
        `Tighten docs/assets/article12-onepager.html - this is meant to be one page.`,
    );
    process.exitCode = 1;
  } else {
    console.log("fits on one page");
  }
} finally {
  await browser.close();
}
