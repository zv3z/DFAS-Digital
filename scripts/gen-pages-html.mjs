/**
 * gen-pages-html.mjs
 * Generates index.html + 404.html for GitHub Pages static deployment.
 *
 * TanStack Start (SSR) does not output index.html in dist/client.
 * This script reads the asset filenames from dist/client/assets/ and
 * writes a minimal HTML shell that bootstraps the React client.
 *
 * Usage:  node scripts/gen-pages-html.mjs
 * Requires: npm run build (with GITHUB_PAGES=true) to have run first.
 */

import { readdirSync, writeFileSync } from "fs";
import { join } from "path";

const DIST = "dist/client";
const ASSETS = `${DIST}/assets`;
const BASE = "/DFAS-Digital/";

// ── Find built assets ─────────────────────────────────────────────
const files = readdirSync(ASSETS);

const cssFile = files.find((f) => f.startsWith("styles-") && f.endsWith(".css"));
// Main bundle is the largest JS file (TanStack + React runtime)
const jsFiles = files.filter((f) => f.endsWith(".js"));

// The main entry is the JS with no route name prefix (just "index-HASH.js")
// There may be two: a small chunk and the large bundle — pick the larger one.
const indexJsFiles = jsFiles.filter((f) => /^index-/.test(f));
let mainJs = indexJsFiles[0];
if (indexJsFiles.length > 1) {
  const sizes = indexJsFiles.map((f) => {
    try {
      return { f, size: readdirSync(ASSETS + "/" + f.replace(/.*\//, "")).length };
    } catch {
      return { f, size: 0 };
    }
  });
  // Fall back: pick the one that contains "StartClient" or simply the larger filename
  // We identify the TanStack Start bootstrap by looking for "StartClient" in a quick grep.
  const { execSync } = await import("child_process");
  mainJs = indexJsFiles.find((f) => {
    try {
      execSync(`grep -l "StartClient\\|hydrateRoot\\|createRoot" "${ASSETS}/${f}"`, {
        stdio: "pipe",
      });
      return true;
    } catch {
      return false;
    }
  }) ?? indexJsFiles[indexJsFiles.length - 1];
}

if (!cssFile) {
  console.error("❌  Could not find styles-*.css in", ASSETS);
  process.exit(1);
}
if (!mainJs) {
  console.error("❌  Could not find main index-*.js in", ASSETS);
  process.exit(1);
}

console.log(`✓  CSS  : ${cssFile}`);
console.log(`✓  JS   : ${mainJs}`);

// ── Generate HTML ─────────────────────────────────────────────────
const html = `<!doctype html>
<html lang="ar" dir="rtl" class="dark">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DFAS v3 — نظام التحليل الجنائي الرقمي</title>
    <meta name="description" content="DFAS — منصة تحليل جنائي رقمي وتعليم الأمن السيبراني." />
    <meta name="author" content="DFAS" />
    <meta property="og:title" content="DFAS v3 — Digital Forensics Analysis System" />
    <meta property="og:description" content="Arabic-first cybersecurity forensics dashboard." />
    <meta property="og:type" content="website" />
    <link rel="icon" type="image/svg+xml" href="${BASE}favicon.svg" />
    <link rel="stylesheet" href="${BASE}assets/${cssFile}" />
  </head>
  <body>
    <!--
      TanStack Start client bootstrap.
      hydrateRoot will perform client-side rendering when no SSR HTML is present.
    -->
    <script type="module" src="${BASE}assets/${mainJs}"></script>
  </body>
</html>
`;

writeFileSync(join(DIST, "index.html"), html, "utf-8");
writeFileSync(join(DIST, "404.html"), html, "utf-8");

console.log(`\n✅  Written:`);
console.log(`   ${DIST}/index.html`);
console.log(`   ${DIST}/404.html  (SPA fallback for GitHub Pages)`);
