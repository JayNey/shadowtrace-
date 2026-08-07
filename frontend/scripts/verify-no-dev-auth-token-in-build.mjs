#!/usr/bin/env node
/**
 * ISSUE-221: fail if a production build inlined a dev bearer token into apiClient.
 * Compose dev builds pass VITE_DEV_AUTH_TOKEN explicitly; default Dockerfile/CI
 * production builds must not emit Authorization: Bearer <dev-token>.
 */
import { readdir, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DIST_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const FORBIDDEN = [
  // apiClient inlines VITE_DEV_AUTH_TOKEN next to VITE_API_BASE_URL at build time.
  /\/api\/v1"[;,][A-Za-z0-9_$]+="bootstrap-token"/,
  /\/api\/v1"[;,][A-Za-z0-9_$]+="e2e-token"/,
  "Bearer bootstrap-token",
  "Bearer e2e-token",
];

async function collectJsFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectJsFiles(path)));
    } else if (entry.name.endsWith(".js")) {
      files.push(path);
    }
  }
  return files;
}

const distPath = DIST_DIR;
let jsFiles;
try {
  jsFiles = await collectJsFiles(distPath);
} catch (err) {
  console.error(`verify-no-dev-auth-token-in-build: dist/ missing — run pnpm build first (${err})`);
  process.exit(1);
}

const hits = [];
for (const file of jsFiles) {
  const content = await readFile(file, "utf8");
  for (const needle of FORBIDDEN) {
    if (typeof needle === "string") {
      if (content.includes(needle)) {
        hits.push({ file, needle });
      }
    } else if (needle.test(content)) {
      hits.push({ file, needle: needle.source });
    }
  }
}

if (hits.length > 0) {
  console.error("Production build must not embed dev auth bearer tokens (ISSUE-221):");
  for (const { file, needle } of hits) {
    console.error(`  ${file}: found "${needle}"`);
  }
  process.exit(1);
}

console.log("verify-no-dev-auth-token-in-build: OK (no inlined dev bearer tokens)");
