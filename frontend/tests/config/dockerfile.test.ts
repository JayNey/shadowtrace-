/** ISSUE-221: Dockerfile must not default-embed dev auth token in production images. */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const DOCKERFILE = join(dirname(fileURLToPath(import.meta.url)), "../../Dockerfile");

describe("frontend/Dockerfile (ISSUE-221)", () => {
  it("defaults VITE_DEV_AUTH_TOKEN to empty, not bootstrap-token", () => {
    const dockerfile = readFileSync(DOCKERFILE, "utf8");
    expect(dockerfile).not.toMatch(/ARG VITE_DEV_AUTH_TOKEN=bootstrap-token/);
    expect(dockerfile).toMatch(/ARG VITE_DEV_AUTH_TOKEN=\s*$/m);
  });
});
