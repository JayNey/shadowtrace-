/** Auth role hint tests (ISSUE-213). */

import { afterEach, describe, expect, it, vi } from "vitest";

describe("config/auth", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("uses VITE_AUTH_ROLES override when set", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "e2e-token");
    const { currentAuthRoles, canPromoteKnowledgeReviews } = await import(
      "../../src/config/auth"
    );
    expect(currentAuthRoles()).toEqual(["analyst"]);
    expect(canPromoteKnowledgeReviews()).toBe(false);
  });

  it("derives roles from known VITE_DEV_AUTH_TOKEN when roles unset", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "e2e-token");
    const { currentAuthRoles, canPromoteKnowledgeReviews } = await import(
      "../../src/config/auth"
    );
    expect(currentAuthRoles()).toEqual(["analyst", "approver"]);
    expect(canPromoteKnowledgeReviews()).toBe(true);
  });

  it("maps bootstrap-token to compose roles", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "bootstrap-token");
    const { currentAuthRoles } = await import("../../src/config/auth");
    expect(currentAuthRoles()).toContain("approver");
    expect(currentAuthRoles()).toContain("admin");
  });

  it("defaults unknown dev token to analyst-only", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "custom-analyst-token");
    const { currentAuthRoles, canPromoteKnowledgeReviews } = await import(
      "../../src/config/auth"
    );
    expect(currentAuthRoles()).toEqual(["analyst"]);
    expect(canPromoteKnowledgeReviews()).toBe(false);
  });
});
