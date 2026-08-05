/** Dev-stage auth role hints for UI gating (ISSUE-213).
 *
 * Mock/Compose maps bearer tokens via backend ``DEV_AUTH_TOKENS``. The UI cannot
 * read that env, so roles are resolved in this order:
 * 1. ``VITE_AUTH_ROLES`` (explicit override — keep in sync with the token's roles)
 * 2. Known compose/dev tokens from ``VITE_DEV_AUTH_TOKEN`` (mirrors docker-compose)
 * 3. Safe default matching ``e2e-token`` / bootstrap approver capability
 */

const APPROVER_ROLE = "approver";

/** Mirrors ``DEV_AUTH_TOKENS`` entries in infra/docker-compose.yml and .env.example. */
const KNOWN_DEV_TOKEN_ROLES: Record<string, readonly string[]> = {
  "e2e-token": ["analyst", APPROVER_ROLE],
  "bootstrap-token": [
    "analyst",
    "admin",
    APPROVER_ROLE,
    "disposition_operator",
  ],
};

function parseRoleCsv(raw: string): string[] {
  return raw
    .split(",")
    .map((role) => role.trim())
    .filter(Boolean);
}

export function currentAuthRoles(): string[] {
  const override = import.meta.env.VITE_AUTH_ROLES?.trim();
  if (override) {
    return parseRoleCsv(override);
  }

  const token = import.meta.env.VITE_DEV_AUTH_TOKEN?.trim();
  if (token && KNOWN_DEV_TOKEN_ROLES[token]) {
    return [...KNOWN_DEV_TOKEN_ROLES[token]];
  }

  // Compose default token carries approver; analyst-only must set VITE_AUTH_ROLES.
  return ["analyst", APPROVER_ROLE];
}

export function canPromoteKnowledgeReviews(): boolean {
  return currentAuthRoles().includes(APPROVER_ROLE);
}
