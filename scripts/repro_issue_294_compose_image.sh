#!/usr/bin/env bash
# ISSUE-294 acceptance repro: compose build → resolve backend image without compose up.
#
# Demonstrates ``docker compose images -q backend`` is often empty after build-only,
# while check_docker_build_context.py --resolve-compose-image still succeeds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-shadowtrace-ci-repro-$$}"
COMPOSE_FILE="${ROOT}/infra/docker-compose.yml"

compose_cmd() {
  docker compose --project-name "${COMPOSE_PROJECT_NAME}" -f "${COMPOSE_FILE}" "$@"
}

echo "[repro-294] build backend only (project=${COMPOSE_PROJECT_NAME}) ..."
compose_cmd build backend

legacy_id="$(compose_cmd images -q backend 2>/dev/null | head -1 || true)"
if [[ -z "${legacy_id}" ]]; then
  echo "[repro-294] legacy compose images -q backend: (empty) — expected after build-only"
else
  echo "[repro-294] legacy compose images -q backend returned: ${legacy_id}"
fi

echo "[repro-294] resolve via check_docker_build_context.py ..."
stderr_file="$(mktemp)"
trap 'rm -f "${stderr_file}"' EXIT

if ! resolved_id="$(
  python3 "${ROOT}/scripts/check_docker_build_context.py" \
    --resolve-compose-image backend \
    --project-name "${COMPOSE_PROJECT_NAME}" \
    --compose-file "${COMPOSE_FILE}" \
    2>"${stderr_file}"
)"; then
  cat "${stderr_file}" >&2
  echo "[repro-294] ERROR: image resolver failed" >&2
  exit 1
fi

cat "${stderr_file}" >&2
if [[ -z "${resolved_id}" ]]; then
  echo "[repro-294] ERROR: resolver returned empty image id" >&2
  exit 1
fi

echo "[repro-294] resolved image id: ${resolved_id}"
echo "[repro-294] acceptance passed"
