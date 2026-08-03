#!/usr/bin/env bash
# ISSUE-117 / #622 — Celery worker + broker smoke (Phase A) and redelivery gate hook (Phase B).
# Requires: make up WORKER=1 or make up-demo (backend TASK_MODE=celery, worker profile healthy)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_PORT="${BACKEND_PORT:-8000}"
BASE="http://127.0.0.1:${BACKEND_PORT}/api/v1"
COMPOSE_FILE="${ROOT}/infra/docker-compose.yml"
OBS_COMPOSE_FILE="${OBS_COMPOSE_FILE:-}"
COMPOSE_PROFILE="${COMPOSE_PROFILE:-}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-}"
PYTHON="${PYTHON:-}"

if [[ -z "${PYTHON}" ]]; then
  if [[ -x "${ROOT}/backend/.venv/bin/python" ]]; then
    PYTHON="${ROOT}/backend/.venv/bin/python"
  else
    PYTHON="python3"
  fi
fi

run_backend_python() {
  cd "${ROOT}/backend"
  if [[ "${PYTHON}" == *" "* ]]; then
    # Makefile may pass multi-word interpreters (e.g. "uv run --frozen python").
    # shellcheck disable=SC2086
    TASK_MODE=celery REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}" \
      CELERY_BROKER_URL="${CELERY_BROKER_URL:-redis://127.0.0.1:6379/0}" \
      ${PYTHON} -
  else
    TASK_MODE=celery REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}" \
      CELERY_BROKER_URL="${CELERY_BROKER_URL:-redis://127.0.0.1:6379/0}" \
      "${PYTHON}" -
  fi
}

compose_ps_worker() {
  local args=(compose)
  if [[ -n "${COMPOSE_PROJECT_NAME}" ]]; then
    args+=(--project-name "${COMPOSE_PROJECT_NAME}")
  fi
  args+=(-f "${COMPOSE_FILE}")
  if [[ -n "${OBS_COMPOSE_FILE}" && -f "${OBS_COMPOSE_FILE}" ]]; then
    args+=(-f "${OBS_COMPOSE_FILE}")
  fi
  if [[ -n "${COMPOSE_PROFILE}" ]]; then
    args+=(--profile "${COMPOSE_PROFILE}")
  fi
  args+=(ps -q worker)
  docker "${args[@]}"
}

echo "==> health (expect celery.worker ok when worker profile is up)"
curl -sf "${BASE}/health" | python3 -m json.tool | grep -A6 '"celery"'

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required for worker smoke (inspect + enqueue need a running worker)"
  echo "Run: make up WORKER=1  or  make up-demo"
  exit 1
fi

worker_id="$(compose_ps_worker 2>/dev/null | head -1 || true)"
if [[ -z "${worker_id}" ]]; then
  echo "ERROR: worker container not found — enqueue smoke requires a healthy worker"
  echo "Run: make up WORKER=1  or  make up-demo"
  exit 1
fi

echo "==> worker ping via celery inspect (destination=investigation@hostname)"
worker_host="$(docker exec "${worker_id}" hostname)"
if ! docker exec "${worker_id}" python -m celery -A app.core.celery_app inspect ping \
  -d "investigation@${worker_host}" -t 5; then
  echo "ERROR: worker inspect ping failed — worker may still be starting"
  echo "Retry after: docker compose -f ${COMPOSE_FILE} --profile ${COMPOSE_PROFILE:-worker} ps worker"
  exit 1
fi

echo "==> enqueue worker_ping (requires redis broker reachable from host)"
run_backend_python <<'PY'
from app.tasks.worker_tasks import worker_ping

async_result = worker_ping.apply_async(queue="investigation")
print("task_id", async_result.id)
print("state", async_result.get(timeout=30))
PY

if [[ -n "${SMOKE_EVENT_ID:-}" ]]; then
  echo "==> optional run_investigation smoke for event ${SMOKE_EVENT_ID}"
  export SMOKE_EVENT_ID
  run_backend_python <<'PY'
import os

from app.tasks.investigation_tasks import run_investigation

event_id = os.environ["SMOKE_EVENT_ID"]
async_result = run_investigation.apply_async(args=[event_id], queue="investigation")
print("task_id", async_result.id)
print("state", async_result.get(timeout=120))
print("result", async_result.result)
PY
fi

echo "OK: celery worker smoke completed"
