#!/usr/bin/env bash
# ISSUE-117 / #622 Phase A — manual Celery worker + broker smoke.
# Requires: make up WORKER=1 (backend TASK_MODE=celery, worker profile healthy)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_PORT="${BACKEND_PORT:-8000}"
BASE="http://127.0.0.1:${BACKEND_PORT}/api/v1"

echo "==> health (expect celery.worker ok when worker profile is up)"
curl -sf "${BASE}/health" | python3 -m json.tool | grep -A6 '"celery"'

echo "==> worker ping via celery inspect (destination=investigation@hostname)"
if command -v docker >/dev/null 2>&1; then
  worker_id="$(docker compose -f "${ROOT}/infra/docker-compose.yml" ps -q worker 2>/dev/null | head -1 || true)"
  if [[ -n "${worker_id}" ]]; then
    worker_host="$(docker exec "${worker_id}" hostname)"
    docker exec "${worker_id}" python -m celery -A app.core.celery_app inspect ping -d "investigation@${worker_host}" -t 5
  else
    echo "WARN: worker container not found — skip in-container inspect"
  fi
fi

echo "==> enqueue worker_ping (requires redis broker reachable from host)"
cd "${ROOT}/backend"
TASK_MODE=celery REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}" \
  CELERY_BROKER_URL="${CELERY_BROKER_URL:-redis://127.0.0.1:6379/0}" \
  .venv/bin/python - <<'PY'
from app.tasks.worker_tasks import worker_ping

async_result = worker_ping.apply_async(queue="investigation")
print("task_id", async_result.id)
print("state", async_result.get(timeout=30))
PY

if [[ -n "${SMOKE_EVENT_ID:-}" ]]; then
  echo "==> optional run_investigation smoke for event ${SMOKE_EVENT_ID}"
  export SMOKE_EVENT_ID
  TASK_MODE=celery REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}" \
    CELERY_BROKER_URL="${CELERY_BROKER_URL:-redis://127.0.0.1:6379/0}" \
    .venv/bin/python - <<'PY'
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
