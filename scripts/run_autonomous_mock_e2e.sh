#!/usr/bin/env bash
# ISSUE-110 / #614 — Autonomous Mock XDR full-loop E2E runner.
# Default: integration scenarios without live worker (postgres + redis required).
# With --worker: also runs worker-gated tests (requires make up WORKER=1).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="${ROOT}/backend"
PYTHON="${BACKEND}/.venv/bin/python"
RUN_WORKER=0

for arg in "$@"; do
  case "$arg" in
    --worker) RUN_WORKER=1 ;;
    -h|--help)
      echo "Usage: $0 [--worker]"
      echo "  --worker  include @pytest.mark.autonomous_mock_e2e (live Celery worker required)"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

export DATABASE_URL="${DATABASE_URL:-postgresql+asyncpg://shadowtrace:shadowtrace@127.0.0.1:5432/shadowtrace}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export CELERY_BROKER_URL="${CELERY_BROKER_URL:-$REDIS_URL}"
export TASK_MODE="${TASK_MODE:-celery}"

cd "${BACKEND}"

echo "==> ISSUE-110 integration scenarios (postgres + redis)"
"${PYTHON}" -m pytest tests/integration/autonomous_e2e/ \
  -m "integration and not autonomous_mock_e2e" -v --tb=short

if [[ "${RUN_WORKER}" -eq 1 ]]; then
  echo "==> ISSUE-110 worker-gated scenarios (live Celery worker)"
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker required for worker probe" >&2
    exit 1
  fi
  "${PYTHON}" -m pytest tests/integration/autonomous_e2e/ \
    -m "autonomous_mock_e2e" -v --tb=short
fi

echo "OK: autonomous mock E2E completed"
