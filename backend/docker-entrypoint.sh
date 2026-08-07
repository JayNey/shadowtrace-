#!/bin/sh
# Apply schema before serving traffic so Compose/e2e never hit an empty DB.
# Set SKIP_DB_MIGRATE=true for services that must not run alembic (ISSUE-238):
# mock-xdr (stateless), Celery worker / beat / scheduler-worker (backend owns migrate).
set -eu
if [ "${SKIP_DB_MIGRATE:-}" != "true" ]; then
  echo "Running alembic upgrade head ..."
  python -m alembic upgrade head
  echo "Migrations applied."
fi
exec "$@"
