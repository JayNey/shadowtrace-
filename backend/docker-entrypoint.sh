#!/bin/sh
# Apply schema before serving traffic so Compose/e2e never hit an empty DB.
# Set SKIP_DB_MIGRATE=true for stateless sidecars (e.g. mock-xdr) that do not need Postgres.
set -eu
if [ "${SKIP_DB_MIGRATE:-}" != "true" ]; then
  echo "Running alembic upgrade head ..."
  python -m alembic upgrade head
  echo "Migrations applied."
fi
exec "$@"
