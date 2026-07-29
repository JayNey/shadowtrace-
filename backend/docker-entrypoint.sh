#!/bin/sh
# Apply schema before serving traffic so Compose/e2e never hit an empty DB.
set -eu
echo "Running alembic upgrade head ..."
python -m alembic upgrade head
echo "Migrations applied."
exec "$@"
