#!/bin/sh
# Apply database migrations before the app starts (NFR-DB-04, OPS-04).
# MIGRATE_ON_START=false for every container but one (the worker waits for the app instead), so two
# containers never migrate at the same time.
set -e
if [ "${MIGRATE_ON_START:-true}" != "false" ] && [ "${DATABASE_URL#postgresql}" != "$DATABASE_URL" ]; then
  alembic upgrade head
fi
exec "$@"
