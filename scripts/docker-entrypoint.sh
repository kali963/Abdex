#!/bin/sh
# Apply database migrations before the app starts (NFR-DB-04, OPS-04).
set -e
if [ "${DATABASE_URL#postgresql}" != "$DATABASE_URL" ]; then
  alembic upgrade head
fi
exec "$@"
