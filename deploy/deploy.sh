#!/bin/sh
# Update the server to a git revision (OPS-01). Run on the server, from the checkout (e.g. /opt/abdex):
#
#   deploy/deploy.sh <branch | tag | commit>      # default: origin/main
#
# Takes a quick database dump first, builds the image, restarts the app and the worker (migrations run at
# start), waits until /healthz answers and runs the launch check. If the new version does not come up, the
# previous revision is started again. Migrations are additive (new columns / tables), so the previous code runs
# on the migrated database; the dump in $BACKUP_DIR/predeploy is there for anything else.
set -eu
# git checkout replaces this file while it runs: continue from a copy
if [ -z "${ABDEX_DEPLOY_DIR:-}" ]; then
  ABDEX_DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
  copy="$(mktemp)"
  cp "$0" "$copy"
  ABDEX_DEPLOY_DIR="$ABDEX_DEPLOY_DIR" exec sh "$copy" "$@"
fi
cd "$ABDEX_DEPLOY_DIR"
REF="${1:-origin/main}"
COMPOSE="docker compose -f docker-compose.prod.yml --env-file .env.production"
envget() { sed -n "s/^$1=//p" .env.production | tail -n 1; }
BACKUP_DIR="${BACKUP_DIR:-$(envget BACKUP_DIR)}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/abdex}"

PREV="$(git rev-parse HEAD)"
git fetch --quiet --tags origin
TARGET="$(git rev-parse --verify "$REF^{commit}")"
echo "deploy: $PREV -> $TARGET"

if [ -n "$($COMPOSE ps -q --status running db 2>/dev/null)" ]; then
  mkdir -p "$BACKUP_DIR/predeploy"
  umask 077
  $COMPOSE exec -T db pg_dump -U postgres -Fc abdex > "$BACKUP_DIR/predeploy/db-$(date -u +%Y%m%d-%H%M%S)-${PREV%"${PREV#???????}"}.dump"
  find "$BACKUP_DIR/predeploy" -name '*.dump' -mtime +14 -delete
fi

start() {  # $1 = revision
  git checkout --quiet --detach "$1"
  ABDEX_VERSION="$(git rev-parse --short HEAD)" $COMPOSE build app worker
  ABDEX_VERSION="$(git rev-parse --short HEAD)" $COMPOSE up -d --remove-orphans
}

healthy() {
  i=0
  while [ $i -lt 40 ]; do  # up to ~4 minutes: migrations + start
    if $COMPOSE exec -T app python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5).status == 200 else 1)" 2>/dev/null; then
      return 0
    fi
    i=$((i + 1)); sleep 6
  done
  return 1
}

start "$TARGET"
if healthy; then
  $COMPOSE exec -T app python -m app.cli preflight || echo "WARNING: the launch check reports errors (see above)"
  echo "deploy ok: $(git rev-parse --short HEAD)"
  exit 0
fi
echo "the new version did not become healthy — starting $PREV again"
$COMPOSE logs --tail 80 app || true
start "$PREV"
healthy && echo "rolled back to $(git rev-parse --short HEAD)" || echo "ROLLBACK ALSO UNHEALTHY — check the server"
exit 1
