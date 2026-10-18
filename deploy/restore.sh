#!/bin/sh
# Restore from backup.sh files:
#   ./restore.sh /var/backups/abdex/db-YYYYMMDD-HHMMSS.dump.gpg [/var/backups/abdex/storage-YYYYMMDD-HHMMSS.tar.gpg]
# Stops the app and the worker, replaces the database (and the files), starts them again.
# Practise it on a separate server once a quarter (OPS-05).
set -eu
cd "$(dirname "$0")"
envget() { sed -n "s/^$1=//p" .env.production | tail -n 1; }
BACKUP_PASSPHRASE="$(envget BACKUP_PASSPHRASE)"
DB_FILE="$1"
FILES="${2:-}"
COMPOSE="docker compose -f docker-compose.prod.yml --env-file .env.production"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
printf "This REPLACES the data of this server with %s. Type YES: " "$DB_FILE"
read -r answer
[ "$answer" = "YES" ] || exit 1

gpg --batch --pinentry-mode loopback --passphrase "$BACKUP_PASSPHRASE" -o "$TMP/db.dump" --decrypt "$DB_FILE"
[ -z "$FILES" ] || gpg --batch --pinentry-mode loopback --passphrase "$BACKUP_PASSPHRASE" -o "$TMP/storage.tar" --decrypt "$FILES"

$COMPOSE stop app worker
$COMPOSE exec -T db pg_restore -U postgres -d abdex --clean --if-exists --no-owner --role=abdex < "$TMP/db.dump"
if [ -n "$FILES" ]; then
  $COMPOSE run --rm --no-deps -T --entrypoint sh app -c "rm -rf /data/storage/* && tar -C /data -xf -" < "$TMP/storage.tar"
fi
$COMPOSE up -d app worker
echo "restored"
