#!/bin/sh
# Restore (OPS-05). Two ways:
#
#   ./restore.sh dump  <daily/db-….dump.gpg> [<daily/storage-….tar.gpg>]
#       the database as it was at that night's dump (and the files)
#
#   ./restore.sh pitr  <daily/base-….tar.gz.gpg> "<YYYY-MM-DD HH:MM:SS+05>" [<daily/storage-….tar.gpg>]
#       point in time: the base backup taken BEFORE that moment + the archived transaction logs up to it,
#       e.g. "2026-10-27 10:14:00+05" — a minute before a mistaken deletion
#
# Stops the app and the worker, replaces the data, starts them again. Practise both on a separate server once
# a quarter (OPS-05) — docs/launch.md, section "Backups".
set -eu
cd "$(dirname "$0")"
envget() { sed -n "s/^$1=//p" .env.production | tail -n 1; }
BACKUP_PASSPHRASE="$(envget BACKUP_PASSPHRASE)"
MODE="${1:-}"
COMPOSE="docker compose -f docker-compose.prod.yml --env-file .env.production"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
decrypt() { gpg --batch --pinentry-mode loopback --passphrase "$BACKUP_PASSPHRASE" -o "$2" --decrypt "$1"; }
confirm() {
  printf "This REPLACES the data of this server (%s). Type YES: " "$1"
  read -r answer
  [ "$answer" = "YES" ] || exit 1
}
restore_files() {
  [ -n "${1:-}" ] || return 0
  decrypt "$1" "$TMP/storage.tar"
  # The security journal archive is restored only onto an empty volume (a new server): on the same server it
  # already holds everything, and records newer than the restored database are set aside, never lost.
  $COMPOSE run --rm --no-deps -T --entrypoint sh app -c \
    'rm -rf /data/storage/* && if [ -z "$(ls -A /data/audit-archive 2>/dev/null)" ]; then tar -C /data -xf -; else tar -C /data -xf - storage; fi' \
    < "$TMP/storage.tar"
}

case "$MODE" in
  dump)
    DB_FILE="$2"; FILES="${3:-}"
    confirm "$DB_FILE"
    decrypt "$DB_FILE" "$TMP/db.dump"
    $COMPOSE stop app worker
    $COMPOSE exec -T db pg_restore -U postgres -d abdex --clean --if-exists --no-owner --role=abdex < "$TMP/db.dump"
    restore_files "$FILES"
    ;;
  pitr)
    BASE="$2"; TARGET="$3"; FILES="${4:-}"
    confirm "$BASE up to $TARGET"
    decrypt "$BASE" "$TMP/base.tar.gz"
    $COMPOSE stop app worker db
    # empty the data directory, unpack the base backup, ask PostgreSQL to replay the archived WAL up to TARGET
    $COMPOSE run --rm --no-deps -T --entrypoint sh db -c '
      set -e
      D=/var/lib/postgresql/data
      find "$D" -mindepth 1 -delete
      tar -xzf - -C "$D"
      touch "$D/recovery.signal"
      printf "%s\n" "restore_command = '"'"'cp /wal/%f %p'"'"'" \
                    "recovery_target_time = '"'"'$0'"'"'" \
                    "recovery_target_action = '"'"'promote'"'"'" >> "$D/postgresql.auto.conf"
      chown -R postgres:postgres "$D" && chmod 700 "$D"' "$TARGET" < "$TMP/base.tar.gz"
    $COMPOSE up -d db
    echo "replaying the transaction log up to $TARGET ..."
    i=0
    until $COMPOSE exec -T db psql -U postgres -tAc "select not pg_is_in_recovery()" 2>/dev/null | grep -q t; do
      i=$((i + 1)); [ $i -lt 360 ] || { echo "recovery did not finish — see: $COMPOSE logs db"; exit 1; }
      sleep 5
    done
    # the recovery settings are not needed any more (they only apply with recovery.signal, but keep it clean)
    $COMPOSE exec -T db psql -U postgres -q -c "ALTER SYSTEM RESET restore_command" \
      -c "ALTER SYSTEM RESET recovery_target_time" -c "ALTER SYSTEM RESET recovery_target_action" \
      -c "SELECT pg_reload_conf()" >/dev/null
    restore_files "$FILES"
    ;;
  *)
    sed -n '2,13p' "$0"; exit 2 ;;
esac
$COMPOSE up -d app worker
echo "restored"
