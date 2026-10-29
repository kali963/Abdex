#!/bin/sh
# Daily backup (OPS-05), cron:  15 3 * * *  /opt/abdex/deploy/backup.sh >> /var/log/abdex-backup.log 2>&1
#
#   base-*.tar.gz.gpg     physical base backup — with the WAL archive it restores any moment (PITR)
#   db-*.dump.gpg         logical dump — the simple way to restore or to inspect
#   storage-*.tar.gpg     uploaded and generated files + the security journal archive (SEC-LOG-04)
#   wal-*.tar.gpg         transaction log segments archived since the previous run (PostgreSQL copies every
#                         segment to $BACKUP_DIR/wal itself, continuously — see docker-compose.prod.yml)
#
# Everything is encrypted (AES-256, BACKUP_PASSPHRASE) and kept BACKUP_KEEP_DAYS (30) days. With BACKUP_REMOTE
# set (an rclone remote, e.g. "kz-storage:abdex-backups" — a second server or storage in Kazakhstan) the
# encrypted files are copied there too. A successful run is recorded in $BACKUP_DIR/status/last_success,
# which the monitoring reads (alert when older than 26 hours).
set -eu
cd "$(dirname "$0")"
# read single values (the env file is for docker compose, not a shell script: values may contain <, >, spaces)
envget() { sed -n "s/^$1=//p" .env.production | tail -n 1; }
BACKUP_PASSPHRASE="$(envget BACKUP_PASSPHRASE)"
[ -n "$BACKUP_PASSPHRASE" ] || { echo "BACKUP_PASSPHRASE is empty in .env.production"; exit 1; }
BACKUP_DIR="${BACKUP_DIR:-$(envget BACKUP_DIR)}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/abdex}"
BACKUP_REMOTE="${BACKUP_REMOTE:-$(envget BACKUP_REMOTE)}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-30}"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
COMPOSE="docker compose -f docker-compose.prod.yml --env-file .env.production"
OUT="$BACKUP_DIR/daily"
mkdir -p "$OUT" "$BACKUP_DIR/status" "$BACKUP_DIR/wal-sent"
umask 077

encrypt() {  # $1 = plain file; replaced by $1.gpg
  gpg --batch --yes --pinentry-mode loopback --symmetric --cipher-algo AES256 \
      --passphrase "$BACKUP_PASSPHRASE" -o "$1.gpg" "$1"
  rm -f "$1"
}

# 1. physical base backup (tar, compressed) + the WAL it needs
$COMPOSE exec -T db pg_basebackup -U postgres -D - -Ft -X fetch -z > "$OUT/base-$STAMP.tar.gz"
encrypt "$OUT/base-$STAMP.tar.gz"

# 2. logical dump
$COMPOSE exec -T db pg_dump -U postgres -Fc abdex > "$OUT/db-$STAMP.dump"
encrypt "$OUT/db-$STAMP.dump"

# 3. files and the security journal archive
$COMPOSE exec -T app tar -C /data -cf - storage audit-archive > "$OUT/storage-$STAMP.tar"
encrypt "$OUT/storage-$STAMP.tar"

# 4. WAL segments archived since the last run, packed and encrypted for the off-site copy
# (the new mark is taken first: a segment arriving meanwhile goes into this set and the next one, never neither)
touch "$BACKUP_DIR/status/wal_mark.new"
NEW_WAL="$(find "$BACKUP_DIR/wal" -maxdepth 1 -type f ! -name '*.part' -newer "$BACKUP_DIR/status/wal_mark" 2>/dev/null || \
           find "$BACKUP_DIR/wal" -maxdepth 1 -type f ! -name '*.part')"
if [ -n "$NEW_WAL" ]; then
  # shellcheck disable=SC2086
  tar -C "$BACKUP_DIR/wal" -cf "$OUT/wal-$STAMP.tar" $(echo "$NEW_WAL" | xargs -n1 basename)
  encrypt "$OUT/wal-$STAMP.tar"
fi
mv "$BACKUP_DIR/status/wal_mark.new" "$BACKUP_DIR/status/wal_mark"

# 5. retention: encrypted sets and archived WAL older than KEEP_DAYS
find "$OUT" -name '*.gpg' -mtime "+$KEEP_DAYS" -delete
find "$BACKUP_DIR/wal" -maxdepth 1 -type f -mtime "+$KEEP_DAYS" -delete

# 6. off-site copy
if [ -n "$BACKUP_REMOTE" ]; then
  rclone copy "$OUT" "$BACKUP_REMOTE" --include '*.gpg' --max-age "$((KEEP_DAYS + 1))d"
  rclone delete "$BACKUP_REMOTE" --min-age "${KEEP_DAYS}d" --include '*.gpg' || true
fi

date -u +%s > "$BACKUP_DIR/status/last_success.new"
chmod 644 "$BACKUP_DIR/status/last_success.new"  # read by the application for the monitoring (another user)
mv "$BACKUP_DIR/status/last_success.new" "$BACKUP_DIR/status/last_success"
echo "$(date -Is) backup ok: $OUT/*-$STAMP.*.gpg${BACKUP_REMOTE:+ (copied to $BACKUP_REMOTE)}"
