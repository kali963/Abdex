#!/bin/sh
# Daily backup (OPS-05): database dump + uploaded files, encrypted (AES-256), kept 30 days.
# cron:  15 3 * * *  /opt/abdex/deploy/backup.sh >> /var/log/abdex-backup.log 2>&1
# Then copy BACKUP_DIR to storage outside this server, in Kazakhstan (rclone / rsync).
set -eu
cd "$(dirname "$0")"
# read single values (the env file is for docker compose, not a shell script: values may contain <, >, spaces)
envget() { sed -n "s/^$1=//p" .env.production | tail -n 1; }
BACKUP_PASSPHRASE="$(envget BACKUP_PASSPHRASE)"
[ -n "$BACKUP_PASSPHRASE" ] || { echo "BACKUP_PASSPHRASE is empty in .env.production"; exit 1; }
BACKUP_DIR="${BACKUP_DIR:-$(envget BACKUP_DIR)}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/abdex}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-30}"
STAMP="$(date +%Y%m%d-%H%M%S)"
COMPOSE="docker compose -f docker-compose.prod.yml --env-file .env.production"
mkdir -p "$BACKUP_DIR"
umask 077

$COMPOSE exec -T db pg_dump -U postgres -Fc abdex > "$BACKUP_DIR/db-$STAMP.dump"
$COMPOSE exec -T app tar -C /data -cf - storage > "$BACKUP_DIR/storage-$STAMP.tar"

for f in "$BACKUP_DIR/db-$STAMP.dump" "$BACKUP_DIR/storage-$STAMP.tar"; do
  gpg --batch --yes --pinentry-mode loopback --symmetric --cipher-algo AES256 \
      --passphrase "$BACKUP_PASSPHRASE" -o "$f.gpg" "$f"
  rm -f "$f"
done
find "$BACKUP_DIR" -name '*.gpg' -mtime "+$KEEP_DAYS" -delete
echo "$(date -Is) backup ok: $BACKUP_DIR/*-$STAMP.*.gpg"
