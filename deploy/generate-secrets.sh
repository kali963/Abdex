#!/bin/sh
# Creates the secrets of a new installation once (re-running keeps existing files, adds missing ones). Keep a
# copy of deploy/secrets/ and .env.production in a safe place outside the server: without the field keys the
# encrypted IIN / IBAN / phone fields cannot be read, without the audit archive key the archive cannot be checked.
set -e
cd "$(dirname "$0")"
mkdir -p secrets
chmod 700 secrets
rnd() { python3 -c "import secrets;print(secrets.token_urlsafe($1))"; }

# mk <file> <owner uid> <mode> <command printing the value>
mk() {
  if [ -s "secrets/$1" ]; then
    echo "secrets/$1 already exists — not overwritten"
  else
    sh -c "$4" > "secrets/$1"
    echo "secrets/$1 created"
  fi
  chown "$2" "secrets/$1" 2>/dev/null || echo "run as root (or: sudo chown $2 secrets/$1)"
  chmod "$3" "secrets/$1"
}
# read by the application user of the image (uid 10001): compose mounts the files as they are on disk
mk field_keys 10001 400 "python3 -c \"import base64,os;print('1:'+base64.b64encode(os.urandom(32)).decode())\""
mk audit_archive_key 10001 400 "python3 -c \"import secrets;print(secrets.token_urlsafe(48))\""
# read by the application and by Prometheus (another user): the directory itself stays closed (700)
mk metrics_token 10001 444 "python3 -c \"import secrets;print(secrets.token_urlsafe(32))\""
# passwords of the first accounts (INITIAL_ADMIN_* / INITIAL_USER_* in .env.production): read them with
#   sudo cat deploy/secrets/initial_admin_password
# and change them after the first sign-in — the files are only used when the account is created
mk initial_admin_password 10001 400 "python3 -c \"import secrets;print(secrets.token_urlsafe(18))\""
mk initial_user_password 10001 400 "python3 -c \"import secrets;print(secrets.token_urlsafe(18))\""
# Telegram bot token for alerts (monitoring profile): put the token of the alerts bot into this file
[ -e secrets/alert_telegram_token ] || : > secrets/alert_telegram_token
chmod 444 secrets/alert_telegram_token

echo
echo "Put these into .env.production (once):"
echo "SECRET_KEY=$(rnd 48)"
echo "FIELD_INDEX_KEY=$(python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())")"
echo "POSTGRES_SUPERUSER_PASSWORD=$(rnd 24)"
echo "APP_DB_PASSWORD=$(rnd 24)"
echo "PAYMENT_WEBHOOK_SECRET=$(rnd 32)"
echo "TELEGRAM_WEBHOOK_SECRET=$(rnd 24)"
echo "BACKUP_PASSPHRASE=$(rnd 32)"
