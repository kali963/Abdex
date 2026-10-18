#!/bin/sh
# Creates the secrets of a new installation once. Keep a copy of deploy/secrets/ and .env.production in a safe
# place outside the server: without the field keys the encrypted IIN / IBAN / phone fields cannot be read.
set -e
cd "$(dirname "$0")"
mkdir -p secrets
chmod 700 secrets
if [ -s secrets/field_keys ]; then
  echo "secrets/field_keys already exists — not overwritten"
else
  python3 -c "import base64,os;print('1:'+base64.b64encode(os.urandom(32)).decode())" > secrets/field_keys
  echo "secrets/field_keys created"
fi
# readable only by the application user of the image (uid 10001): compose mounts the file as it is on disk
chown 10001 secrets/field_keys 2>/dev/null || echo "run as root (or: sudo chown 10001 secrets/field_keys)"
chmod 400 secrets/field_keys
rnd() { python3 -c "import secrets;print(secrets.token_urlsafe($1))"; }
echo
echo "Put these into .env.production (once):"
echo "SECRET_KEY=$(rnd 48)"
echo "FIELD_INDEX_KEY=$(python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())")"
echo "POSTGRES_SUPERUSER_PASSWORD=$(rnd 24)"
echo "APP_DB_PASSWORD=$(rnd 24)"
echo "METRICS_TOKEN=$(rnd 24)"
echo "PAYMENT_WEBHOOK_SECRET=$(rnd 32)"
echo "TELEGRAM_WEBHOOK_SECRET=$(rnd 24)"
echo "BACKUP_PASSPHRASE=$(rnd 32)"
