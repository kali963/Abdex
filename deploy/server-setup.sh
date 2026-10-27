#!/bin/sh
# Prepares a fresh Ubuntu 22.04 / 24.04 server (in a data centre in Kazakhstan) for AbdEX. Run once as root:
#
#   sudo sh deploy/server-setup.sh
#
# Installs Docker, opens only SSH/80/443 in the firewall, synchronises the clock (chrony — the security journal
# needs exact time, SEC-LOG-07), blocks SSH password guessing (fail2ban), turns on automatic security updates,
# installs gpg + rclone for the backups and the daily backup cron job. Safe to run again.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/abdex}"
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q ca-certificates curl gnupg ufw chrony fail2ban unattended-upgrades rclone python3

# --- Docker (official repository) ---
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
# container logs are rotated by the compose file; the daemon keeps live-restore for updates without downtime
[ -f /etc/docker/daemon.json ] || echo '{"live-restore": true}' > /etc/docker/daemon.json
systemctl enable --now docker

# --- firewall: only SSH and the web. Docker publishes 80/443 itself; Prometheus/Alertmanager bind to 127.0.0.1 ---
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

# --- time: chrony keeps the clock exact (Kazakhstan NTP servers first) ---
if ! grep -q "kz.pool.ntp.org" /etc/chrony/chrony.conf; then
  sed -i 's/^pool /#pool /' /etc/chrony/chrony.conf
  printf 'pool kz.pool.ntp.org iburst maxsources 4\npool pool.ntp.org iburst maxsources 2\n' >> /etc/chrony/chrony.conf
fi
systemctl enable --now chrony
systemctl restart chrony

# --- SSH brute force protection ---
cat > /etc/fail2ban/jail.d/abdex.conf <<'EOF'
[sshd]
enabled = true
maxretry = 5
findtime = 10m
bantime = 1h
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# --- automatic security updates (no automatic reboot: plan reboots in a quiet hour) ---
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# --- backups: directories, daily cron at 03:15 server time, log rotation ---
mkdir -p "$BACKUP_DIR/wal" "$BACKUP_DIR/status" "$BACKUP_DIR/daily"
chmod 700 "$BACKUP_DIR"
chmod +x "$DEPLOY_DIR/backup.sh" "$DEPLOY_DIR/restore.sh" "$DEPLOY_DIR/generate-secrets.sh"
cat > /etc/cron.d/abdex-backup <<EOF
# AbdEX daily backup (OPS-05)
15 3 * * * root BACKUP_DIR=$BACKUP_DIR $DEPLOY_DIR/backup.sh >> /var/log/abdex-backup.log 2>&1
EOF
chmod 644 /etc/cron.d/abdex-backup
cat > /etc/logrotate.d/abdex-backup <<'EOF'
/var/log/abdex-backup.log {
  weekly
  rotate 12
  compress
  missingok
  notifempty
}
EOF

echo
echo "Server ready. Next (docs/launch.md):"
echo "  1. cd $DEPLOY_DIR && ./generate-secrets.sh"
echo "  2. cp .env.production.example .env.production   # fill it in"
echo "  3. docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build"
echo "  4. rclone config   # off-site copy of the backups (BACKUP_REMOTE), storage in Kazakhstan"
echo "  5. disable SSH password login once your key works: PasswordAuthentication no in /etc/ssh/sshd_config"
