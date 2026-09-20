#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi

install -d -m 700 /var/lib/server-deploy
install -d -m 700 /etc/server-deploy
install -d -m 700 /opt/nullink/secrets
if [ ! -s /opt/nullink/secrets/DEPLOY_WEBHOOK_SECRET.txt ]; then
  umask 077
  openssl rand -hex 32 > /opt/nullink/secrets/DEPLOY_WEBHOOK_SECRET.txt
fi
chmod 600 /opt/nullink/secrets/DEPLOY_WEBHOOK_SECRET.txt
if [ ! -s /etc/server-deploy/repos.json ]; then
  install -m 600 /opt/nullink/deploy/repos.json.example /etc/server-deploy/repos.json
fi
install -m 644 /opt/nullink/deploy/nullink-deploy-hook.service /etc/systemd/system/nullink-deploy-hook.service
systemctl daemon-reload
systemctl enable --now nullink-deploy-hook.service

echo "Deploy hook installed on 127.0.0.1:8768."
echo "Next: add deploy/Caddyfile.deploy.example to the Nullink site and configure"
echo "a GitHub push webhook for /__deploy/github using the server-side secret."
echo "Approve more repositories by editing /etc/server-deploy/repos.json as root."
