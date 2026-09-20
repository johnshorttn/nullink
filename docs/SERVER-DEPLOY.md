# Server deployment hook

The deployment hook is a reusable, signed GitHub push receiver for approved repositories on this VPS.

## Security model

- Public traffic reaches only `POST /__deploy/github` through HTTPS/Caddy.
- The Python receiver binds to `127.0.0.1:8768` and verifies `X-Hub-Signature-256` before parsing a deployment.
- Only repositories listed in root-owned `/etc/server-deploy/repos.json` are accepted.
- Each repository has an exact branch, production path below `/opt`, service allowlist, test commands, and localhost health checks.
- A requested commit must be reachable from the configured `origin/<branch>`.
- Tracked production changes stop deployment instead of being overwritten.
- Tests run in a detached worktree before production changes.
- A failed restart or health check resets the previous commit and restarts the configured services.
- Runtime secrets, uploads, databases, and other untracked files are preserved.

## Bootstrap

From the current `/opt/nullink` checkout:

```sh
sudo /opt/nullink/deploy/install-deploy-hook.sh
```

Add `deploy/Caddyfile.deploy.example` before the Nullink catch-all handler, validate Caddy, and reload it. Configure a GitHub `push` webhook for each approved repository:

- Payload URL: `https://nullink.216.158.238.236.sslip.io/__deploy/github`
- Content type: `application/json`
- Secret: the value stored in `/opt/nullink/secrets/DEPLOY_WEBHOOK_SECRET.txt`
- SSL verification: enabled
- Event: push only

Transfer the secret directly from the server into GitHub’s webhook form. Never print it in logs, Slack, chat, or commits.

## Add a repository

Edit `/etc/server-deploy/repos.json` as root. Copy the shape in `deploy/repos.json.example`, then add a GitHub push webhook using the same endpoint and server-side secret. A repository is never deployable merely because it exists on the server; it must be explicitly listed.

## Operations

```sh
systemctl status nullink-deploy-hook.service
journalctl -u nullink-deploy-hook.service
cat /var/lib/server-deploy/last_deploy__johnshorttn__nullink.json
```

The hook response only confirms that a valid deployment was queued. The per-repository state record confirms completion.
