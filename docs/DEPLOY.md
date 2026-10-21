# Nullink deploys

Prod (`/opt/nullink`, `nullink.service`) is deployed by the signed GitHub hook
(`nullink-deploy-hook.service` → `deploy/deploy_worker.py`) on every push to `main`:
fetch, run the test suite in a staged worktree, move to the merged commit, restart, health-check,
and automatically roll back if the health check fails.

- `.git` must stay owned by `morc` (fixed 2026-10-21 after root-owned objects blocked fetches).
- Never edit tracked files on prod by hand: the hook refuses to deploy over tracked changes.
- Backups: `~morc/nullink-backups/` (files.json + code tarballs, mode 600).

- 2026-10-21: hook verified after safe.directory fix (PR #17).
