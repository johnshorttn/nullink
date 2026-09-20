# Nullink

Private HTTPS AI workspace bridge — roster, chat, Desktop/Android, Files, Playground, wake/presence, and MCP agent adapter.

## Status

Fluid redesign slices 1–4 are live (responsive shell, Pixel nav, component tokens, desktop adaptive panels).

## Agents

- **Morc** — Chief of Staff / orchestrator
- **Jinx** — ChatGPT agent identity (dedicated VPS login `jinx`)
- **Forge** — builder guild

## Quick start

See `NULLINK-PLAYBOOK.md` and `HOST.txt` for deploy notes. Runtime secrets stay out of this repo (see `secrets/README.md`).

## Human authentication

Nullink supports two login methods side by side:

- the existing expiring six-digit PIN;
- RFC 6238 TOTP codes from Google Authenticator, LastPass Authenticator, Microsoft Authenticator, Authy, or another compatible app.

Sign in with the current PIN, open **Authenticator security**, enter the displayed setup key in the authenticator app, and confirm one generated code. Nullink then provides eight single-use recovery codes. The authenticator secret is stored only in `secrets/totp.json` with mode `0600`; it and the recovery codes must never be committed or pasted into chat. TOTP remains usable when a fresh Nullink PIN cannot be obtained.

## VPS deployments

`deploy/deploy_webhook.py` provides a signed GitHub push deployment hook shared by approved repositories on the server. Repository-specific paths, branches, tests, services, and health checks live in root-owned configuration. See [docs/SERVER-DEPLOY.md](docs/SERVER-DEPLOY.md).

## License

Private — all rights reserved.
