# Nullink Master MCP v1

Adds ten administrative tools to the six existing Nullink messaging tools.
The existing `/mcp` endpoint and chat token retain their original permissions.
A separately authenticated `/master/mcp` endpoint talks over a group-restricted
Unix socket to a single persistent Codex worker. No new public listening port.

## Tools

| Tool | Behavior |
|---|---|
| master_capabilities | Configured projects, services, UID, sandbox, limits |
| server_status | Load, disk, hostname, Codex executable existence |
| repo_status | Allowlisted repository branch and dirty files |
| service_status | Allowlisted systemd service state |
| agent_start_task | Queue prompt; explicit project and retry key required |
| agent_task_status | State, session ID, exit code and latest output |
| agent_list_tasks | Last 50 tasks |
| agent_reply | Resume a finished session as a new task |
| agent_cancel_task | Cancel queued work or kill running process group |
| master_audit | Last 100 lifecycle records without prompts |

Codex handles coding, package installation, diagnostics, tests, and deployments
within the configured OS privileges and sandbox. This is not a generic shell
RPC. Task prompts are administrative instructions with the same practical power
as the worker. The project list selects working directories; it is NOT a
filesystem boundary in full-access mode. One administrator identity owns this
endpoint; it is not a multi-user permissions system.

## Job semantics

SQLite persists jobs and an audit trail. One job runs at a time; up to 20 active
or queued jobs are accepted. Reusing a request_key returns the original job only
when its project, parent and prompt match. A restart marks previously running
jobs interrupted and continues queued jobs; it never silently repeats an
interrupted job. systemd KillMode=control-group clears child processes on stop.
Cancellation kills the process group and does not roll back changes. Processes
that deliberately detach are outside per-job process-group cancellation; use
systemd service stop for whole-worker cleanup.

Default job timeout: 30 minutes. Output limit: 2 MiB, with a 32,768-character rolling tail
returned by status. Inspect Codex's own saved session for older output. Prompts
and output remain in the private database and may contain secrets; no universal
redaction is claimed. No automated retention purge is implemented yet. Audit
records exclude prompts, but a root worker is not a tamper-proof audit boundary.
`agent_reply` requires a finished task with a captured session UUID. It does not
provide live steering or answer an interactive approval prompt. Noninteractive
Codex uses approval policy `never`: commands requiring approval are not handled
interactively. Choose the server-side sandbox deliberately.

## Deployment (on the VPS, root)

Do not reset, stash, or overwrite the dirty `/opt/nullink` working tree. Obtain
this branch in a SEPARATE checkout, run the tests, and deploy these four Python
files together into `/opt/nullink-master`:
`master_worker.py`, `master_gateway.py`, `mcp_http_server.py`, `mcp_server.py`.
The last two are the matching shared transport and messaging adapter versions.

1. Create a dedicated system group and user `nullink-master` with no login shell.
   Create `/opt/nullink-master` root-owned 0755 and `/etc/nullink-master`
   root:nullink-master 0750. Copy Python files root-owned 0644.
2. Copy `deploy/master-config.json.example` to
   `/etc/nullink-master/config.json` as root-owned 0600. Set `codex_bin` to
   the absolute result of `command -v codex` from the account used by the worker.
   The supplied worker unit runs as root because this deployment targets server
   administration. The example sandbox is `workspace-write`; for explicitly
   authorized full-server operations set it to `danger-full-access`.
   This grants the agent production-level control. Running as a dedicated
   non-root account is also supported by adjusting the unit, state directory,
   project access and Codex login accordingly.
3. Generate a NEW admin token with `openssl rand -hex 32`, redirect it directly
   into `/etc/nullink-master/admin-token`, and set root:nullink-master 0640.
   Do not put it in Git, a prompt, URL, shell history, or logs.
4. For messaging tools on this endpoint, copy the existing scoped chat token
   into `/etc/nullink-master/chat-token` with root:nullink-master 0640.
   Never reuse that token as the admin token. If omitted, administrative tools
   still work but authenticated messaging tools report a missing token.
5. As the worker user, run `codex --version`, `codex login status`,
   `codex exec --help`, and `codex exec resume --help`. Authenticate on the VPS
   if needed. Check support for `--json`, stdin prompts (`-`), and session resume.
   CLI version compatibility must be verified on the target before live writes.
6. Install the two supplied unit files into `/etc/systemd/system/`.
   Run `systemctl daemon-reload` then
   `systemctl enable --now nullink-master-worker nullink-master-gateway`.
7. Add the Caddy handler from `deploy/Caddyfile.master.example` to the existing
   site before its catch-all. Validate with `caddy validate --config
   /etc/caddy/Caddyfile` before reloading Caddy. Existing SSH, applications,
   `/mcp`, and deployment hooks stay unchanged.
8. Verify locally that missing/chat tokens get 401 on port 8768 and the admin
   token can initialize/list tools. Run `master_capabilities`, `repo_status`,
   and a read-only Codex task, then test cancellation before production tasks.

Expected endpoint: `https://nullink.216.158.238.236.sslip.io/master/mcp`.
This URL is proposed configuration, not proof of a live deployment.

## Connector authentication and availability

This version uses a static admin Bearer token. It DOES NOT implement OAuth,
OAuth discovery, a plugin marketplace package, or Secure MCP Tunnel enrollment.
Use a client capable of securely supplying an Authorization Bearer header. If
the ChatGPT connector UI cannot configure that header, do not disable auth:
add a reviewed OAuth integration or supported authenticated MCP tunnel before
connecting. Installing these files does not itself expose tools in this chat.

HTTP binds only to 127.0.0.1. Requests with an Origin header are rejected unless
that origin is listed in MASTER_ALLOWED_ORIGINS (comma-separated, exact match).
The worker socket must never be published through Caddy or a TCP forwarder.
Keep root credentials, token files, and the private database out of repositories.

## Validation and rollback

Run `python3 -m unittest discover -s tests -v` from the checkout. Tests use a
fake local Codex executable, never a paid model or the VPS. They exercise
queueing, execution, resume routing, duplicate protection, cancellation,
timeout, output limits, restart recovery, allowlists and token separation.
A real authenticated Codex run and a ChatGPT connector handshake are deployment
gates and were not verified by these tests.

Rollback: stop/disable only `nullink-master-gateway` and
`nullink-master-worker`, remove only the `/master/*` Caddy handler, validate and
reload Caddy. Keep `/var/lib/nullink-master` for investigation. Existing Nullink
services need no change.

## Extension points

Add tool schemas in master_gateway.py and dispatch in Worker.call. Keep fixed
read-only diagnostics separate from asynchronous mutations. Future releases
can add OAuth identities and scopes, per-project workers, live app-server
steering, artifact downloads, backup/restore workflows, retention policies and
multi-host routing. None of those are implied to exist in v1.
