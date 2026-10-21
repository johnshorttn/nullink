#!/usr/bin/env python3
"""Deploy one verified commit from origin/<branch> with rollback.

Safe update (2026-10-21): the checkout only ever moves by ``git merge --ff-only``. Deploys are
refused (logged + alert to Morc via Nullink /api/admin/reply) when tracked files have local
changes, the checkout is not on the configured branch, or the update is not a fast-forward.
A tarball of tracked files is written before updating; a failed health check rolls back with
``git reset --keep <previous>`` (refuses to discard local changes), never ``--hard``.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

CONFIG_FILE = Path(os.environ.get("SERVER_DEPLOY_CONFIG", "/etc/server-deploy/repos.json"))
STATE = Path(os.environ.get("SERVER_DEPLOY_STATE", "/var/lib/server-deploy"))
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]+\.service$")


def run(args: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        capture_output=True,
        timeout=300,
    )


def git(repo_path: Path, *args: str, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    # The hook runs as root while the checkout is owned by the service user;
    # trust only this configured repo path (avoids git "dubious ownership").
    return run(
        ["/usr/bin/git", "-c", f"safe.directory={repo_path}", *args],
        cwd=cwd or repo_path,
        check=check,
    )


def health_ok(check: dict, attempts: int = 15) -> bool:
    url = str(check.get("url") or "")
    expected_status = int(check.get("status") or 200)
    expected_json = check.get("json")
    if not url.startswith("http://127.0.0.1:"):
        raise RuntimeError("health checks must use a localhost URL")
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                body = response.read()
                if response.status != expected_status:
                    continue
                if expected_json is not None:
                    data = json.loads(body)
                    if not all(data.get(key) == value for key, value in expected_json.items()):
                        continue
                    return True
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def restart(services: list[str]) -> None:
    for service in services:
        if not SERVICE_RE.fullmatch(service):
            raise RuntimeError("invalid service name in deployment configuration")
        run(["/usr/bin/systemctl", "restart", service])


class Refused(RuntimeError):
    pass


def alert(repository: str, message: str) -> None:
    """Best-effort alert to Morc via the Nullink localhost admin reply path."""
    line = json.dumps({"ts": int(time.time()), "repository": repository, "message": message})
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        with (STATE / "deploy_alerts.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    url = os.environ.get("NULLINK_ALERT_URL", "http://127.0.0.1:8766/api/admin/reply")
    if not url:
        return
    try:
        req = urllib.request.Request(url, data=json.dumps({"text": f"[deploy hook] {repository}: {message}"}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass


def refuse(repository: str, reason: str, detail: str = "") -> None:
    alert(repository, f"deploy refused: {reason}" + (f" — {detail}" if detail else ""))
    raise Refused(f"refusing to deploy: {reason}")


def backup_tracked(repo_path: Path, repository: str, commit: str, keep: int = 10) -> Path:
    """Tarball of tracked files (working tree) before updating; keeps the newest ``keep``."""
    out_dir = STATE / "backups"
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    name = f"{repository.replace('/', '__')}-{commit[:12]}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.tgz"
    out = out_dir / name
    files = git(repo_path, "ls-files", "-z").stdout
    import tarfile
    with tarfile.open(out, "w:gz") as tar:
        for rel in filter(None, files.split("\0")):
            p = repo_path / rel
            if p.is_file() and not p.is_symlink():
                tar.add(p, arcname=rel, recursive=False)
    os.chmod(out, 0o600)
    olds = sorted(out_dir.glob(f"{repository.replace('/', '__')}-*.tgz"), key=lambda x: x.stat().st_mtime)
    for old in olds[:-keep]:
        old.unlink(missing_ok=True)
    return out


def load_config(repository: str) -> dict:
    if not REPO_RE.fullmatch(repository):
        raise RuntimeError("invalid repository name")
    data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    config = (data.get("repositories") or {}).get(repository)
    if not isinstance(config, dict):
        raise RuntimeError("repository is not approved for deployment")
    repo_path = Path(str(config.get("path") or "")).resolve()
    if repo_path == Path("/opt") or Path("/opt") not in repo_path.parents:
        raise RuntimeError("deployment path must be a child of /opt")
    config["resolved_path"] = repo_path
    return config


def deploy(repository: str, commit: str) -> None:
    if not SHA_RE.fullmatch(commit):
        raise RuntimeError("invalid commit")
    config = load_config(repository)
    repo_path: Path = config["resolved_path"]
    branch = str(config.get("branch") or "main")
    services = [str(item) for item in (config.get("services") or [])]
    health_checks = list(config.get("health_checks") or [])
    test_commands = list(config.get("test_commands") or [])
    if not services or not health_checks:
        raise RuntimeError("services and health_checks are required")
    STATE.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE, 0o700)
    with (STATE / "deploy.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return

        dirty = git(repo_path, "status", "--porcelain", "--untracked-files=no").stdout.strip()
        if dirty:
            refuse(repository, "tracked production changes present", dirty[:500])
        current = git(repo_path, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
        if current != branch:
            refuse(repository, f"checkout is on {current!r}, not {branch!r}")

        previous = git(repo_path, "rev-parse", "HEAD").stdout.strip()
        git(repo_path, "fetch", "--prune", "origin", branch)
        if git(repo_path, "merge-base", "--is-ancestor", commit, f"origin/{branch}", check=False).returncode != 0:
            raise RuntimeError(f"requested commit is not reachable from origin/{branch}")
        if previous == commit:
            return
        if git(repo_path, "merge-base", "--is-ancestor", previous, commit, check=False).returncode != 0:
            refuse(repository, f"{commit[:12]} is not a fast-forward of {previous[:12]}")

        stage = Path(tempfile.mkdtemp(prefix="stage-", dir=STATE))
        try:
            git(repo_path, "worktree", "add", "--detach", str(stage), commit)
            for command in test_commands:
                if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
                    raise RuntimeError("test commands must be non-empty argument arrays")
                run(command, cwd=stage)

            backup = backup_tracked(repo_path, repository, previous)
            merged = git(repo_path, "merge", "--ff-only", commit, check=False)
            if merged.returncode != 0:
                refuse(repository, "git merge --ff-only failed", (merged.stderr or "")[:500])
            try:
                restart(services)
                if not all(health_ok(check) for check in health_checks):
                    raise RuntimeError("health check failed after deployment")
            except Exception as exc:
                git(repo_path, "reset", "--keep", previous)
                restart(services)
                ok = all(health_ok(check) for check in health_checks)
                alert(repository, f"deploy of {commit[:12]} failed ({exc}); rolled back to {previous[:12]}"
                      + ("" if ok else " BUT ROLLBACK HEALTH CHECK FAILED"))
                if not ok:
                    raise RuntimeError("deployment and rollback health checks failed")
                raise

            record = {
                "ok": True,
                "repository": repository,
                "commit": commit,
                "previous": previous,
                "backup": str(backup),
                "deployed_at": int(time.time()),
            }
            safe_name = repository.replace("/", "__")
            (STATE / f"last_deploy__{safe_name}.json").write_text(json.dumps(record, indent=2) + "\n")
        finally:
            git(repo_path, "worktree", "remove", "--force", str(stage), check=False)
            shutil.rmtree(stage, ignore_errors=True)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: deploy_worker.py OWNER/REPO COMMIT_SHA")
    try:
        deploy(sys.argv[1].lower(), sys.argv[2].lower())
    except Exception as exc:
        STATE.mkdir(parents=True, exist_ok=True)
        (STATE / "last_error.json").write_text(json.dumps({
            "ok": False,
            "repository": sys.argv[1] if len(sys.argv) > 1 else None,
            "error": str(exc),
            "failed_at": int(time.time()),
        }, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
