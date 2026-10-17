"""Authenticated relay for a Nullink Android companion.

The phone opens outbound HTTPS connections only. Folder listings and file
contents are returned on request; approved screen sessions publish short-lived
frames in memory and never create a recording.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import queue
import re
import secrets
import threading
import time
import uuid
from pathlib import Path

PAIR_CODE_TTL = 120
PAIR_ATTEMPT_WINDOW = 300
PAIR_ATTEMPT_LIMIT = 8
STAGED_TTL = 15 * 60
DEVICE_ACTIVE_TTL = 90
MAX_ROOTS = 32
MAX_STAGED_BYTES = 25 * 1024 * 1024
MAX_SCREEN_FRAME_BYTES = 768 * 1024
SCREEN_FRAME_TTL = 8
ROOT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DOC_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class PhoneBridgeError(Exception):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


class PhoneBridge:
    """Small in-memory command broker with hashed, persisted device tokens."""

    def __init__(self, data_dir: Path, staging_dir: Path):
        self.data_dir = Path(data_dir)
        self.staging_dir = Path(staging_dir)
        self.devices_path = self.data_dir / "phone_devices.json"
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._pair_codes: dict[str, float] = {}
        self._pair_attempts: dict[str, list[float]] = {}
        self._queues: dict[str, queue.Queue] = {}
        self._pending: dict[str, dict] = {}
        self._staged: dict[str, dict] = {}
        self._screen_frames: dict[str, dict] = {}
        self._screen_sequence = 0
        self._devices = self._load_devices()
        # Process restart ends every temporary file session; never resurrect
        # staged attachment bytes without the owning browser session.
        self.cleanup_staged(max_age=0)

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _load_devices(self) -> dict[str, dict]:
        try:
            raw = json.loads(self.devices_path.read_text(encoding="utf-8"))
            items = raw.get("devices") if isinstance(raw, dict) else None
            if not isinstance(items, list):
                return {}
            return {str(d["id"]): d for d in items if isinstance(d, dict) and d.get("id") and d.get("token_hash")}
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            return {}

    def _save_devices(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.devices_path.with_name(self.devices_path.name + ".tmp")
        tmp.write_text(json.dumps({"devices": list(self._devices.values())}, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.devices_path)
        try:
            os.chmod(self.devices_path, 0o600)
        except OSError:
            pass

    def create_pairing_code(self) -> dict:
        code = f"{secrets.randbelow(1_000_000):06d}"
        with self._lock:
            now = time.time()
            self._pair_codes = {k: expiry for k, expiry in self._pair_codes.items() if expiry > now}
            self._pair_codes[self._hash(code)] = now + PAIR_CODE_TTL
        return {"code": code, "expires_in": PAIR_CODE_TTL}

    def pair(self, code: str, name: str, client_key: str = "unknown") -> dict:
        normalized = str(code or "").strip().replace("-", "").replace(" ", "")
        rate_key = self._hash(str(client_key or "unknown"))
        now_mono = time.monotonic()
        with self._lock:
            attempts = [t for t in self._pair_attempts.get(rate_key, []) if now_mono - t < PAIR_ATTEMPT_WINDOW]
            if len(attempts) >= PAIR_ATTEMPT_LIMIT:
                self._pair_attempts[rate_key] = attempts
                raise PhoneBridgeError("pair_rate_limited", 429)
            attempts.append(now_mono)
            self._pair_attempts[rate_key] = attempts
        if not re.fullmatch(r"[0-9]{6}", normalized):
            raise PhoneBridgeError("invalid_pairing_code", 401)
        hashed = self._hash(normalized)
        now = time.time()
        with self._lock:
            expiry = self._pair_codes.pop(hashed, None)
            self._pair_codes = {k: value for k, value in self._pair_codes.items() if value > now}
            if expiry is None or expiry <= now:
                raise PhoneBridgeError("invalid_or_expired_pairing_code", 401)
            self._pair_attempts.pop(rate_key, None)
            device_id = uuid.uuid4().hex
            token = secrets.token_urlsafe(32)
            label = re.sub(r"[\x00-\x1f\x7f]", "", str(name or "Pixel phone")).strip()[:80] or "Pixel phone"
            self._devices[device_id] = {
                "id": device_id,
                "name": label,
                "token_hash": self._hash(token),
                "paired_at": int(now),
                "last_seen": int(now),
                "sharing": False,
                "screen_active": False,
                "roots": [],
            }
            self._save_devices()
        return {"device": self.public_device(device_id), "token": token}

    def authenticate(self, token: str | None) -> dict | None:
        if not token:
            return None
        candidate = self._hash(token)
        with self._lock:
            for device_id, device in self._devices.items():
                if hmac.compare_digest(candidate, str(device.get("token_hash") or "")):
                    device["last_seen"] = int(time.time())
                    return dict(device)
        return None

    def public_device(self, device_id: str) -> dict | None:
        with self._lock:
            device = self._devices.get(device_id)
            if not device:
                return None
            now = time.time()
            online = now - float(device.get("last_seen") or 0) <= DEVICE_ACTIVE_TTL
            frame = self._screen_frames.get(device_id)
            screen_live = bool(device.get("screen_active") and online and frame and now - frame["created"] <= SCREEN_FRAME_TTL)
            return {
                "id": device.get("id"), "name": device.get("name"),
                "paired_at": device.get("paired_at"), "last_seen": device.get("last_seen"),
                "online": online, "sharing": bool(device.get("sharing") and online),
                "screen_active": screen_live,
                "roots": list(device.get("roots") or []) if online and device.get("sharing") else [],
            }

    def list_devices(self) -> list[dict]:
        with self._lock:
            return [self.public_device(device_id) for device_id in self._devices]

    def revoke(self, device_id: str) -> bool:
        with self._changed:
            existed = self._devices.pop(device_id, None) is not None
            self._queues.pop(device_id, None)
            self._screen_frames.pop(device_id, None)
            for request_id, item in list(self._pending.items()):
                if item.get("device_id") == device_id:
                    item["error"] = "device_revoked"
                    item["event"].set()
                    self._pending.pop(request_id, None)
            for stage_id, item in list(self._staged.items()):
                if item.get("device_id") == device_id:
                    try:
                        Path(item["path"]).unlink(missing_ok=True)
                    except OSError:
                        pass
                    self._staged.pop(stage_id, None)
            self._save_devices()
            self._changed.notify_all()
            return existed

    def set_screen_active(self, device_id: str, enabled: bool) -> None:
        with self._lock:
            device = self._devices.get(device_id)
            if not device:
                raise PhoneBridgeError("device_revoked", 401)
            device["screen_active"] = bool(enabled)
            device["last_seen"] = int(time.time())
            if not enabled:
                self._screen_frames.pop(device_id, None)
            self._save_devices()

    def publish_screen_frame(self, device_id: str, body: bytes) -> int:
        if not body or len(body) > MAX_SCREEN_FRAME_BYTES:
            raise PhoneBridgeError("invalid_screen_frame", 413)
        if not body.startswith(b"\xff\xd8\xff"):
            raise PhoneBridgeError("invalid_screen_frame", 400)
        with self._lock:
            device = self._devices.get(device_id)
            if not device:
                raise PhoneBridgeError("device_revoked", 401)
            if not device.get("screen_active"):
                raise PhoneBridgeError("screen_sharing_inactive", 409)
            self._screen_sequence += 1
            sequence = self._screen_sequence
            device["last_seen"] = int(time.time())
            self._screen_frames[device_id] = {
                "sequence": sequence, "body": bytes(body), "created": time.time(),
            }
            return sequence

    def get_screen_frame(self, device_id: str, after: int = 0) -> dict | None:
        with self._lock:
            if device_id not in self._devices:
                raise PhoneBridgeError("device_not_found", 404)
            frame = self._screen_frames.get(device_id)
            if not frame or time.time() - frame["created"] > SCREEN_FRAME_TTL:
                self._screen_frames.pop(device_id, None)
                return None
            if frame["sequence"] <= max(0, int(after)):
                return None
            return dict(frame)

    def set_sharing(self, device_id: str, enabled: bool, roots: list) -> dict:
        if not isinstance(roots, list) or len(roots) > MAX_ROOTS:
            raise PhoneBridgeError("invalid_roots")
        cleaned = []
        seen = set()
        for item in roots:
            if not isinstance(item, dict):
                continue
            root_id = str(item.get("id") or "")
            name = re.sub(r"[\x00-\x1f\x7f]", "", str(item.get("name") or "Shared folder")).strip()[:120]
            if not ROOT_ID_RE.fullmatch(root_id) or root_id in seen:
                raise PhoneBridgeError("invalid_root_id")
            seen.add(root_id)
            cleaned.append({"id": root_id, "name": name or "Shared folder"})
        if enabled and not cleaned:
            raise PhoneBridgeError("no_shared_folders")
        with self._changed:
            device = self._devices.get(device_id)
            if not device:
                raise PhoneBridgeError("device_revoked", 401)
            device["sharing"] = bool(enabled)
            device["roots"] = cleaned if enabled else []
            device["last_seen"] = int(time.time())
            self._save_devices()
            self._queues.setdefault(device_id, queue.Queue())
            if not enabled:
                for request_id, item in list(self._pending.items()):
                    if item.get("device_id") == device_id:
                        item["error"] = "sharing_stopped"
                        item["event"].set()
                        self._pending.pop(request_id, None)
                self._queues[device_id] = queue.Queue()
            self._changed.notify_all()
            return self.public_device(device_id)

    def _root_allowed(self, device: dict, root_id: str) -> bool:
        online = time.time() - float(device.get("last_seen") or 0) <= DEVICE_ACTIVE_TTL
        return bool(device.get("sharing") and online) and any(r.get("id") == root_id for r in device.get("roots") or [])

    def request_phone(self, device_id: str, operation: str, root_id: str, document_id: str = "root", timeout: float = 25) -> dict:
        if operation not in ("list", "read"):
            raise PhoneBridgeError("invalid_operation")
        if not ROOT_ID_RE.fullmatch(str(root_id or "")) or not DOC_ID_RE.fullmatch(str(document_id or "")):
            raise PhoneBridgeError("invalid_document_reference")
        with self._changed:
            device = self._devices.get(device_id)
            if not device or not self._root_allowed(device, root_id):
                raise PhoneBridgeError("folder_sharing_inactive", 409)
            request_id = uuid.uuid4().hex
            event = threading.Event()
            item = {"id": request_id, "device_id": device_id, "operation": operation,
                    "root_id": root_id, "document_id": document_id, "created": time.time(),
                    "event": event, "result": None, "error": None}
            self._pending[request_id] = item
            self._queues.setdefault(device_id, queue.Queue()).put({
                "id": request_id, "operation": operation,
                "root_id": root_id, "document_id": document_id,
            })
            self._changed.notify_all()
        if not event.wait(max(0.1, min(float(timeout), 30.0))):
            with self._lock:
                self._pending.pop(request_id, None)
            raise PhoneBridgeError("phone_request_timeout", 504)
        with self._lock:
            item = self._pending.pop(request_id, item)
            if item.get("error"):
                raise PhoneBridgeError(item["error"], 409)
            result = item.get("result")
            if not isinstance(result, dict):
                raise PhoneBridgeError("invalid_phone_response", 502)
            return result

    def next_command(self, device_id: str, timeout: float = 20) -> dict | None:
        deadline = time.time() + max(0, min(float(timeout), 25.0))
        with self._changed:
            device = self._devices.get(device_id)
            if (not device or not device.get("sharing") or not device.get("roots") or
                    not any(self._root_allowed(device, str(root.get("id") or ""))
                            for root in device.get("roots", []) if isinstance(root, dict))):
                raise PhoneBridgeError("folder_sharing_inactive", 409)
            q = self._queues.setdefault(device_id, queue.Queue())
            while True:
                if not self._devices.get(device_id, {}).get("sharing"):
                    raise PhoneBridgeError("sharing_stopped", 409)
                try:
                    command = q.get_nowait()
                    pending = self._pending.get(command["id"])
                    if pending and pending["device_id"] == device_id:
                        return command
                except queue.Empty:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        return None
                    self._changed.wait(min(remaining, 1.0))

    def complete_command(self, device_id: str, request_id: str, result: dict) -> None:
        with self._lock:
            item = self._pending.get(request_id)
            if not item or item.get("device_id") != device_id:
                raise PhoneBridgeError("unknown_request", 404)
            if isinstance(result, dict) and result.get("error"):
                item["error"] = "phone_read_failed"
                item["event"].set()
                return
            if item.get("operation") != "list":
                raise PhoneBridgeError("file_bytes_required", 400)
            if not isinstance(result, dict) or not isinstance(result.get("items"), list):
                raise PhoneBridgeError("invalid_listing", 400)
            safe_items = []
            for raw in result["items"][:500]:
                if not isinstance(raw, dict):
                    continue
                document_id = str(raw.get("id") or "")
                if not DOC_ID_RE.fullmatch(document_id):
                    continue
                try:
                    size = int(raw.get("size") or 0)
                except (ValueError, TypeError, OverflowError):
                    size = 0
                safe_items.append({
                    "id": document_id,
                    "name": re.sub(r"[\x00-\x1f\x7f]", "", str(raw.get("name") or "File"))[:240],
                    "directory": bool(raw.get("directory")),
                    "mime": str(raw.get("mime") or "application/octet-stream")[:160],
                    "size": max(0, min(size, 2**53 - 1)),
                })
            item["result"] = {"items": safe_items}
            item["event"].set()

    def complete_file(self, device_id: str, request_id: str, name: str, mime: str, body: bytes) -> dict:
        if len(body) > MAX_STAGED_BYTES:
            raise PhoneBridgeError("file_too_large", 413)
        with self._lock:
            item = self._pending.get(request_id)
            if not item or item.get("device_id") != device_id:
                raise PhoneBridgeError("unknown_request", 404)
            if item.get("operation") != "read":
                raise PhoneBridgeError("listing_result_required", 400)
            clean_name = os.path.basename(str(name or "phone-file"))
            clean_name = re.sub(r"[\x00-\x1f\x7f/\\]", "_", clean_name)[:240] or "phone-file"
            safe_mime = str(mime or mimetypes.guess_type(clean_name)[0] or "application/octet-stream")[:160]
            self.staging_dir.mkdir(parents=True, exist_ok=True)
            stage_id = uuid.uuid4().hex
            path = self.staging_dir / stage_id
            with path.open("xb") as f:
                f.write(body)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            staged = {"id": stage_id, "name": clean_name, "mime": safe_mime,
                      "size": len(body), "path": str(path), "created": time.time(),
                      "request_id": request_id, "device_id": device_id}
            self._staged[stage_id] = staged
            item["result"] = {k: staged[k] for k in ("id", "name", "mime", "size")}
            item["event"].set()
            return {k: staged[k] for k in ("id", "name", "mime", "size")}

    def list_staged(self, max_age: int = STAGED_TTL) -> list[dict]:
        self.cleanup_staged(max_age)
        with self._lock:
            return [{k: item[k] for k in ("id", "name", "mime", "size", "created")}
                    for item in self._staged.values()]

    def consume_staged(self, stage_id: str) -> dict | None:
        self.cleanup_staged()
        with self._lock:
            item = self._staged.pop(stage_id, None)
            if not item:
                return None
            path = Path(item["path"])
            if not path.is_file():
                return None
            return {**item, "path": path}

    def cleanup_staged(self, max_age: int = STAGED_TTL) -> int:
        cutoff = time.time() - max_age
        removed = 0
        with self._lock:
            for stage_id, item in list(self._staged.items()):
                path = Path(item["path"])
                if float(item.get("created") or 0) < cutoff or not path.exists():
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    self._staged.pop(stage_id, None)
                    removed += 1
            # Also clear abandoned files left by a process restart.
            try:
                self.staging_dir.mkdir(parents=True, exist_ok=True)
                for path in self.staging_dir.iterdir():
                    if path.is_file() and path.stat().st_mtime < cutoff:
                        try:
                            path.unlink()
                            removed += 1
                        except OSError:
                            pass
            except OSError:
                pass
        return removed


_default_bridge = None
_default_lock = threading.Lock()


def get_bridge(data_dir: Path, staging_dir: Path) -> PhoneBridge:
    global _default_bridge
    with _default_lock:
        if _default_bridge is None:
            _default_bridge = PhoneBridge(data_dir, staging_dir)
        return _default_bridge

