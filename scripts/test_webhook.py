#!/usr/bin/env python3
"""Send a small dry-run webhook using secrets/webhook.json."""
from __future__ import annotations

import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[1] / "secrets" / "webhook.json"
TIMEOUT_SECONDS = 3


def main() -> int:
    if not CONFIG.exists():
        print(f"Webhook config missing; skipped: {CONFIG}")
        return 0
    try:
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Invalid webhook config: {exc}", file=sys.stderr)
        return 1
    if config.get("enabled") is not True:
        print("Webhook disabled; skipped dry-run")
        return 0

    url = str(config.get("url") or "").strip()
    header_name = str(config.get("header_name") or "").strip()
    header_value = str(config.get("header_value") or "")
    if not url or not header_name or not header_value:
        print("Enabled webhook config needs url, header_name, and header_value", file=sys.stderr)
        return 1

    payload = {
        "source": "nullink",
        "kind": "message",
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "hint": "test_webhook.py dry-run",
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", header_name: header_value},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            print(f"Webhook dry-run POST returned HTTP {response.status}")
            return 0 if 200 <= response.status < 300 else 1
    except Exception as exc:
        print(f"Webhook dry-run failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
