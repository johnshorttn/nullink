#!/usr/bin/env python3
"""Register a box path into the Nullink vault (safe copy).

Usage:
  python3 register_file.py /workspace/chat-bridge/foo.txt [label_id ...]
  python3 register_file.py /workspace/athenaeum/notes.md nullink
"""
from __future__ import annotations
import json
import sys
import urllib.request
from pathlib import Path

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: register_file.py <path> [label_id ...]", file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    labels = sys.argv[2:] or ["inbox"]
    body = json.dumps({"path": path, "labels": labels}).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8766/api/files/register",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        print(resp.read().decode())

if __name__ == "__main__":
    main()
