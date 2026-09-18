#!/usr/bin/env python3
"""Append an assistant reply to the Nullink chat bridge.

Usage:
  python3 reply.py "Hello John"
  python3 reply.py --session morc "Hello"
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
MESSAGES = BASE / "data" / "messages.jsonl"


def main() -> None:
    args = sys.argv[1:]
    session_id = "morc"
    if args and args[0] == "--session" and len(args) >= 3:
        session_id = args[1]
        text = " ".join(args[2:])
    else:
        text = " ".join(args)

    text = text.strip()
    if not text:
        print("Usage: reply.py \"message text\"", file=sys.stderr)
        sys.exit(1)

    MESSAGES.parent.mkdir(parents=True, exist_ok=True)
    now = time.strftime("%Y-%m-%dT%H:%M:%S") + time.strftime("%z")
    if len(now) >= 5 and now[-5] in "+-" and ":" not in now[-5:]:
        now = now[:-2] + ":" + now[-2:]
    msg = {
        "role": "assistant",
        "text": text,
        "ts": now,
        "session_id": session_id,
    }
    with MESSAGES.open("a", encoding="utf-8") as f:
        f.write(json.dumps(msg, ensure_ascii=False) + "\n")
    print(f"OK: assistant reply appended ({len(text)} chars)")


if __name__ == "__main__":
    main()
