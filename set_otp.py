#!/usr/bin/env python3
"""Set a 6-digit OTP for the Nullink chat bridge.

Usage:
  python3 set_otp.py            # random PIN
  python3 set_otp.py 123456     # explicit PIN
"""
from __future__ import annotations

import hashlib
import json
import random
import secrets
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
SECRETS = BASE / "secrets"
OTP_FILE = SECRETS / "otp.json"
CURRENT = SECRETS / "CURRENT_PIN.txt"
RATE_FILE = BASE / "data" / "rate_limit.json"


def hash_pin(pin: str, salt: str) -> str:
    return hashlib.sha256((salt + pin).encode()).hexdigest()


def main() -> None:
    SECRETS.mkdir(parents=True, exist_ok=True)
    (BASE / "data").mkdir(parents=True, exist_ok=True)

    if len(sys.argv) > 1:
        pin = sys.argv[1].strip()
    else:
        pin = f"{random.randint(0, 999999):06d}"

    if not (pin.isdigit() and len(pin) == 6):
        print("PIN must be exactly 6 digits", file=sys.stderr)
        sys.exit(1)

    ttl = 24 * 3600
    salt = secrets.token_hex(16)
    now = time.time()
    data = {
        "pin_hash": hash_pin(pin, salt),
        "salt": salt,
        "expires_at": now + ttl,
        "created_at": now,
    }
    OTP_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    OTP_FILE.chmod(0o600)
    CURRENT.write_text(pin + "\n", encoding="utf-8")
    CURRENT.chmod(0o600)
    RATE_FILE.write_text(json.dumps({"fails": 0, "locked_until": 0}), encoding="utf-8")
    print(f"OTP set. Clear PIN written to {CURRENT}")
    print(f"PIN: {pin}")
    print(f"Expires in {ttl // 3600}h")


if __name__ == "__main__":
    main()
