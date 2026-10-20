#!/usr/bin/env python3
"""Set a fresh single-use 6-digit Nullink PIN.

Usage:
  python3 set_otp.py                 # random PIN (secrets module), valid 24h
  python3 set_otp.py --ttl-hours 1   # shorter validity
  python3 set_otp.py 123456          # explicit PIN (discouraged)

The PIN is printed ONCE to stdout for Morc to relay to John. It is stored only as a
salted PBKDF2 hash in secrets/otp.json (mode 600), works for exactly one successful
login (or step-up), and is never written anywhere in clear text. Setting a PIN also
clears all login lockouts.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server  # noqa: E402  (shares the exact hashing/storage code)


def main() -> None:
    ap = argparse.ArgumentParser(description="Set a single-use Nullink PIN")
    ap.add_argument("pin", nargs="?", help="explicit 6-digit PIN (default: random)")
    ap.add_argument("--ttl-hours", type=float, default=server.PIN_TTL_SEC / 3600,
                    help="validity in hours (default 24)")
    args = ap.parse_args()

    pin = (args.pin or server.generate_pin()).strip()
    if not (pin.isdigit() and len(pin) == 6):
        print("PIN must be exactly 6 digits", file=sys.stderr)
        sys.exit(1)
    info = server.write_otp(pin, int(args.ttl_hours * 3600))
    expires = time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(info["expires_at"]))
    print(f"PIN: {pin}")
    print(f"Single-use; expires {expires} ({info['ttl_sec'] // 60} min). Not stored in clear text - relay it now.")


if __name__ == "__main__":
    main()
