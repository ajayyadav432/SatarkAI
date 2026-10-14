"""Sanity check for app/data/brands.json: does every 'official' domain resolve in DNS?

This does NOT prove a domain belongs to the brand. It only catches typing mistakes.
Run:  python scripts/check_brands.py
"""
import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
socket.setdefaulttimeout(5)


def main() -> int:
    data = json.loads((ROOT / "app/data/brands.json").read_text(encoding="utf-8"))
    bad = 0
    for b in data["brands"]:
        for d in b["official_domains"]:
            ok = False
            for host in (d, "www." + d):
                try:
                    socket.getaddrinfo(host, 443)
                    ok = True
                    break
                except OSError:
                    continue
            if not ok:
                bad += 1
            print(f"{'ok  ' if ok else 'FAIL'}  {b['name']:<28} {d}")
    print(f"\n{bad} domain(s) did not resolve")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
