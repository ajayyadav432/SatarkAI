"""Start-up for public hosting (Vercel, see api/index.py).

The host keeps no files between restarts, so every fresh server instance:
- creates the database in /tmp,
- creates the admin account from the secret SATARK_ADMIN_PASSWORD (set in the host's settings,
  never in the code), because nobody can be "on the laptop" there,
- adds the demo cases and demo feed posts (./run.sh seed), so the pages are not empty.
Anything users add lasts only as long as that instance; the page says so.
"""
from __future__ import annotations

from app import accounts, config, db


def prepare() -> None:
    db.init_db()
    with db.connect() as con:
        has_users = con.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        has_cases = con.execute("SELECT 1 FROM cases LIMIT 1").fetchone()
    password = config.env("SATARK_ADMIN_PASSWORD")
    if not has_users and password:
        accounts.register(accounts.ADMIN_NAME, password, local=True, reserve=False)
    if not has_cases and config.env("SATARK_SEED") == "1":
        from scripts import seed_demo
        seed_demo.seed()
