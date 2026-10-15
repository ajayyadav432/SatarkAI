"""User accounts and login sessions.

- Passwords are hashed with scrypt (Python standard library) and a random salt per user.
- A session is a random token in an HttpOnly cookie; the database keeps only its SHA-256.
- The first account registered on this laptop becomes admin. Accounts registered from another
  device are always ordinary users, so nobody on the Wi-Fi can make themselves admin.
- Too many wrong passwords from one address pause logins from it for a while.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request

from app import config, db

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
ROLES = ("user", "admin")

_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}
_FAILS_MAX = 8            # wrong passwords per address ...
_FAILS_WINDOW = 10 * 60   # ... within this many seconds
_fails: dict[str, list[float]] = {}
_fails_lock = threading.Lock()


class AuthError(ValueError):
    """A login or registration problem the user can fix; the message is shown to them."""


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), **_SCRYPT)
    except ValueError:
        return False
    return hmac.compare_digest(got.hex(), digest)


def _public(row) -> dict:
    return {"id": row["id"], "username": row["username"], "role": row["role"],
            "blocked": bool(row["blocked"]), "created_at": row["created_at"]}


def register(username: str, password: str, local: bool) -> dict:
    """Create an account. local: the request came from this laptop (only then can it become admin)."""
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise AuthError("Username: 3-30 letters, digits, dot, dash or underscore.")
    if len(password or "") < config.PASSWORD_MIN:
        raise AuthError(f"Password: at least {config.PASSWORD_MIN} characters.")
    if len(password) > 200:
        raise AuthError("Password is too long.")
    with db.connect() as con:
        if con.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise AuthError("This username is taken.")
        has_admin = con.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
        role = "admin" if local and not has_admin else "user"
        cur = con.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                          (username, hash_password(password), role, db.now_iso()))
        row = con.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _public(row)


def _too_many_fails(addr: str) -> bool:
    now = time.time()
    with _fails_lock:
        recent = [t for t in _fails.get(addr, []) if now - t < _FAILS_WINDOW]
        _fails[addr] = recent
        return len(recent) >= _FAILS_MAX


def _note_fail(addr: str) -> None:
    with _fails_lock:
        _fails.setdefault(addr, []).append(time.time())


def login(username: str, password: str, addr: str) -> dict:
    if _too_many_fails(addr):
        raise AuthError("Too many wrong passwords. Wait 10 minutes and try again.")
    with db.connect() as con:
        row = con.execute("SELECT * FROM users WHERE username = ?", ((username or "").strip(),)).fetchone()
    if not row or not check_password(password or "", row["password_hash"]):
        _note_fail(addr)
        raise AuthError("Wrong username or password.")
    if row["blocked"]:
        raise AuthError("This account is blocked by an admin.")
    return _public(row)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    with db.connect() as con:
        con.execute("DELETE FROM sessions WHERE expires_at < ?", (db.now_iso(),))
        con.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                    (_token_hash(token), user_id, db.now_iso(),
                     (now + timedelta(days=config.SESSION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    return token


def end_session(token: str | None) -> None:
    if token:
        with db.connect() as con:
            con.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def user_for_token(token: str | None) -> dict | None:
    if not token or len(token) > 100:
        return None
    with db.connect() as con:
        row = con.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ? AND s.expires_at > ? AND u.blocked = 0",
            (_token_hash(token), db.now_iso())).fetchone()
    return _public(row) if row else None


# --- FastAPI dependencies ----------------------------------------------------

def current_user(request: Request) -> dict | None:
    return user_for_token(request.cookies.get(config.SESSION_COOKIE))


def require_user(request: Request) -> dict:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Log in first.")
    return user


def require_admin(request: Request) -> dict:
    user = require_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only an admin can do this.")
    return user


# --- admin: user management --------------------------------------------------

def list_users() -> list[dict]:
    with db.connect() as con:
        rows = con.execute(
            "SELECT u.*, (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) AS posts "
            "FROM users u ORDER BY u.id").fetchall()
    return [{**_public(r), "posts": r["posts"]} for r in rows]


def update_user(user_id: int, actor: dict, role: str | None = None, blocked: bool | None = None) -> dict | None:
    if user_id == actor["id"] and (role == "user" or blocked):
        raise AuthError("You cannot remove your own admin rights or block yourself.")
    with db.connect() as con:
        if not con.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
            return None
        if role is not None:
            con.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if blocked is not None:
            con.execute("UPDATE users SET blocked = ? WHERE id = ?", (int(blocked), user_id))
            if blocked:
                con.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _public(row)
