"""Inbox watcher: checks every new e-mail in a mailbox over IMAP, without opening links or marking mail as read.

Turned on by these lines in .env (never committed):
    IMAP_USER=yourtest@gmail.com
    IMAP_PASSWORD=xxxx xxxx xxxx xxxx     (a Gmail "app password", not the normal password)
    IMAP_HOST=imap.gmail.com              (optional, this is the default)

Only mail that arrives after the watcher starts is checked. The last checked message is remembered in
data/mailwatch_state.json, so a restart does not check old mail again.
"""
from __future__ import annotations

import email
import imaplib
import json
import logging
import re
import threading
import time
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import parseaddr
from html.parser import HTMLParser

from app import config, ingest

log = logging.getLogger("satark.mailwatch")
STATE = config.ROOT / "data" / "mailwatch_state.json"
POLL_SECONDS = 20
MAX_PER_POLL = 25

status = {"enabled": False, "running": False, "user": None, "last_check": None, "checked": 0, "error": None}


class _HTMLText(HTMLParser):
    """Visible text of an HTML e-mail, plus the real target of every link (scam mails hide them)."""

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.links: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip += 1
        if tag == "a":
            href = dict(attrs).get("href") or ""
            if href.lower().startswith(("http://", "https://")):
                self.links.append(href)
        if tag in ("br", "p", "div", "tr", "li"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def message_text(msg: EmailMessage) -> tuple[str, str | None]:
    """(text to analyse, sender address) for one e-mail."""
    subject = str(msg.get("subject", "") or "")
    sender = parseaddr(str(msg.get("from", "") or ""))[1] or None
    body, links = "", []
    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    if html is not None:
        p = _HTMLText()
        p.feed(html.get_content())
        links = p.links
        if plain is None:
            body = "".join(p.parts)
    if plain is not None:
        body = plain.get_content()
    body = re.sub(r"\n\s*\n+", "\n\n", body).strip()
    hidden = [u for u in dict.fromkeys(links) if u not in body]
    text = subject + "\n\n" + body
    if hidden:
        text += "\n\nLinks in this e-mail:\n" + "\n".join(hidden[:20])
    return text[: config.MAX_TEXT_CHARS], sender


def _load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s), encoding="utf-8")


def check_once(conn: imaplib.IMAP4, user: str) -> int:
    """Analyse mail that arrived since the last check. Returns how many were analysed."""
    typ, data = conn.select("INBOX", readonly=True)
    if typ != "OK":
        raise RuntimeError("cannot open INBOX")
    typ, uv = conn.response("UIDVALIDITY")
    uidvalidity = (uv[0].decode() if uv and uv[0] else "")
    state = _load_state()
    typ, data = conn.uid("search", None, "ALL")
    uids = [int(u) for u in data[0].split()] if data and data[0] else []
    newest = max(uids, default=0)
    if state.get("user") != user or state.get("uidvalidity") != uidvalidity:
        # First run for this mailbox: start from now, do not analyse the whole inbox.
        _save_state({"user": user, "uidvalidity": uidvalidity, "last_uid": newest})
        return 0
    todo = [u for u in uids if u > state.get("last_uid", 0)][:MAX_PER_POLL]
    for uid in todo:
        typ, msgdata = conn.uid("fetch", str(uid), "(BODY.PEEK[])")   # PEEK: do not mark as read
        raw = next((part[1] for part in msgdata if isinstance(part, tuple)), None)
        if raw:
            msg = email.message_from_bytes(raw, policy=default_policy)
            text, sender = message_text(msg)
            ref = str(msg.get("message-id") or f"uid-{uidvalidity}-{uid}")
            ingest.ingest(text, "email", sender, "email-watch", ref=ref)
        state["last_uid"] = uid
        _save_state(state)
    return len(todo)


def _loop(user: str, password: str, host: str) -> None:
    status.update(running=True)
    while True:
        try:
            conn = imaplib.IMAP4_SSL(host, timeout=30)
            conn.login(user, password)
            try:
                while True:
                    n = check_once(conn, user)
                    status.update(last_check=time.time(), error=None, checked=status["checked"] + n)
                    time.sleep(POLL_SECONDS)
            finally:
                try:
                    conn.logout()
                except Exception:
                    pass
        except Exception as err:  # network down, wrong password, ...: report and retry later
            status["error"] = type(err).__name__ + ": " + str(err)[:200]
            log.warning("mail watcher: %s", status["error"])
            time.sleep(60)


def start() -> None:
    if config.env("SATARK_NO_MAILWATCH"):   # tests never touch a real mailbox
        return
    user, password = config.env("IMAP_USER"), config.env("IMAP_PASSWORD")
    host = config.env("IMAP_HOST", "imap.gmail.com")
    status.update(enabled=bool(user and password), user=user)
    if user and password:
        threading.Thread(target=_loop, args=(user, password.replace(" ", ""), host), daemon=True,
                         name="mailwatch").start()
