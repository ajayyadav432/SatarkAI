"""Automatic checking: messages that arrive by themselves (SMS app, inbox watcher, Gmail in the browser).

- ingest() analyses one message, saves it as a case and, if it is risky, adds it to the live alert feed.
- The same message (same source + ref) is analysed only once while the server runs.
- alerts_after() is what the web app polls to pop up a notification.
"""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import OrderedDict, deque

from app import config, db
from app.analysis.pipeline import analyze
from app.analysis.scoring import level_rank

ALERT_FROM_LEVEL = "Medium"
_MAX_SEEN = 2000
_MAX_ALERTS = 200

_lock = threading.Lock()
_seen: OrderedDict[str, dict] = OrderedDict()     # "source:ref" -> summary
_alerts: deque[dict] = deque(maxlen=_MAX_ALERTS)
_seq = 0


def token() -> str | None:
    """Pairing code the phone app must send. Set SATARK_TOKEN in .env."""
    return config.env("SATARK_TOKEN")


def token_ok(given: str | None) -> bool:
    expected = token()
    return bool(expected and given and hmac.compare_digest(expected.encode(), given.encode()))


def new_token() -> str:
    return secrets.token_urlsafe(9)


def _summary(result: dict, case_id: int | None, source: str) -> dict:
    return {
        "case_id": case_id, "source": source, "level": result["level"], "score": result["score"],
        "category": result.get("category"), "summary": result.get("summary"),
        "reasons": [f["title"] for f in result.get("factors", [])[:3]],
        "advice": (result.get("advice") or [])[:2],
        "sender": result.get("sender"), "channel": result.get("channel"),
    }


def ingest(text: str, channel: str, sender: str | None, source: str, ref: str | None = None) -> dict:
    key = f"{source}:{ref}" if ref else None
    if key:
        with _lock:
            if key in _seen:
                return {**_seen[key], "duplicate": True}
    result = analyze(text[: config.MAX_TEXT_CHARS], channel=channel, sender=sender, lookup=False)
    case_id = db.save_case(result, source=source)
    out = _summary(result, case_id, source)
    global _seq
    with _lock:
        if key:
            _seen[key] = out
            while len(_seen) > _MAX_SEEN:
                _seen.popitem(last=False)
        if level_rank(result["level"]) >= level_rank(ALERT_FROM_LEVEL):
            _seq += 1
            _alerts.append({**out, "seq": _seq, "time": time.time(), "snippet": text[:140]})
    return {**out, "duplicate": False}


def alerts_after(seq: int) -> dict:
    with _lock:
        items = [a for a in _alerts if a["seq"] > seq]
        return {"latest": _seq, "alerts": items}
