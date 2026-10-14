"""Rule engine for suspicious language (English, Hinglish, Hindi).

Rules live in app/data/patterns.json. Each rule group fires at most once per message and
reports the exact words that triggered it. Weights are hand-set, not learned.
"""
from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache

from app import config

_FLAGS = re.I | re.U


@lru_cache(maxsize=1)
def _load() -> dict:
    data = json.loads((config.KNOWLEDGE_DIR / "patterns.json").read_text(encoding="utf-8"))
    groups = []
    for g in data["groups"]:
        compiled = []
        for lang, patterns in g["patterns"].items():
            for p in patterns:
                compiled.append((lang, re.compile(p, _FLAGS)))
        groups.append({**g, "compiled": compiled})
    neg = data["negation"]
    return {
        "groups": groups,
        "neg_before": re.compile(neg["before"], _FLAGS),
        "neg_inside": re.compile(neg["inside"], _FLAGS),
        "neg_after": re.compile(neg["after"], _FLAGS),
    }


def group_info() -> list[dict]:
    """Public description of every rule group (for the model card page)."""
    return [
        {"id": g["id"], "title": g["title"], "weight": g["weight"], "max_weight": g["max_weight"],
         "category": g["category"], "explain": g["explain"],
         "patterns": {lang: len(p) for lang, p in g["patterns"].items()}}
        for g in _load()["groups"]
    ]


def _negated(text: str, start: int, end: int, data: dict) -> bool:
    """True for 'do NOT share your OTP' style text around a match."""
    if data["neg_before"].search(text[max(0, start - 45):start]):
        return True
    if data["neg_inside"].search(text[start:end]):
        return True
    if data["neg_after"].search(text[end:end + 18]):
        return True
    return False


def apply_rules(text: str) -> list[dict]:
    """Run every rule group. Returns one evidence item per group that fired."""
    data = _load()
    out = []
    for g in data["groups"]:
        hits, spans, langs, negated = [], [], set(), []
        patterns_hit = 0
        for lang, rx in g["compiled"]:
            matched_this = False
            for m in rx.finditer(text):
                if m.end() == m.start():
                    continue
                if g["negatable"] and _negated(text, m.start(), m.end(), data):
                    negated.append(m.group(0).strip())
                    continue
                if any(m.start() < e and m.end() > s for s, e in spans):
                    continue
                spans.append((m.start(), m.end()))
                hits.append(" ".join(m.group(0).split()))
                langs.add(lang)
                matched_this = True
            patterns_hit += matched_this
        if not hits:
            continue
        weight = min(g["max_weight"], g["weight"] + 0.05 * (patterns_hit - 1))
        out.append({
            "id": "rule_" + g["id"], "source": "rule", "group": g["id"],
            "title": g["title"], "detail": g["explain"], "weight": round(weight, 3),
            "evidence": hits[:8], "spans": sorted(spans)[:20], "languages": sorted(langs),
            "category": g["category"],
        })
    return out


# --- obfuscation: tricks used to slip past filters -------------------------------------

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
_WORD = re.compile(r"[^\W\d_]{3,}", re.U)
_LEET = re.compile(
    r"(?<![\w])(?:fr[e3]{2}|w[i1!]n(?:ner)?|pr[i1!]ze|cl[i1!]ck|ver[i1!]fy|acc[o0]unt|l[o0]g[i1!]n|"
    r"p[a@]ssw[o0]rd|b[a@]nk|[o0]tp|upd[a@]te|[o0]ffer|c[a@]sh|l[o0]an|k[y¥]c|[o0]nl[i1!]ne|"
    r"s[e3]cur[e3]|paym[e3]nt)(?![\w])", re.I)


def _script(ch: str) -> str:
    try:
        return unicodedata.name(ch).split(" ")[0]
    except ValueError:
        return "UNKNOWN"


def obfuscation(text: str) -> list[dict]:
    """Detect hidden characters, mixed alphabets inside a word and digit-for-letter spelling."""
    out = []

    if _ZERO_WIDTH.search(text):
        out.append({
            "id": "obf_zero_width", "source": "rule", "group": "obfuscation",
            "title": "Hidden characters inside the text",
            "detail": "Invisible characters are inserted to break up words so that spam filters miss them.",
            "weight": 0.3, "evidence": [f"{len(_ZERO_WIDTH.findall(text))} invisible character(s)"],
            "spans": [], "languages": [], "category": None,
        })

    mixed = []
    for m in _WORD.finditer(text):
        scripts = {_script(c) for c in m.group(0)}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            mixed.append((m.group(0), m.span()))
    if mixed:
        out.append({
            "id": "obf_mixed_script", "source": "rule", "group": "obfuscation",
            "title": "Words mix look-alike letters from another alphabet",
            "detail": "For example a Cyrillic 'а' inside an English word. The word looks normal but is not.",
            "weight": 0.4, "evidence": [w for w, _ in mixed[:5]], "spans": [s for _, s in mixed[:10]],
            "languages": [], "category": None,
        })

    leet = [(m.group(0), m.span()) for m in _LEET.finditer(text) if re.search(r"[\d@!¥]", m.group(0))]
    if leet:
        out.append({
            "id": "obf_leet", "source": "rule", "group": "obfuscation",
            "title": "Key words are spelled with digits or symbols",
            "detail": "Spellings such as 'fr33' or 'acc0unt' are used to get past keyword filters.",
            "weight": 0.3, "evidence": [w for w, _ in leet[:5]], "spans": [s for _, s in leet[:10]],
            "languages": [], "category": None,
        })

    letters = [c for c in text if c.isalpha() and c.isascii()]
    if len(letters) >= 30 and sum(c.isupper() for c in letters) / len(letters) > 0.6:
        out.append({
            "id": "obf_caps", "source": "rule", "group": "obfuscation",
            "title": "Mostly written in capital letters",
            "detail": "Shouting in capitals is a common way to create alarm.",
            "weight": 0.1, "evidence": [], "spans": [], "languages": [], "category": None,
        })
    return out


# --- standard bank / service alerts ----------------------------------------------------

_OTP_ALERT = re.compile(
    r"\b\d{4,8}\b\s+is\s+(?:your|the)\s+(?:otp|one[\s-]?time\s+password|verification\s+code|login\s+code|security\s+code)"
    r"|\b(?:otp|one[\s-]?time\s+password|verification\s+code)\b[^.\n]{0,60}?\b(?:is|:)\s*\d{4,8}\b"
    r"|\b(?:use|enter)\s+(?:otp\s+)?\d{4,8}\s+(?:as|for|to)\b", re.I)
_TXN_ALERT = re.compile(
    r"\b(?:debited|credited|withdrawn|spent|deposited|received|transferred|paid)\b", re.I)
_TXN_ACCOUNT = re.compile(
    r"\b(?:a/c|ac|acct|account|card|upi)\b[^.\n]{0,25}?(?:[x*]+\s?\d{2,6}|\bending\s+(?:in\s+|with\s+)?\d{3,4}\b|\b\d{4}\b)", re.I)


def looks_like_standard_alert(text: str) -> str | None:
    """'otp' or 'transaction' if the message has the shape of a routine bank alert."""
    if len(text) > 400:
        return None
    if _OTP_ALERT.search(text):
        return "otp"
    if _TXN_ALERT.search(text) and _TXN_ACCOUNT.search(text):
        return "transaction"
    return None
