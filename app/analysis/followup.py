"""Evidence from the sender's earlier messages.

A scammer may send a phishing link in one message and, later, a harmless-looking follow-up such as
"Please open the link I sent you". On its own the follow-up has nothing suspicious in it. SatarkAI
therefore looks at the same sender's last risky messages (History, the last HISTORY_LIMIT) and adds:

- repeat_sender: the sender already sent risky messages (weight 0.30 for one, 0.38 for two, 0.45 for three or more)
- followup_link: the message points back to an earlier message and that sender earlier sent a risky link (0.65)

The pipeline adds these only when the message is a follow-up (followup_link) or is already suspicious on its
own (score SUSPICIOUS_FROM or more, i.e. Low or higher). A plain "hello" keeps its own score.
"""
from __future__ import annotations

import re

from app import config

REPEAT_WEIGHT = {1: 0.30, 2: 0.38}
REPEAT_WEIGHT_MAX = 0.45
FOLLOWUP_WEIGHT = 0.65
HISTORY_LIMIT = 3        # how many of the sender's latest risky messages are looked at
SUSPICIOUS_FROM = dict(config.RISK_LEVELS)["Low"]   # own score from which earlier messages count

# Phrases that refer back to an earlier message or link (English, Hinglish, Hindi).
_REFERENCE = re.compile(
    r"\b(?:"
    r"(?:that|same|above|previous|earlier|last|old)\s+(?:link|url|website|site|message|msg|sms|mail|e-?mail)"
    r"|(?:the|my|our)\s+(?:link|url|website|site)\b"
    r"|link\s+(?:i|we)\s+(?:sent|shared|forwarded|gave)"
    r"|(?:link|message|msg|sms|mail)\s+(?:i|we)\s+(?:sent|shared|forwarded)"
    r"|(?:sent|shared)\s+(?:you\s+)?(?:earlier|before|above|yesterday|previously)"
    r"|(?:open|click|check|visit|use|tap)\s+(?:on\s+)?(?:the\s+)?(?:above|previous|earlier|same|that|my)\b"
    r"|(?:open|click|tap)\s+(?:on\s+)?(?:the\s+)?link\b(?!\s*[:\-]?\s*(?:https?://|www\.))"
    r"|(?:as|link)\s+(?:sent|shared|mentioned)\s+(?:earlier|before|above|previously)"
    r"|(?:upar|uppar)\s+(?:wala|vala|wale|diya|diye|di)\s*(?:link|message|msg)?"
    r"|pichl[ae]\s+(?:link|message|msg|sms|mail)"
    r"|jo\s+link\s+(?:bheja|bhejah?|diya|share)"
    r"|link\s+(?:pe|par|pr)\s+(?:click|clik)"
    r"|link\s+(?:khol|kholo|kholiye|open\s+karo)"
    r")",
    re.IGNORECASE,
)
_REFERENCE_HI = re.compile(r"(?:ऊपर\s*(?:वाले|वाला|दिए|दिया)|पिछले\s*(?:मैसेज|संदेश|लिंक)|भेजे\s*गए\s*लिंक|लिंक\s*(?:पर|को)\s*(?:क्लिक|खोल))")


def refers_back(text: str) -> str | None:
    """The phrase that points back to an earlier message or link, or None."""
    m = _REFERENCE.search(text) or _REFERENCE_HI.search(text)
    return m.group(0).strip() if m else None


def evidence(text: str, history: dict | None, has_own_link: bool) -> list[dict]:
    """Factors from the sender's earlier risky messages (empty when there are none)."""
    if not history or not history.get("count"):
        return []
    out = []
    n = history["count"]
    cases = history.get("cases") or []
    out.append({
        "id": "repeat_sender", "source": "sender-history",
        "title": f"This sender already sent {n} risky message{'s' if n != 1 else ''}",
        "detail": f"Earlier messages from the same sender scored up to {history['max_score']}"
                  + (f", mostly {history['top_category']}" if history.get("top_category") else "")
                  + ". Scammers often send several messages from one number or address.",
        "weight": REPEAT_WEIGHT.get(n, REPEAT_WEIGHT_MAX),
        "evidence": [f"#{c['id']} {c['level']} {c['score']}" for c in cases[:3]],
    })
    phrase = refers_back(text)
    links = history.get("links") or []
    if phrase and links and not has_own_link:
        first = links[0]
        out.append({
            "id": "followup_link", "source": "sender-history",
            "title": "Points to an earlier phishing link from this sender",
            "detail": f"The message refers back to an earlier message (\"{phrase}\"), and this sender earlier sent "
                      f"{first['domain']} ({first['level']} {first['score']}). On its own this message looks harmless; "
                      "together with the earlier one it is part of the same scam.",
            "weight": FOLLOWUP_WEIGHT,
            "category": history.get("top_category") or None,
            "evidence": [phrase] + [l["display"] for l in links[:2]],
        })
    return out
