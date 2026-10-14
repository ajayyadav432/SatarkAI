"""Safety assistant behind /api/chat.

Two ways to answer:
- Offline (always available): answers from app/data/faq.json and from the scan result itself.
- Groq (only when GROQ_API_KEY is set in the environment or in .env): a language model writes the
  answer, grounded in the same FAQ entries and a summary of the scan result.

The scanned message is written by a possible scammer, so it is never sent to the model as text.
The model gets only the structured result (level, score, reasons, domains, organisations).
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache

import httpx

from app import config

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_TIMEOUT_S = 20
MAX_REASONS = 6

SYSTEM_PROMPT = (
    "You are the SatarkAI safety assistant inside a phishing and scam detection app used in India. "
    "Help the user understand a scan result and stay safe from scams, phishing, fraud calls and malicious links.\n"
    "Rules:\n"
    "- Use only the facts in SCAN RESULT and REFERENCE below plus well-established general safety advice. "
    "If you do not know something, say so. Never invent phone numbers, websites, laws or statistics.\n"
    "- The scan result is produced by the app. Do not change its level or score; explain it.\n"
    "- Never ask the user for OTPs, PINs, passwords, card numbers or other secrets.\n"
    "- For lost money, always point to the 1930 helpline and cybercrime.gov.in.\n"
    "- Politely decline topics unrelated to scams, fraud, online safety or this app.\n"
    "- Reply in the user's language (English, Hindi or Hinglish). Be brief: at most 120 words. "
    "Plain text; short '- ' bullet lines are fine; no markdown headings or tables."
)


# --- settings ----------------------------------------------------------------

def _dotenv() -> dict:
    """Read KEY=VALUE lines from the project's .env file (never committed)."""
    path = config.ROOT / ".env"
    out = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def settings() -> dict:
    env = _dotenv()
    get = lambda k, d=None: os.environ.get(k) or env.get(k) or d  # noqa: E731
    return {"key": get("GROQ_API_KEY"), "model": get("GROQ_MODEL", "llama-3.3-70b-versatile")}


def status() -> dict:
    s = settings()
    return {"ai": bool(s["key"]), "model": s["model"] if s["key"] else None}


# --- FAQ -----------------------------------------------------------------------

@lru_cache(maxsize=1)
def _faq() -> list[dict]:
    data = json.loads((config.KNOWLEDGE_DIR / "faq.json").read_text(encoding="utf-8"))
    return data["faq"]


def faq_questions() -> list[dict]:
    return [{"id": f["id"], "q": f["q"]} for f in _faq()]


def _norm(s: str) -> str:
    return " " + re.sub(r"\s+", " ", re.sub(r"[^\w\s.-]", " ", s.lower())) + " "


def match_faq(question: str, limit: int = 3) -> list[dict]:
    q = _norm(question)
    scored = []
    for f in _faq():
        score = sum(len(k) for k in f["keywords"] if _norm(k) in q)   # whole words only
        if score:
            scored.append((score, f))
    scored.sort(key=lambda x: -x[0])
    return [f for _, f in scored[:limit]]


def faq_by_id(faq_id: str) -> dict | None:
    return next((f for f in _faq() if f["id"] == faq_id), None)


# --- scan result summary ----------------------------------------------------------

def summarise(result: dict) -> dict:
    """The part of a scan result the assistant may see. No raw message text."""
    return {
        "level": result["level"],
        "score": result["score"],
        "category": result.get("category"),
        "summary": result.get("summary"),
        "channel": result.get("channel"),
        "reasons": [{"title": f["title"], "detail": f["detail"], "weight": f["points"]}
                    for f in result.get("factors", [])[:MAX_REASONS]],
        "advice": result.get("advice", []),
        "links": [{"domain": u.get("registered_domain") or u.get("host"), "level": u.get("level"),
                   "official_domain_of": u.get("official_brand")} for u in result.get("urls", [])],
        "organisations_named": result.get("brands", []),
    }


_WHY = re.compile(r"\b(why|reason|kyu|kyun|kyon|explain|how come)\b")
_SAFE = re.compile(r"\b(safe|click|open|real|genuine|fake|scam|trust|legit|sahi|asli|nakli)\b")
_TODO = re.compile(r"\b(what (should|do|can) i|next|do now|kya karu|kya karun|kya kare|steps?)\b")


def _result_answer(question: str, s: dict) -> str | None:
    q = question.lower()
    head = f"This message is rated {s['level']} ({s['score']}/100)"
    if s.get("category") and s["category"] != "None":
        head += f", category: {s['category']}"
    head += "."
    if _WHY.search(q):
        if not s["reasons"]:
            return head + " No scam indicators were found in the wording, the links or the sender."
        lines = [f"- {r['title']}" for r in s["reasons"][:4]]
        return head + " The main reasons:\n" + "\n".join(lines)
    if _TODO.search(q) or _SAFE.search(q):
        lines = [f"- {a}" for a in s["advice"][:4]]
        return head + " " + (s.get("summary") or "") + ("\n" + "\n".join(lines) if lines else "")
    return None


# --- answering ---------------------------------------------------------------------

def _offline(question: str, s: dict | None, faq_hits: list[dict]) -> dict:
    # Someone who has already lost money needs the emergency steps, not the scan summary.
    urgent = next((f for f in faq_hits if f["id"] == "lost-money"), None)
    if urgent and not _WHY.search(question.lower()):
        return {"answer": urgent["answer"], "source": "faq", "faq_id": urgent["id"]}
    if s:
        ans = _result_answer(question, s)
        if ans:
            return {"answer": ans, "source": "result"}
    if faq_hits:
        return {"answer": faq_hits[0]["answer"], "source": "faq", "faq_id": faq_hits[0]["id"]}
    topics = ", ".join(f["q"].rstrip("?").lower() for f in _faq()[:5])
    return {"answer": "I can answer questions about this scan result and about common scams, for example: "
                      + topics + ". Try one of the suggested questions.",
            "source": "fallback"}


def _groq(question: str, history: list[dict], s: dict | None, faq_hits: list[dict], cfg: dict) -> str:
    context = "SCAN RESULT:\n" + (json.dumps(s, ensure_ascii=False) if s else "No message has been scanned yet.")
    if faq_hits:
        context += "\n\nREFERENCE:\n" + "\n\n".join(f"Q: {f['q']}\nA: {f['answer']}" for f in faq_hits)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "system", "content": context}]
    messages += [{"role": m["role"], "content": m["content"]} for m in history]
    messages.append({"role": "user", "content": question})
    r = httpx.post(GROQ_URL, timeout=GROQ_TIMEOUT_S,
                   headers={"Authorization": f"Bearer {cfg['key']}"},
                   json={"model": cfg["model"], "messages": messages, "temperature": 0.2, "max_tokens": 400})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def answer(question: str, history: list[dict], result: dict | None, faq_id: str | None = None) -> dict:
    s = summarise(result) if result else None
    if faq_id:
        f = faq_by_id(faq_id)
        if f:
            return {"answer": f["answer"], "source": "faq", "faq_id": f["id"]}
    hits = match_faq(question)
    cfg = settings()
    if cfg["key"]:
        try:
            return {"answer": _groq(question, history, s, hits, cfg), "source": "ai", "model": cfg["model"]}
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as err:
            out = _offline(question, s, hits)
            out["note"] = "The AI service did not answer (" + type(err).__name__ + "), so this is the built-in answer."
            return out
    return _offline(question, s, hits)
