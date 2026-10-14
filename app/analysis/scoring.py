"""Turn a list of evidence into one risk score, a level and a scam category.

    risk = 1 - (1 - w1) x (1 - w2) x (1 - w3) x ...        (each w is between 0 and 1)

One weak signal gives a low score, independent signals add up, the score never passes
100, and adding evidence can never lower it.
"""
from __future__ import annotations

from app import config

# A model on its own can raise the level to Medium at most; High needs a concrete indicator.
ML_TEXT_MIN, ML_TEXT_MAX = 0.15, 0.45
ML_URL_MIN, ML_URL_MAX = 0.25, 0.55


def ml_text_weight(probability: float) -> float:
    """0 below 0.5, then 0.15 at 0.5 rising in a straight line to 0.45 at 1.0."""
    if probability < 0.5:
        return 0.0
    return round(ML_TEXT_MIN + (probability - 0.5) / 0.5 * (ML_TEXT_MAX - ML_TEXT_MIN), 3)


def ml_url_weight(probability: float, threshold: float) -> float:
    """0 below the alert threshold, then 0.25 rising in a straight line to 0.55 at 1.0."""
    if probability < threshold:
        return 0.0
    span = max(1e-9, 1.0 - threshold)
    return round(ML_URL_MIN + (probability - threshold) / span * (ML_URL_MAX - ML_URL_MIN), 3)


def combine(weights) -> int:
    """Noisy-OR of the weights, as a whole number from 0 to 100."""
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - max(0.0, min(1.0, float(w)))
    return int(round(100 * (1.0 - remaining)))


# High and Critical need at least one strong indicator that is not a statistical model.
# Measured reason: "Call 98765... for the notes, urgent" (two weak rules + the text model,
# which was trained on UK spam where "call <number>" is typical) came out High.
STRONG_WEIGHT = 0.30
CAP_WITHOUT_STRONG = 59
MODEL_SOURCES = {"ml-text", "ml-url"}
CAP_REASON = ("High and Critical need at least one strong indicator (weight 0.30 or more) that does not "
              "come from a statistical model. Only weak indicators and model opinions were found, so the "
              "score stops at the top of Medium.")


def apply_cap(score: int, factors: list[dict]) -> tuple[int, bool]:
    """Limit the score to Medium when no strong, non-model indicator is present."""
    strong = any(f["weight"] >= STRONG_WEIGHT and f.get("source") not in MODEL_SOURCES for f in factors)
    if score > CAP_WITHOUT_STRONG and not strong:
        return CAP_WITHOUT_STRONG, True
    return score, False


def level_for(score: int) -> str:
    name = config.RISK_LEVELS[0][0]
    for level, lowest in config.RISK_LEVELS:
        if score >= lowest:
            name = level
    return name


def level_rank(level: str) -> int:
    return [name for name, _ in config.RISK_LEVELS].index(level)


def dedupe(evidence: list[dict]) -> list[dict]:
    """Keep one item per evidence id (the strongest), so three links with the same trick
    do not count three times."""
    best: dict[str, dict] = {}
    for e in evidence:
        if e["weight"] <= 0:
            continue
        cur = best.get(e["id"])
        if cur is None or e["weight"] > cur["weight"]:
            best[e["id"]] = e
    return sorted(best.values(), key=lambda e: -e["weight"])


def pick_category(evidence: list[dict], level: str) -> str:
    if level == "Safe":
        return "None"
    cats: dict[str, float] = {}
    for e in evidence:
        c = e.get("category")
        if c:
            cats[c] = max(cats.get(c, 0.0), e["weight"])
    if cats:
        return max(cats, key=cats.get)
    ids = {e["id"] for e in evidence}
    if ids & {"url_lookalike", "url_brand_in_host", "brand_link_mismatch", "sender_lookalike",
              "sender_free_mail", "sender_mismatch", "sender_personal_number", "url_mixed_script",
              "url_lookalike_script", "url_deceptive_subdomain"}:
        return "Brand impersonation"
    if "url_download" in ids:
        return "Malware download"
    if any(e["id"].startswith("url_") or e["id"] == "ml_url" for e in evidence):
        return "Suspicious link"
    if "ml_text" in ids:
        return "Spam / unsolicited message"
    return "Suspicious message"


LEVEL_SUMMARY = {
    "Safe": "No scam indicators were found.",
    "Low": "A few weak indicators. Probably fine, but stay alert.",
    "Medium": "Several indicators of a scam. Do not act on this message without checking independently.",
    "High": "Strong indicators of a scam. Do not click, reply, pay or share any details.",
    "Critical": "This matches known scam patterns very closely. Do not interact. Report and delete it.",
}

BASE_ADVICE = {
    "Safe": ["Nothing suspicious was found. Still, never share an OTP, PIN or password with anyone."],
    "Low": ["If the message asks for anything unusual, contact the sender through a channel you already trust."],
    "Medium": [
        "Do not open the link or call the number in the message.",
        "Check with the organisation using its official app, website or the number printed on your card.",
    ],
    "High": [
        "Do not click the link, reply, call back or pay.",
        "Never share an OTP, PIN, CVV or password. No genuine organisation asks for them.",
        "Report it: call the cybercrime helpline 1930 or use cybercrime.gov.in (India).",
    ],
    "Critical": [
        "Do not click the link, reply, call back or pay.",
        "Never share an OTP, PIN, CVV or password. No genuine organisation asks for them.",
        "If you already shared details or paid, call your bank and the cybercrime helpline 1930 at once.",
        "Report it on cybercrime.gov.in, then block the sender and delete the message.",
    ],
}

CATEGORY_ADVICE = {
    "Authority impersonation / digital arrest": "Police and agencies never arrest, question or collect money over a video call.",
    "Utility bill scam": "Check your bill only in the electricity board's official app or website.",
    "KYC / account update": "KYC is done at the branch or inside the bank's official app, never through a link in a message.",
    "Courier / delivery scam": "Track parcels only on the courier's official website using your own tracking number.",
    "Job / task scam": "A real employer never asks you to pay or deposit money to start work.",
    "Lottery / prize scam": "A real prize never needs a fee, a tax payment or your bank details first.",
    "Investment / crypto scam": "Check the adviser on the SEBI website. Guaranteed returns are always a lie.",
    "Tech support / remote access scam": "Never install a screen-sharing app because a caller or message asks you to.",
    "Impersonation of a known person": "Call the person on the number you already have before sending anything.",
    "Malware download": "Install apps only from the official app store.",
    "Loan scam": "Check that the lender is registered with the RBI before sharing documents.",
    "Extortion / blackmail": "Do not pay. Keep the message as evidence and report it.",
    "Refund / tax scam": "Refunds are paid automatically to your registered account. Nobody needs your details again.",
    "Credential phishing": "Type the website address yourself instead of using the link.",
    "Brand impersonation": "Compare the link with the organisation's real address, letter by letter.",
}


def advice_for(level: str, category: str) -> list[str]:
    tips = list(BASE_ADVICE[level])
    extra = CATEGORY_ADVICE.get(category)
    if extra and level != "Safe":
        tips.insert(0, extra)
    return tips
