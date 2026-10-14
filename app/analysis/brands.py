"""Brand knowledge: official domains, impersonation and lookalike (typosquat) checks."""
from __future__ import annotations

import json
import re
from functools import lru_cache

from app import config

# Characters often swapped to make a lookalike domain: paypa1 -> paypal, amaz0n -> amazon
_HOMOGLYPHS = [
    ("rn", "m"), ("vv", "w"),
    ("0", "o"), ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"),
    ("$", "s"), ("@", "a"), ("!", "i"), ("|", "l"),
]

# Words that scammers glue to a short brand name: sbikyc, hdfcrewards, jiorecharge
_GLUE_WORDS = {
    "kyc", "ekyc", "bank", "banking", "online", "net", "netbanking", "update", "updates", "secure",
    "security", "login", "signin", "card", "cards", "reward", "rewards", "points", "verify",
    "verification", "india", "support", "care", "help", "helpdesk", "pay", "payment", "upi",
    "account", "service", "services", "customer", "alert", "alerts", "info", "mobile", "app",
    "apk", "user", "portal", "offer", "offers", "bonus", "gift", "win", "free", "my", "the",
    "e", "i", "recharge", "refund", "claim", "pan", "aadhaar", "block", "unblock", "activate",
    "credit", "debit", "loan", "yono", "official", "web", "site", "team", "center", "centre",
}


@lru_cache(maxsize=1)
def _load() -> dict:
    data = json.loads((config.KNOWLEDGE_DIR / "brands.json").read_text(encoding="utf-8"))
    brands = data["brands"]
    official = {}
    for b in brands:
        for d in b["official_domains"]:
            official.setdefault(d.lower(), b["name"])
    text_rx = []
    for b in brands:
        for alias in b.get("text_aliases", []):
            pattern = r"(?<![\w])" + re.escape(alias).replace(r"\ ", r"\s+") + r"(?![\w])"
            text_rx.append((re.compile(pattern, re.I), b["name"], alias))
    # Longest alias first, so "state bank of india" wins over "state bank".
    text_rx.sort(key=lambda t: -len(t[2]))
    # Lookalike targets: the main label of each official domain and long url keywords.
    targets = {}
    for b in brands:
        for d in b["official_domains"]:
            label = d.split(".")[0]
            if len(label) >= 5:
                targets.setdefault(label, b["name"])
        for kw in b.get("url_keywords", []):
            if len(kw) >= 5:
                targets.setdefault(kw, b["name"])
    return {
        "keywords": {kw for b in brands for kw in b.get("url_keywords", [])},
        "brands": brands,
        "by_name": {b["name"]: b for b in brands},
        "official": official,
        "text_rx": text_rx,
        "targets": targets,
        "restricted": [s.lower() for s in data["restricted_suffixes"]["suffixes"]],
        "free_mail": {d.lower() for d in data["free_mail_domains"]},
    }


def brand_count() -> int:
    return len(_load()["brands"])


def official_brand(registered_domain: str) -> str | None:
    """Brand name if this registered domain is on the official list."""
    return _load()["official"].get((registered_domain or "").lower())


def is_restricted(host: str) -> bool:
    """True for hosts under a verified-only registry such as gov.in or bank.in."""
    host = (host or "").lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in _load()["restricted"])


def is_trusted(host: str, registered_domain: str) -> bool:
    return bool(official_brand(registered_domain)) or is_restricted(host)


def is_free_mail(domain: str) -> bool:
    return (domain or "").lower() in _load()["free_mail"]


def official_domains_of(brand: str) -> list[str]:
    b = _load()["by_name"].get(brand)
    return list(b["official_domains"]) if b else []


def category_of(brand: str) -> str:
    b = _load()["by_name"].get(brand)
    return b["category"] if b else ""


def brands_in_text(text: str) -> list[dict]:
    """Brand names mentioned in a message: [{brand, alias, start, end}], one per brand."""
    found, seen, spans = [], set(), []
    for rx, name, alias in _load()["text_rx"]:
        for m in rx.finditer(text):
            if any(m.start() < e and m.end() > s for s, e in spans):
                continue
            spans.append((m.start(), m.end()))
            if name in seen:
                continue
            seen.add(name)
            found.append({"brand": name, "alias": m.group(0), "start": m.start(), "end": m.end()})
    return sorted(found, key=lambda f: f["start"])


def skeletons(label: str) -> set[str]:
    """Replace lookalike characters: 'paypa1' -> 'paypal', '1cici' -> 'icici'.

    The digit 1 can stand for either l or i, so both readings are returned.
    """
    s = label.lower()
    for a, b in _HOMOGLYPHS:
        s = s.replace(a, b)
    return {s.replace("1", "l"), s.replace("1", "i")}


def _edit_distance_le1(a: str, b: str) -> bool:
    """True if a and b differ by one insert, delete, substitute or adjacent swap."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _keyword_in_token(kw: str, token: str) -> bool:
    if token == kw:
        return True
    if len(kw) >= 5:
        return kw in token
    # Short names (sbi, jio, dhl) match only next to a known scam word: sbikyc, jiooffer
    if token.startswith(kw) and token[len(kw):] in _GLUE_WORDS:
        return True
    if token.endswith(kw) and token[: -len(kw)] in _GLUE_WORDS:
        return True
    return False


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def check_host(host: str, registered_domain: str, domain_label: str, subdomain: str, path: str = "") -> list[dict]:
    """Impersonation findings for a URL that is NOT on a trusted domain.

    Returns a list of {kind, brand, matched, where}:
      kind 'lookalike'   - the domain name is a misspelling of a brand (paypa1.com)
      kind 'brand_in_host' - a brand name used inside someone else's domain
      kind 'brand_in_path' - a brand name used only in the path
    """
    data = _load()
    if is_trusted(host, registered_domain):
        return []
    findings: list[dict] = []
    seen: set[str] = set()

    label_tokens = _tokens(domain_label)
    sub_tokens = _tokens(subdomain)
    path_tokens = _tokens(path)

    # 1. Lookalike spelling of the domain label or one of its hyphen-separated parts.
    for cand in {domain_label.lower(), *label_tokens}:
        if len(cand) < 5 or cand in data["keywords"]:
            continue
        sk = skeletons(cand)
        for target, brand in data["targets"].items():
            if cand == target:
                continue
            if target in sk or (len(target) >= 6 and _edit_distance_le1(cand, target)):
                if brand not in seen:
                    seen.add(brand)
                    findings.append({"kind": "lookalike", "brand": brand, "matched": cand,
                                     "where": "domain", "looks_like": target})

    # 2. Brand keyword inside the host or the path.
    for b in data["brands"]:
        if b["name"] in seen:
            continue
        for kw in b.get("url_keywords", []):
            where = None
            hit = next((t for t in label_tokens if _keyword_in_token(kw, t)), None)
            if hit:
                where = "domain"
            else:
                hit = next((t for t in sub_tokens if _keyword_in_token(kw, t)), None)
                if hit:
                    where = "subdomain"
                else:
                    hit = next((t for t in path_tokens if _keyword_in_token(kw, t)), None)
                    if hit:
                        where = "path"
            if where:
                seen.add(b["name"])
                findings.append({
                    "kind": "brand_in_path" if where == "path" else "brand_in_host",
                    "brand": b["name"], "matched": hit, "where": where,
                })
                break
    return findings
