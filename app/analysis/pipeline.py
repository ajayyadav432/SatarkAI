"""The full analysis of one message: extract -> check links -> rules -> models -> score."""
from __future__ import annotations

import re
import time

from app import config
from app.analysis import brands, followup, models, rules, scoring
from app.analysis.extract import Entities, defang, extract_entities, phone_kind
from app.analysis.url_features import heuristic_findings, parse_url

# Rule groups that are too weak to count as a "concrete scam indicator" on their own.
_WEAK_GROUPS = {"generic_greeting", "callback", "link_action", "urgency"}
# Brand categories that never write to you from a personal phone number.
_ORG_CATEGORIES = {"bank", "payments", "government", "telecom", "courier", "insurance", "shopping"}

_EMAIL_HINT = re.compile(r"^\s*(?:subject|from|to|cc)\s*:", re.I | re.M)
_ONLY_URL = re.compile(r"^\S+$")
_SENDER_EMAIL = re.compile(r"[\w.+-]+@((?:[^\W_](?:[^\W_]|-)*\.)+[^\W\d_]{2,24})")


def detect_channel(text: str, entities: Entities) -> str:
    stripped = text.strip()
    if len(entities.urls) == 1 and _ONLY_URL.match(stripped) and entities.urls[0].raw == stripped.rstrip(".,;"):
        return "url"
    if len(stripped) > 700 or _EMAIL_HINT.search(stripped) or stripped.count("\n\n") >= 2:
        return "email"
    return "sms"


def analyze_url(url: str, raw: str | None = None, had_scheme: bool = True, defanged: bool = False,
                lookup: bool = False) -> dict:
    """Risk of a single link, from its text only. The link is never opened."""
    info = parse_url(url)
    result = {
        "raw": raw or url, "url": url, "display": defang(url), "was_defanged": defanged,
        "valid": info.valid, "host": info.host_unicode or info.host, "host_ascii": info.host,
        "registered_domain": info.registered_domain, "subdomain": info.subdomain,
        "suffix": info.suffix, "scheme": info.scheme, "port": info.port,
        "path": info.path, "query": info.query,
        "is_ip": info.is_ip, "trusted": info.trusted, "official_brand": info.official_brand,
        "restricted_registry": info.restricted_registry, "is_shortener": info.is_shortener,
        "hosting_platform": info.user_content_host,
        "factors": [], "notes": [], "ml": {"used": False}, "lookup": None,
    }
    if not info.valid:
        result.update({"score": 0, "score_uncapped": 0, "cap_applied": False, "level": "Safe"})
        result["notes"].append({"title": "Not a valid link", "detail": "The address could not be parsed."})
        return result

    factors = heuristic_findings(info, had_scheme=had_scheme)
    if info.trusted:
        who = info.official_brand or "a verified-only registry"
        result["notes"].append({
            "title": "Official domain",
            "detail": (f"{info.registered_domain} is on the official list for {who}."
                       if info.official_brand else
                       f"{info.host} is under a registry that only registers verified organisations."),
        })

    ml = models.predict_url(info)
    result["ml"] = ml
    if ml.get("used"):
        weight = scoring.ml_url_weight(ml["probability"], ml["threshold"])
        if weight > 0:
            reasons = [f"{p['label']} (+{p['points']})" for p in ml["raises_risk"][:4]]
            factors.append({
                "id": "ml_url", "source": "ml-url",
                "title": f"URL model: {ml['probability']:.0%} phishing probability",
                "detail": "Learned from public phishing URL datasets. Main reasons: " + "; ".join(reasons) + ".",
                "weight": weight, "evidence": [info.host_unicode or info.host],
            })

    if lookup:
        from app.analysis.lookup import live_lookup
        look = live_lookup(info)
        result["lookup"] = look
        factors.extend(look.get("factors", []))

    for f in factors:
        f["url"] = url
    factors.sort(key=lambda f: -f["weight"])
    raw = scoring.combine(f["weight"] for f in factors)
    score, capped = scoring.apply_cap(raw, factors)
    result.update({"factors": factors, "score": score, "score_uncapped": raw, "cap_applied": capped,
                   "level": scoring.level_for(score)})
    return result


def _mask(text: str, spans: list[tuple[int, int]]) -> str:
    """Blank out spans (links, e-mail addresses) so text rules do not match inside them."""
    chars = list(text)
    for s, e in spans:
        for i in range(s, min(e, len(chars))):
            if not chars[i].isspace():
                chars[i] = " "
    return "".join(chars)


def _sender_evidence(sender: str, mentioned: list[dict]) -> tuple[list[dict], list[dict]]:
    """Compare who the message claims to be from with who actually sent it."""
    factors, notes = [], []
    sender = sender.strip()
    if not sender:
        return factors, notes
    claimed = list(mentioned)
    for b in brands.brands_in_text(sender):
        if b["brand"] not in {c["brand"] for c in claimed}:
            claimed.append(b)

    m = _SENDER_EMAIL.search(sender)
    if m:
        domain = m.group(1).lower()
        info = parse_url("http://" + domain)
        if claimed and brands.is_free_mail(domain):
            factors.append({
                "id": "sender_free_mail", "source": "sender",
                "title": f"Claims to be {claimed[0]['brand']} but uses a free e-mail address",
                "detail": f"Organisations write from their own domain, not from {domain}.",
                "weight": 0.5, "evidence": [domain]})
            return factors, notes
        if info.trusted and not brands.is_free_mail(domain):
            notes.append({"title": "Sender address uses an official domain",
                          "detail": f"{domain} is on the official list. Note: a sender address can still be forged."})
            return factors, notes
        look = [f for f in brands.check_host(info.host, info.registered_domain, info.domain_label, info.subdomain)
                if f["kind"] in ("lookalike", "brand_in_host")]
        if look:
            f = look[0]
            factors.append({
                "id": "sender_lookalike", "source": "sender",
                "title": f"Sender address imitates {f['brand']}",
                "detail": f"The mail comes from {domain}, which is not an official {f['brand']} domain "
                          f"({', '.join(brands.official_domains_of(f['brand'])[:3])}).",
                "weight": 0.65, "evidence": [domain]})
        elif claimed and not brands.is_free_mail(domain):
            factors.append({
                "id": "sender_mismatch", "source": "sender",
                "title": f"Sender domain does not belong to {claimed[0]['brand']}",
                "detail": f"The mail comes from {domain}. Official: "
                          f"{', '.join(brands.official_domains_of(claimed[0]['brand'])[:3])}.",
                "weight": 0.4, "evidence": [domain]})
        return factors, notes

    if phone_kind(sender) == "mobile":
        orgs = [c for c in claimed
                if brands.category_of(c["brand"]) in _ORG_CATEGORIES]
        if orgs:
            factors.append({
                "id": "sender_personal_number", "source": "sender",
                "title": f"Claims to be {orgs[0]['brand']} but was sent from a personal mobile number",
                "detail": "Organisations send SMS from a registered sender ID (for example AD-HDFCBK), "
                          "not from a 10-digit mobile number.",
                "weight": 0.4, "evidence": [sender]})
    return factors, notes


def analyze(text: str, channel: str = "auto", sender: str | None = None, lookup: bool = False,
            history: dict | None = None) -> dict:
    """Analyse one message and return score, level, reasons and extracted indicators.
    history: the sender's earlier risky messages (db.sender_history), used for follow-up messages."""
    started = time.perf_counter()
    text = (text or "").replace("\r\n", "\n").replace("\x00", "")[: config.MAX_TEXT_CHARS]
    sender = (sender or "").strip()[: config.MAX_SENDER_CHARS]
    entities = extract_entities(text)

    detected = channel in (None, "", "auto") or channel not in config.CHANNELS
    if detected:
        channel = detect_channel(text, entities)

    notes: list[dict] = []
    evidence: list[dict] = []
    highlights: list[dict] = []

    # 1. Links ------------------------------------------------------------------------
    url_results = []
    for u in entities.urls:
        r = analyze_url(u.url, raw=u.raw, had_scheme=u.had_scheme, defanged=u.defanged, lookup=lookup)
        r["start"], r["end"] = u.start, u.end
        url_results.append(r)
        evidence.extend(r["factors"])
        if r["was_defanged"]:
            notes.append({"title": "Disguised link was decoded",
                          "detail": f"'{u.raw}' was written so that filters miss it. It is the link {r['display']}."})
        highlights.append({"start": u.start, "end": u.end, "kind": "url",
                           "label": f"Link: {r['level']} risk" if r["valid"] else "Link"})
    if entities.urls_truncated:
        notes.append({"title": "Many links",
                      "detail": f"Only the first {config.MAX_URLS_PER_MESSAGE} links were analysed."})
    untrusted = [r for r in url_results if r["valid"] and not r["trusted"]]
    trusted = [r for r in url_results if r["trusted"]]
    for r in trusted:
        notes.append({"title": "Link to an official domain", "detail": r["notes"][0]["detail"]})

    # 2. Language rules (links and e-mail addresses are blanked out first) -----------------
    masked = _mask(text, [(u.start, u.end) for u in entities.urls])
    rule_hits: list[dict] = []
    mentioned: list[dict] = []
    if channel != "url":
        rule_hits = rules.apply_rules(masked) + rules.obfuscation(masked)
        mentioned = brands.brands_in_text(masked)
        for h in rule_hits:
            for s, e in h.get("spans", []):
                highlights.append({"start": s, "end": e, "kind": "rule", "label": h["title"]})
        for b in mentioned:
            highlights.append({"start": b["start"], "end": b["end"], "kind": "brand",
                               "label": f"Names {b['brand']}"})
        evidence.extend(rule_hits)
    fired = {h["group"] for h in rule_hits}
    strong_fired = fired - _WEAK_GROUPS

    # 3. Evidence that needs more than one fact ---------------------------------------
    url_brand_ids = {"url_lookalike", "url_brand_in_host", "url_brand_in_path"}
    already_impersonation = any(f["id"] in url_brand_ids for r in untrusted for f in r["factors"])
    # A brand is "linked elsewhere" only if none of the untrusted links is on its own domains.
    elsewhere = [(b, r) for b in mentioned for r in untrusted
                 if r["registered_domain"] not in brands.official_domains_of(b["brand"])
                 and brands.official_brand(r["registered_domain"]) is None]
    if elsewhere and not already_impersonation:
        b, r = elsewhere[0]
        evidence.append({
            "id": "brand_link_mismatch", "source": "impersonation",
            "title": f"Names {b['brand']} but the link goes somewhere else",
            "detail": f"The message mentions {b['brand']}, yet the link opens {r['registered_domain']}. "
                      f"Official: {', '.join(brands.official_domains_of(b['brand'])[:3])}.",
            "weight": 0.5, "evidence": [b["alias"], r["registered_domain"]],
        })

    if sender:
        s_factors, s_notes = _sender_evidence(sender, mentioned)
        evidence.extend(s_factors)
        notes.extend(s_notes)

    # Earlier risky messages from the same sender (e.g. a follow-up to a phishing link sent before).
    # The follow-up reason applies only when the message has no link of its own (its own link is checked anyway).
    evidence.extend(followup.evidence(text, history, has_own_link=bool(url_results)))

    mobiles = [p for p in entities.phones if phone_kind(p) == "mobile"]
    if mobiles and "callback" in fired and (mentioned or strong_fired & {"threat", "kyc", "bill", "authority", "refund", "courier"}):
        evidence.append({
            "id": "personal_number_callback", "source": "impersonation",
            "title": "Asks you to call a personal mobile number",
            "detail": "Customer care uses toll-free or landline numbers published on the official website, "
                      "not an ordinary mobile number sent in a message.",
            "weight": 0.35, "evidence": mobiles[:2],
        })

    if entities.upi_ids and fired & {"payment_request", "reward", "job", "refund", "courier", "bill", "loan"}:
        evidence.append({
            "id": "upi_payment_request", "source": "impersonation",
            "title": "Asks for payment to a personal UPI ID",
            "detail": "Money sent by UPI to a private ID cannot be recalled.",
            "weight": 0.3, "evidence": entities.upi_ids[:2],
        })

    # 4. Text model --------------------------------------------------------------------
    ml_text: dict = {"used": False, "reason": "Only a link was given; there is no message text to judge."}
    if channel != "url":
        alert = rules.looks_like_standard_alert(masked)
        quiet = not strong_fired and not untrusted and not mobiles and not entities.upi_ids
        if trusted and quiet:
            ml_text = {"used": False,
                       "reason": "Every link in this message goes to an official domain and nothing else "
                                 "suspicious was found, so the text model's opinion is not used. Its training "
                                 "data has no messages from Indian banks, shops or services and it tends to "
                                 "read them as spam."}
            notes.append({"title": "Text model not used", "detail": ml_text["reason"]})
        elif alert and quiet:
            kind = "one-time password (OTP) message" if alert == "otp" else "bank transaction alert"
            ml_text = {"used": False, "standard_alert": alert,
                       "reason": f"This has the shape of a routine {kind} and contains no link, no personal "
                                 "phone number and no request. The text model is not used for these, because "
                                 "its training data contains no bank alerts and it misreads them as spam."}
            notes.append({"title": f"Looks like a routine {kind}", "detail": ml_text["reason"]})
        else:
            ml_text = models.predict_text(text, channel)
            if ml_text.get("used"):
                weight = scoring.ml_text_weight(ml_text["probability"])
                if weight > 0:
                    words = ", ".join(f"'{t['display']}'" for t in ml_text["scam_terms"][:6])
                    evidence.append({
                        "id": "ml_text", "source": "ml-text",
                        "title": f"Text model: {ml_text['probability']:.0%} scam probability",
                        "detail": f"Learned from labelled {ml_text['trained_on']}. "
                                  f"Words that pushed the score up: {words}.",
                        "weight": weight, "evidence": [t["display"] for t in ml_text["scam_terms"][:6]],
                    })
                    for w in ml_text["highlight_words"]:
                        for m in re.finditer(r"(?<![\w])" + re.escape(w) + r"(?![\w])", masked, re.I):
                            highlights.append({"start": m.start(), "end": m.end(), "kind": "ml",
                                               "label": "Word the text model associates with scams"})
            elif ml_text.get("reason"):
                notes.append({"title": "Text model not used", "detail": ml_text["reason"]})

    # 5. Combine -----------------------------------------------------------------------
    factors = scoring.dedupe(evidence)
    raw_score = scoring.combine(f["weight"] for f in factors)
    score, capped = scoring.apply_cap(raw_score, factors)
    if capped:
        notes.append({"title": f"Score limited to {score}", "detail": scoring.CAP_REASON})
    level = scoring.level_for(score)
    category = scoring.pick_category(factors, level)
    for f in factors:
        f["points"] = int(round(f["weight"] * 100))
        f.pop("spans", None)

    if not text.strip():
        notes.append({"title": "Empty message", "detail": "There is nothing to analyse."})

    return {
        "score": score,
        "score_uncapped": raw_score,
        "cap_applied": capped,
        "level": level,
        "category": category,
        "summary": scoring.LEVEL_SUMMARY[level],
        "advice": scoring.advice_for(level, category),
        "channel": channel,
        "channel_detected": detected,
        "factors": factors,
        "notes": notes,
        "highlights": _clean_highlights(highlights, len(text)),
        "entities": {
            "urls": [{"raw": r["raw"], "display": r["display"], "domain": r["registered_domain"],
                      "level": r["level"], "score": r["score"], "trusted": r["trusted"]} for r in url_results],
            "domains": sorted({r["registered_domain"] for r in url_results if r["valid"] and r["registered_domain"]}),
            "emails": entities.emails, "phones": entities.phones,
            "upi_ids": entities.upi_ids, "amounts": entities.amounts,
        },
        "urls": url_results,
        "brands": [b["brand"] for b in mentioned],
        "ml_text": ml_text,
        "formula": "risk = 1 - (1 - w1) x (1 - w2) x ... ; score = risk x 100",
        "text": text,
        "sender": sender,
        "sender_history": {"count": history["count"], "max_score": history.get("max_score"),
                           "links": history.get("links", [])[:3]} if history and history.get("count") else None,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
    }


def _clean_highlights(items: list[dict], length: int) -> list[dict]:
    """Sort and drop overlaps. Priority: link > rule > brand > model word."""
    rank = {"url": 0, "rule": 1, "brand": 2, "ml": 3}
    items = [h for h in items if 0 <= h["start"] < h["end"] <= length]
    items.sort(key=lambda h: (rank[h["kind"]], h["start"], -(h["end"] - h["start"])))
    kept: list[dict] = []
    for h in items:
        if all(h["end"] <= k["start"] or h["start"] >= k["end"] for k in kept):
            kept.append(h)
    return sorted(kept, key=lambda h: h["start"])
