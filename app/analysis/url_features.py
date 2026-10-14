"""Analyse one URL from its text only. Nothing here opens or fetches the link.

Two outputs:
  * lexical_features(): numbers used by the URL machine-learning model
  * heuristic_findings(): known tricks (IP address host, '@', lookalike domain, ...)
"""
from __future__ import annotations

import json
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import unquote, urlsplit

from app import config
from app.analysis import brands
from app.analysis.extract import split_domain


@lru_cache(maxsize=1)
def lists() -> dict:
    data = json.loads((config.KNOWLEDGE_DIR / "url_lists.json").read_text(encoding="utf-8"))
    data["shorteners"] = set(data["shorteners"])
    data["sensitive_words"] = set(data["sensitive_words"])
    data["tld_like_labels"] = set(data["tld_like_labels"])
    return data


@dataclass
class UrlInfo:
    url: str
    scheme: str = ""
    host: str = ""              # lower case, ASCII (punycode) form
    host_unicode: str = ""      # as a person would read it
    port: int | None = None
    path: str = ""
    query: str = ""
    userinfo: str = ""
    registered_domain: str = ""
    domain_label: str = ""
    subdomain: str = ""         # without a leading "www"
    suffix: str = ""
    suffix_is_private: bool = False
    is_ip: bool = False
    valid: bool = True
    trusted: bool = False
    official_brand: str | None = None
    restricted_registry: bool = False
    user_content_host: str | None = None
    is_shortener: bool = False
    is_messaging: bool = False
    features: dict = field(default_factory=dict)


# Endings that look like TLDs inside a path but are file types.
_FILE_SUFFIXES = {"php", "html", "htm", "asp", "aspx", "jsp", "js", "css", "png", "jpg", "gif", "pdf",
                  "zip", "py", "sh", "pl", "md", "do", "cgi", "xml", "json", "txt"}

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IP_ODD = re.compile(r"^(?:0x[0-9a-f]+|\d{8,10})$", re.I)  # hex or single-integer IP


def _to_ascii_host(host: str) -> str:
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        labels = []
        for label in host.split("."):
            try:
                labels.append(label.encode("idna").decode("ascii") if not label.isascii() else label)
            except UnicodeError:
                labels.append("xn--" + label.encode("punycode").decode("ascii"))
        return ".".join(labels)


def _to_unicode_host(host: str) -> str:
    if "xn--" not in host:
        return host
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except UnicodeError:
                pass
        out.append(label)
    return ".".join(out)


def _scripts(s: str) -> set[str]:
    """Writing systems used by the letters of s (LATIN, CYRILLIC, DEVANAGARI, ...)."""
    found = set()
    for ch in s:
        if ch.isalpha():
            try:
                found.add(unicodedata.name(ch).split(" ")[0])
            except ValueError:
                found.add("UNKNOWN")
    return found


def _host_matches(host: str, names) -> str | None:
    for n in names:
        if host == n or host.endswith("." + n):
            return n
    return None


def parse_url(url: str) -> UrlInfo:
    info = UrlInfo(url=url)
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").strip().rstrip(".").lower()
        port = parts.port
    except ValueError:
        info.valid = False
        return info
    if not host or ".." in host or host.startswith(".") or len(host) > 253:
        info.valid = False
        return info

    info.scheme = (parts.scheme or "").lower()
    info.port = port
    info.path = parts.path or ""
    info.query = parts.query or ""
    info.userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""
    info.host_unicode = _to_unicode_host(host)
    info.host = _to_ascii_host(host)

    info.is_ip = bool(_IPV4.match(info.host) or _IP_ODD.match(info.host) or ":" in info.host)
    if info.is_ip:
        info.registered_domain = info.host
        info.domain_label = info.host
    else:
        ext = split_domain(info.host)
        info.suffix = ext.suffix
        info.suffix_is_private = bool(getattr(ext, "is_private", False))
        info.domain_label = ext.domain
        info.registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        sub = ext.subdomain
        if sub == "www":
            sub = ""
        elif sub.startswith("www."):
            sub = sub[4:]
        info.subdomain = sub

    L = lists()
    info.user_content_host = _host_matches(info.host, L["user_content_hosts"])
    if not info.user_content_host and info.suffix_is_private:
        info.user_content_host = info.suffix
    info.is_shortener = bool(_host_matches(info.host, L["shorteners"]))
    info.is_messaging = bool(_host_matches(info.host, L["messaging_hosts"]))

    if not (info.is_ip or info.user_content_host or info.is_shortener or info.is_messaging):
        info.official_brand = brands.official_brand(info.registered_domain)
        info.restricted_registry = brands.is_restricted(info.host)
        info.trusted = bool(info.official_brand) or info.restricted_registry

    info.features = lexical_features(info)
    return info


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def sensitive_hits(s: str) -> list[str]:
    """Sensitive words (login, verify, kyc, ...) found as a token or inside a longer token."""
    words = lists()["sensitive_words"]
    hits = []
    for tok in _tokens(s):
        if tok in words:
            best = tok
        else:
            inside = [w for w in words if len(w) >= 5 and w in tok]
            best = max(inside, key=len) if inside else None
        if best and best not in hits:
            hits.append(best)
    return hits


def lexical_features(info: UrlInfo) -> dict:
    """Numbers computed from the URL text, in three groups: domain, subdomain, path.

    Scheme and 'www' are deliberately not features. In the PhiUSIIL dataset every
    legitimate URL is 'https://www.<domain>' with no subdomain and no path, so scheme,
    'www', subdomains and paths would let a model cheat (see PLAN.md, section 12).
    """
    label = info.domain_label
    sub = info.subdomain
    path_q = info.path + ("?" + info.query if info.query else "")
    path_decoded = unquote(path_q)
    letters = [c for c in label if c.isalpha()]
    vowels = sum(1 for c in letters if c in "aeiou")
    path_tail = info.path.rsplit("/", 1)[-1].lower()
    ext = path_tail.rsplit(".", 1)[-1] if "." in path_tail else ""

    embedded = 0
    for tok in re.split(r"[/?&=]+", path_decoded.lower()):
        if "." in tok and not tok.startswith("."):
            e = split_domain(tok)
            if e.suffix and e.domain and tok.endswith(e.suffix) and e.suffix not in _FILE_SUFFIXES:
                embedded += 1

    return {
        # domain group
        "domain_label_len": len(label) if not info.is_ip else 0,
        "n_hyphens_domain": label.count("-"),
        "n_digits_domain": sum(c.isdigit() for c in label) if not info.is_ip else 0,
        "domain_entropy": round(_entropy(label), 3) if not info.is_ip else 0.0,
        "vowel_ratio": round(vowels / len(letters), 3) if letters else 0.0,
        "is_ip": int(info.is_ip),
        "has_punycode": int("xn--" in info.host),
        "private_suffix": int(bool(info.user_content_host)),
        "domain_sensitive": len(sensitive_hits(label)),
        # subdomain group
        "n_subdomains": len([p for p in sub.split(".") if p]),
        "subdomain_len": len(sub),
        "n_hyphens_sub": sub.count("-"),
        "n_digits_sub": sum(c.isdigit() for c in sub),
        "sub_sensitive": len(sensitive_hits(sub)),
        # path group
        "path_len": len(info.path) if info.path != "/" else 0,
        "path_depth": len([p for p in info.path.split("/") if p]),
        "query_len": len(info.query),
        "n_params": len([p for p in info.query.split("&") if p]) if info.query else 0,
        "n_digits_path": sum(c.isdigit() for c in path_q),
        "n_dots_path": path_q.count("."),
        "n_special_path": sum(path_q.count(c) for c in "@%=&~+;!$"),
        "path_sensitive": len(sensitive_hits(path_decoded)),
        "has_exec_ext": int(ext in lists()["exec_extensions"]),
        "embedded_domain": min(embedded, 2),
        "has_at": int(bool(info.userinfo) or "@" in path_q),
        "double_slash_path": int("//" in info.path),
    }


def tld_of(info: UrlInfo) -> str:
    """Last label of the public suffix ('co.in' -> 'in'). Empty for IP hosts."""
    if info.is_ip or not info.suffix:
        return ""
    return info.suffix.split(".")[-1]


def _finding(fid: str, title: str, detail: str, weight: float, evidence: str) -> dict:
    return {"id": fid, "source": "url-check", "title": title, "detail": detail,
            "weight": round(weight, 3), "evidence": [evidence] if evidence else []}


def heuristic_findings(info: UrlInfo, had_scheme: bool = True) -> list[dict]:
    """Known link tricks. Each finding has a fixed, hand-set weight."""
    out: list[dict] = []
    if not info.valid or info.trusted:
        return out
    L = lists()
    shown = info.host_unicode

    if info.is_ip:
        out.append(_finding(
            "url_ip_host", "Link uses a raw IP address",
            "Real organisations use a domain name. An IP address hides who runs the site.",
            0.55, info.host))

    if info.userinfo:
        out.append(_finding(
            "url_userinfo", "Link hides its real destination with '@'",
            f"Everything before '@' is ignored by the browser. The link really opens {shown}.",
            0.5, info.userinfo + "@"))

    if "xn--" in info.host or not info.host_unicode.isascii():
        scripts_per_label = [_scripts(lbl) for lbl in info.host_unicode.split(".")]
        mixed = any(len(s) > 1 for s in scripts_per_label)
        non_latin = {s for group in scripts_per_label for s in group} - {"LATIN"}
        if mixed:
            out.append(_finding(
                "url_mixed_script", "Domain mixes alphabets to imitate another name",
                "Letters from different alphabets (for example Cyrillic 'а' and Latin 'a') look "
                "the same but make a different domain.",
                0.65, f"{shown} = {info.host}"))
        elif non_latin & {"CYRILLIC", "GREEK", "ARMENIAN"}:
            out.append(_finding(
                "url_lookalike_script", "Domain is written in a lookalike alphabet",
                f"The domain uses {', '.join(sorted(non_latin)).title()} letters, which can look "
                "identical to English letters.",
                0.55, f"{shown} = {info.host}"))
        else:
            out.append(_finding(
                "url_idn", "Domain uses non-English characters (IDN)",
                "Internationalised domains are legal but are also used for lookalike names.",
                0.25, f"{shown} = {info.host}"))

    for f in brands.check_host(info.host, info.registered_domain, info.domain_label,
                               info.subdomain, info.path):
        official = ", ".join(brands.official_domains_of(f["brand"])[:3])
        if f["kind"] == "lookalike":
            out.append(_finding(
                "url_lookalike", f"Domain looks like a misspelling of {f['brand']}",
                f"'{f['matched']}' is almost '{f['looks_like']}'. Official: {official}.",
                0.7, f["matched"]))
        elif f["kind"] == "brand_in_host":
            out.append(_finding(
                "url_brand_in_host", f"Uses the name {f['brand']} on a domain {f['brand']} does not own",
                f"'{f['matched']}' appears in the {f['where']}, but the site is "
                f"{info.registered_domain}. Official: {official}.",
                0.6, f["matched"]))
        else:
            out.append(_finding(
                "url_brand_in_path", f"Mentions {f['brand']} in the link path",
                f"The site is {info.registered_domain}, not an official {f['brand']} domain "
                f"({official}).",
                0.35, f["matched"]))

    sub_labels = [p for p in info.subdomain.split(".") if p]
    if any(lbl in L["tld_like_labels"] for lbl in sub_labels) and len(sub_labels) >= 2:
        out.append(_finding(
            "url_deceptive_subdomain", "Subdomain is made to look like a different website",
            f"'{info.subdomain}' reads like a full address, but the real site is the last part: "
            f"{info.registered_domain}.",
            0.5, info.subdomain))
    elif len(sub_labels) >= 3:
        out.append(_finding(
            "url_many_subdomains", "Unusually many subdomains",
            f"{len(sub_labels)} subdomain levels in front of {info.registered_domain}.",
            0.2, info.subdomain))

    if info.is_shortener:
        out.append(_finding(
            "url_shortener", "Shortened link hides the real destination",
            "You cannot see where this link goes until you open it.",
            0.25, info.host))
    elif info.is_messaging:
        out.append(_finding(
            "url_messaging", "Link opens a chat with an unknown person or group",
            "WhatsApp / Telegram links are a common way to move a victim to a private chat.",
            0.2, info.host))
    elif info.user_content_host:
        out.append(_finding(
            "url_user_content", "Hosted on a platform where anyone can publish a page",
            f"{info.user_content_host} hosts pages made by its users. The platform name does not "
            "make the page trustworthy.",
            0.2, info.user_content_host))

    tail = info.path.rsplit("/", 1)[-1].lower()
    ext = tail.rsplit(".", 1)[-1] if "." in tail else ""
    if ext in L["exec_extensions"]:
        weight = L["exec_extensions"][ext]
        if ext == "apk":
            title, detail = ("Link downloads an Android app (.apk)",
                             "Apps installed from a link, outside the Play Store, can read SMS and OTPs.")
        elif weight >= 0.4:
            title, detail = (f"Link downloads a program (.{ext})",
                             "Opening it can install malware.")
        else:
            title, detail = (f"Link downloads an archive (.{ext})",
                             "Archives are often used to hide malware from scanners.")
        out.append(_finding("url_download", title, detail, weight, tail))

    if info.port and info.port not in (80, 443):
        out.append(_finding(
            "url_port", "Link uses an unusual port number",
            "Public websites almost never need a port number in the address.",
            0.2, f":{info.port}"))

    words = sensitive_hits(info.host + " " + unquote(info.path + " " + info.query))
    if words:
        weight = 0.15 if len(words) == 1 else 0.25 if len(words) == 2 else 0.35
        out.append(_finding(
            "url_sensitive_words", "Link contains words used to gain trust",
            "Words such as login, verify or kyc in a link are typical of phishing pages.",
            weight, ", ".join(words[:6])))

    if re.search(r"(?:^|[?&])[\w-]{0,20}=(?:https?(?::|%3a)(?://|%2f%2f))", info.query, re.I):
        out.append(_finding(
            "url_redirect", "Link carries another link inside it",
            "A redirect parameter can send you on to a different site than the one shown.",
            0.25, info.query[:80]))

    if had_scheme and info.scheme == "http" and words:
        out.append(_finding(
            "url_no_https", "No HTTPS on a page that asks for sensitive details",
            "Anything typed on this page would be sent without encryption.",
            0.15, "http://"))

    return out
