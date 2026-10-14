"""Find URLs, e-mail addresses, phone numbers, UPI IDs and money amounts in a message.

Scammers often "defang" or disguise links (hxxp://, example[.]com, bare domains with
no http). All of these are found and normalised to a real URL.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

import tldextract

from app import config

# Use the public-suffix list bundled with tldextract: no network call, works offline.
_TLD = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def split_domain(host: str):
    """tldextract result for a host (subdomain, domain, suffix, is_private)."""
    return _TLD(host)


# --- defanging -------------------------------------------------------------

_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"
_REFANG = [
    (re.compile(r"\bh(?:xx|\*\*)p(s?)", re.I), r"http\1"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[(?:at|@)\]|\((?:at)\)", re.I), "@"),
]


def refang(text: str) -> str:
    """hxxps://evil[.]com -> https://evil.com"""
    for rx, repl in _REFANG:
        text = rx.sub(repl, text)
    return text


def defang(url: str) -> str:
    """https://evil.com -> hxxps://evil[.]com  (safe to display, cannot be clicked)."""
    out = re.sub(r"^http", "hxxp", url, flags=re.I)
    scheme, sep, rest = out.partition("://")
    if not sep:
        scheme, rest = "", out
    host, slash, tail = rest.partition("/")
    host = host.replace(".", "[.]")
    return f"{scheme}{sep}{host}{slash}{tail}"


# --- patterns --------------------------------------------------------------

_SCHEME_URL = re.compile(
    r"(?:h(?:tt|xx|\*\*)ps?|ftp)(?:\[:\]|:)(?://|\[/\]\[/\])[^\s<>\"'`]+", re.I
)
_WWW_URL = re.compile(rf"(?<![\w@/.-])www\d{{0,2}}{_DOT}[^\s<>\"'`]+", re.I)
_LABEL = r"[^\W_](?:[^\W_]|-)*"
_BARE_DOMAIN = re.compile(
    rf"(?<![\w@/.\-\]])(?:{_LABEL}{_DOT})+[^\W\d_]{{2,24}}(?::\d{{2,5}})?(?:[/?#][^\s<>\"'`]*)?",
    re.I,
)
_IP_URL = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?:/[^\s<>\"'`]*)?(?![\w])"
)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@(?:[^\W_](?:[^\W_]|-)*\.)+[^\W\d_]{2,24}(?![\w-])")
_UPI = re.compile(r"(?<![\w.@-])[\w.\-]{2,64}@[a-zA-Z][a-zA-Z0-9]{1,31}(?![\w@-])(?!\.\w)")
_PHONE_PATTERNS = [
    re.compile(r"(?<![\d+])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),      # Indian mobile
    re.compile(r"(?<![\d+])1800[\s-]?\d{3}[\s-]?\d{3,4}(?!\d)"),                   # Indian toll-free
    re.compile(r"(?<![\d+])\+\d{1,3}[\s-]?\d{2,5}[\s-]?\d{3,5}[\s-]?\d{3,5}(?!\d)"),  # international
    re.compile(r"(?<![\d+])0\d{9,10}(?!\d)"),                                      # 0-prefixed national
]
_AMOUNT = re.compile(
    r"(?:(?:rs\.?|inr|usd|₹|\$|£|€)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:lakhs?|lacs?|crores?|cr|k|million|billion))?)"
    r"|(?:\d[\d,]*(?:\.\d+)?\s?(?:rupees|rs\.?|lakhs?|lacs?|crores?|dollars|pounds|usd|inr)\b)"
    r"|(?:\d[\d,]*(?:\.\d+)?\s?(?:रुपये|रुपए|रु\.?|लाख|करोड़))",
    re.I,
)

# A name written with no http, no www and no path ("abc.com") is read as a link only
# when its TLD is in this list. Reason: measured on the 4,827 normal messages of the
# SMS Spam Collection, sloppy typing such as "Wife.how", "her.love", "days.so" matched
# real TLDs and produced false links. The list is the TLDs seen at least 60 times in
# the PhiUSIIL URL dataset, minus TLDs that are everyday English / Hinglish words
# (it, me, us, be, at, no, is, to, my, so, se, pe, ke, hu, ga, live, work, win, ...),
# plus a few generic TLDs that are not ordinary words.
# Links with http, www or a path (bit.ly/abc, t.me/group) are always found.
_BARE_TLDS = set(
    "com org net app uk co io de ru au dev top jp edu fr br nl ca info site xyz link in "
    "gov cf ml cn eu es nz cz ch ro club za gr mx gq page ie biz cloud shop cc ws ua dk "
    "fi cl mil online kr il pt tv sg vn ly ir tw tk sk pk ph ng icu hk ae bg network ee "
    "pro cfd pw tech store su vip space bio click lk asia ai mobi np "
    "buzz cyou sbs website finance loans digital email download bid trade stream bank".split()
)
# "come.in", "sign.in": words that are followed by "in" far more often than they are domains.
_NOT_A_DOMAIN_LABEL = {
    "come", "sign", "check", "log", "login", "join", "back", "stay", "turn", "move", "give",
    "hand", "fill", "drop", "tune", "plug", "cash", "live", "lives", "born", "made", "get",
    "let", "was", "were", "been", "went", "came", "put", "all", "not", "now", "here", "there",
}

_TRAILING = ".,;:!?'\"`|…।"
_CLOSERS = {")": "(", "]": "[", "}": "{", ">": "<"}

# UPI handles ("abc@okaxis"). Not complete; used only to label an ID as a known handle.
KNOWN_UPI_HANDLES = {
    "upi", "ybl", "ibl", "axl", "apl", "paytm", "okaxis", "oksbi", "okhdfcbank", "okicici",
    "sbi", "hdfcbank", "icici", "axisbank", "kotak", "pnb", "boi", "cnrb", "barodampay",
    "ptyes", "ptsbi", "ptaxis", "pthdfc", "fbl", "idfcbank", "yesbank", "indus", "airtel",
    "jio", "freecharge", "ikwik", "jupiteraxis", "yapl", "rapl", "waaxis", "wasbi",
    "wahdfcbank", "waicici", "naviaxis", "slice", "pz", "superyes", "timecosmos",
}


@dataclass
class FoundUrl:
    raw: str            # exactly as written in the message
    url: str            # normalised, with scheme
    start: int
    end: int
    defanged: bool = False
    had_scheme: bool = True


@dataclass
class Entities:
    urls: list[FoundUrl] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    amounts: list[str] = field(default_factory=list)
    urls_truncated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _trim(raw: str) -> str:
    """Drop trailing punctuation that belongs to the sentence, not the URL."""
    while raw:
        last = raw[-1]
        if last in _TRAILING:
            raw = raw[:-1]
        elif last in _CLOSERS and raw.count(last) > raw.count(_CLOSERS[last]):
            raw = raw[:-1]
        else:
            break
    return raw


def _looks_like_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and int(p) <= 255 for p in parts)


def _valid_bare_domain(raw: str, clean: str) -> bool:
    """A bare 'something.tld' counts as a link only if the TLD really exists."""
    host = re.split(r"[/?#:]", clean, maxsplit=1)[0]
    ext = split_domain(host)
    if not ext.suffix or not ext.domain:
        return False
    # "end.Next sentence" - a missing space after a full stop, not a domain.
    raw_host = re.split(r"[/?#:]", raw, maxsplit=1)[0]
    last_label = re.split(_DOT, raw_host, flags=re.I)[-1]
    if last_label[:1].isupper() and not raw_host.isupper() and len(raw) == len(raw_host):
        return False
    # No scheme, no www, no path: accept only TLDs that are not ordinary words.
    if len(raw) == len(raw_host):
        if ext.suffix.split(".")[-1] not in _BARE_TLDS:
            return False
        if ext.domain.lower() in _NOT_A_DOMAIN_LABEL or len(ext.domain) < 2:
            return False
    return True


def normalise_url(raw: str) -> str:
    """Refang and add a scheme. Does not open or fetch anything."""
    url = refang(raw.strip())
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    return url


def extract_entities(text: str) -> Entities:
    ent = Entities()
    taken: list[tuple[int, int]] = []

    def overlaps(s: int, e: int) -> bool:
        return any(s < te and e > ts for ts, te in taken)

    def add_url(m: re.Match, had_scheme: bool, check_bare: bool = False) -> None:
        raw = _trim(m.group(0))
        if not raw:
            return
        start, end = m.start(), m.start() + len(raw)
        if overlaps(start, end):
            return
        clean = refang(raw)
        if check_bare and not _valid_bare_domain(raw, clean):
            return
        url = normalise_url(raw)[: config.MAX_URL_CHARS]
        taken.append((start, end))
        ent.urls.append(
            FoundUrl(raw=raw, url=url, start=start, end=end,
                     defanged=(clean != raw), had_scheme=had_scheme)
        )

    # E-mail addresses first, so "user@bank.com" is not read as the link "bank.com".
    email_spans = []
    for m in _EMAIL.finditer(text):
        email_spans.append((m.start(), m.end()))
        if m.group(0).lower() not in ent.emails:
            ent.emails.append(m.group(0).lower())

    for m in _SCHEME_URL.finditer(text):
        add_url(m, had_scheme=True)
    taken_before_email = list(taken)
    taken.extend(s for s in email_spans if not any(s[0] < te and s[1] > ts for ts, te in taken_before_email))
    for m in _WWW_URL.finditer(text):
        add_url(m, had_scheme=False)
    for m in _IP_URL.finditer(text):
        host = re.split(r"[/:]", m.group(0), maxsplit=1)[0]
        if _looks_like_ip(host):
            add_url(m, had_scheme=False)
    for m in _BARE_DOMAIN.finditer(text):
        add_url(m, had_scheme=False, check_bare=True)

    ent.urls.sort(key=lambda u: u.start)
    if len(ent.urls) > config.MAX_URLS_PER_MESSAGE:
        ent.urls = ent.urls[: config.MAX_URLS_PER_MESSAGE]
        ent.urls_truncated = True

    url_spans = [(u.start, u.end) for u in ent.urls]

    def inside_url(s: int, e: int) -> bool:
        return any(s >= us and e <= ue for us, ue in url_spans)

    for m in _UPI.finditer(text):
        if inside_url(m.start(), m.end()):
            continue
        if any(m.start() >= s and m.end() <= e for s, e in email_spans):
            continue
        value = m.group(0).lower()
        if value not in ent.upi_ids:
            ent.upi_ids.append(value)

    seen_digits = set()
    for rx in _PHONE_PATTERNS:
        for m in rx.finditer(text):
            if inside_url(m.start(), m.end()):
                continue
            digits = re.sub(r"\D", "", m.group(0))
            key = digits[-10:]
            if key in seen_digits:
                continue
            seen_digits.add(key)
            ent.phones.append(m.group(0).strip())

    for m in _AMOUNT.finditer(text):
        if inside_url(m.start(), m.end()):
            continue
        value = m.group(0).strip()
        if value not in ent.amounts:
            ent.amounts.append(value)

    return ent


def phone_kind(phone: str) -> str:
    """'mobile', 'toll_free' or 'other' for an extracted phone number."""
    digits = re.sub(r"\D", "", phone)
    if digits.startswith("1800"):
        return "toll_free"
    core = digits[-10:]
    if len(digits) in (10, 11, 12) and len(core) == 10 and core[0] in "6789":
        if len(digits) == 10 or digits[:-10] in ("0", "91"):
            return "mobile"
    return "other"
