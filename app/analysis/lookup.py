"""Optional live lookup: DNS and domain age (RDAP). Off by default; needs internet.

Safety: the suspicious link itself is NEVER opened. We only
  1. ask DNS for the host's IP addresses, and
  2. ask the public RDAP service (rdap.org) when the registered domain was created.
Hosts that are, or resolve to, internal addresses are reported and not looked up further.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone

import httpx

RDAP_URL = "https://rdap.org/domain/{domain}"
DNS_TIMEOUT = 4.0
RDAP_TIMEOUT = 6.0
_SAFE_DOMAIN = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet", ".test", ".invalid")
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="lookup")


def is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
            or addr.is_multicast or addr.is_unspecified)


def is_internal_name(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host == "localhost" or "." not in host or host.endswith(_INTERNAL_SUFFIXES)


def _resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({i[4][0] for i in infos})


def resolve(host: str) -> dict:
    future = _pool.submit(_resolve, host)
    try:
        ips = future.result(timeout=DNS_TIMEOUT)
    except FutureTimeout:
        return {"ok": False, "error": "DNS lookup timed out"}
    except socket.gaierror:
        return {"ok": False, "error": "The name does not exist in DNS"}
    except OSError as exc:
        return {"ok": False, "error": f"DNS lookup failed: {exc}"}
    return {"ok": True, "addresses": ips[:6], "internal": any(is_internal_ip(ip) for ip in ips)}


def domain_age(domain: str) -> dict:
    """Registration date of a registered domain from RDAP."""
    if not _SAFE_DOMAIN.match(domain):
        return {"ok": False, "error": "Domain name is not valid for an RDAP query"}
    try:
        with httpx.Client(timeout=RDAP_TIMEOUT, follow_redirects=True, max_redirects=4,
                          headers={"Accept": "application/rdap+json", "User-Agent": "satarkai/1.0"}) as client:
            resp = client.get(RDAP_URL.format(domain=domain))
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"RDAP service not reachable ({type(exc).__name__})"}
    if resp.status_code == 404:
        return {"ok": False, "not_found": True, "error": "No registration record found for this domain"}
    if resp.status_code != 200:
        return {"ok": False, "error": f"RDAP service answered {resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return {"ok": False, "error": "RDAP answer could not be read"}
    registered = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            registered = event.get("eventDate")
            break
    if not registered:
        return {"ok": False, "error": "The registry does not publish a registration date"}
    try:
        when = datetime.fromisoformat(registered.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
    except ValueError:
        return {"ok": False, "error": "Registration date could not be read"}
    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            try:
                for item in ent["vcardArray"][1]:
                    if item[0] == "fn":
                        registrar = str(item[3])[:120]
            except (KeyError, IndexError, TypeError):
                pass
    age_days = (datetime.now(timezone.utc) - when).days
    return {"ok": True, "registered": when.date().isoformat(), "age_days": age_days,
            "registrar": registrar, "source": str(resp.url)}


def live_lookup(info) -> dict:
    """DNS and domain age for a parsed URL. Returns notes and, when warranted, risk factors."""
    out: dict = {"performed": True, "dns": None, "rdap": None, "factors": [], "notes": []}

    if info.is_ip:
        internal = is_internal_ip(info.host)
        out["notes"].append("Host is an IP address" + (" on a private / internal network." if internal else "."))
        out["blocked"] = internal
        return out
    if is_internal_name(info.host):
        out["blocked"] = True
        out["notes"].append("Internal host name: no lookup was made.")
        return out

    dns = resolve(info.host)
    out["dns"] = dns
    if not dns["ok"]:
        out["notes"].append(f"DNS: {dns['error']}. The site may have been taken down.")
    elif dns["internal"]:
        out["blocked"] = True
        out["factors"].append({
            "id": "lookup_internal_address", "source": "live-lookup",
            "title": "Domain points to a private network address",
            "detail": "A public website never resolves to an internal address.",
            "weight": 0.4, "evidence": dns["addresses"][:2]})
        return out

    if info.suffix_is_private or not info.suffix:
        out["notes"].append("Domain age is not checked for hosting-platform subdomains.")
        return out

    rdap = domain_age(info.registered_domain)
    out["rdap"] = rdap
    if rdap["ok"]:
        days = rdap["age_days"]
        if days < 30:
            out["factors"].append({
                "id": "lookup_new_domain", "source": "live-lookup",
                "title": f"Domain was registered only {days} day(s) ago",
                "detail": f"{info.registered_domain} was registered on {rdap['registered']}. "
                          "Phishing sites are usually only days old.",
                "weight": 0.5, "evidence": [rdap["registered"]]})
        elif days < 180:
            out["factors"].append({
                "id": "lookup_young_domain", "source": "live-lookup",
                "title": f"Domain is only {days} days old",
                "detail": f"{info.registered_domain} was registered on {rdap['registered']}.",
                "weight": 0.25, "evidence": [rdap["registered"]]})
        else:
            years = days / 365.25
            out["notes"].append(f"Domain registered on {rdap['registered']} ({years:.1f} years ago).")
    else:
        out["notes"].append(f"Domain age: {rdap['error']}.")
    return out
