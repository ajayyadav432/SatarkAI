"""Security of our own application: injection, unsafe links, CSV formulas, internal addresses."""
import csv
import io
import re
from pathlib import Path

import pytest

from app import config, db
from app.analysis import lookup
from app.analysis.pipeline import analyze
from app.analysis.url_features import parse_url

XSS = '<script>alert("x")</script><img src=x onerror=alert(1)> "\'><svg onload=alert(1)>'


def test_security_headers(client):
    for path in ("/", "/go", "/api/health", "/static/app.js"):
        h = client.get(path).headers
        csp = h["content-security-policy"]
        assert "default-src 'self'" in csp and "script-src 'self'" in csp and "object-src 'none'" in csp
        assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
        assert "frame-ancestors 'none'" in csp
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"


@pytest.fixture()
def save_everything(monkeypatch):
    """These tests check how stored text is handled; their harmless messages would score below 50 and
    not be saved, so the minimum is switched off for them."""
    monkeypatch.setattr(config, "SAVE_MIN_SCORE", 0)


def test_html_in_a_message_is_returned_as_data_not_markup(client, save_everything):
    r = client.post("/api/analyze", json={"text": XSS, "sender": XSS[:100]})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    assert r.json()["text"] == XSS            # stored and returned unchanged, as JSON text
    cid = r.json()["case_id"]
    assert client.get(f"/api/cases/{cid}").json()["text"] == XSS
    assert client.get("/api/cases", params={"q": "script"}).json()["total"] == 1


def test_front_end_never_builds_html_from_data():
    """The UI inserts all data with textContent; it must not use innerHTML and friends."""
    for name in ("app.js", "go.js"):
        src = (config.STATIC_DIR / name).read_text(encoding="utf-8")
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert banned not in src, f"{banned} used in {name}"


def test_pages_have_no_inline_script_or_style():
    for name in ("index.html", "go.html"):
        html = (config.STATIC_DIR / name).read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>", html), f"inline <script> in {name}"
        assert not re.search(r"\son\w+\s*=", html), f"inline event handler in {name}"
        assert "style=" not in html and "<style" not in html, f"inline style in {name}"
        assert "http://" not in html and "https://" not in html, f"external resource in {name}"


def test_sql_injection_in_search_and_filters(client, save_everything):
    client.post("/api/analyze", json={"text": "Dear customer update your KYC now"})
    attacks = ["' OR '1'='1", "'; DROP TABLE cases; --", '" OR 1=1 --', "kyc') UNION SELECT 1,2,3 --",
               "NEAR(", '"', "*", "kyc AND", "text:kyc", "(((", "\x00", "a" * 190]
    for a in attacks:
        r = client.get("/api/cases", params={"q": a})
        assert r.status_code == 200, a
        assert r.json()["total"] in (0, 1), a
    for field in ("level", "category", "status", "channel", "source"):
        r = client.get("/api/cases", params={field: "x' OR '1'='1"})
        assert r.status_code == 200 and r.json()["total"] == 0, field
    assert client.get("/api/cases").json()["total"] == 1       # table still there


def test_sql_injection_through_stored_text(client, save_everything):
    evil = "Robert'); DROP TABLE cases;-- http://x.com/'; DELETE FROM cases;--"
    cid = client.post("/api/analyze", json={"text": evil, "sender": "'; DROP TABLE cases;--"}).json()["case_id"]
    client.patch(f"/api/cases/{cid}", json={"notes": "'); DROP TABLE cases;--"})
    assert client.get(f"/api/cases/{cid}").json()["notes"] == "'); DROP TABLE cases;--"
    assert client.get("/api/cases").json()["total"] == 1


def test_csv_export_neutralises_formulas(client, save_everything):
    for text in ("=HYPERLINK(\"http://evil.com\",\"click\")", "+1+1", "-2+3", "@SUM(A1:A9)"):
        client.post("/api/analyze", json={"text": text, "sender": "=cmd|' /C calc'!A0"})
    rows = list(csv.reader(io.StringIO(client.get("/api/cases/export.csv").text.lstrip("﻿"))))
    header, body = rows[0], rows[1:]
    assert len(body) == 4
    for row in body:
        for cell in row:
            assert cell[:1] not in ("=", "+", "-", "@", "\t", "\r"), cell
        assert row[header.index("sender")].startswith("'=")


def test_warning_page_only_opens_http_links(client):
    for bad in ("javascript:alert(document.cookie)", "data:text/html;base64,PHNjcmlwdD4=", "vbscript:msgbox(1)"):
        r = client.get("/api/check-url", params={"u": bad})
        assert r.status_code == 400 or not r.json()["url"].lower().startswith(("javascript:", "data:", "vbscript:"))
    # The page script itself re-checks the scheme before it builds the link.
    assert "/^https?:\\/\\//i.test(target)" in (config.STATIC_DIR / "go.js").read_text(encoding="utf-8")


def test_links_are_never_fetched_during_analysis(monkeypatch):
    """Analysing a message must not make any network connection."""
    import socket

    def boom(*a, **k):
        raise AssertionError("network access during analysis")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    r = analyze("Verify now http://sbi-kyc-update.xyz/login and http://192.168.0.1/admin and bit.ly/abc")
    assert r["score"] > 0 and len(r["urls"]) == 3


def test_live_lookup_blocks_internal_targets(monkeypatch):
    def no_http(*a, **k):
        raise AssertionError("RDAP must not be called for internal targets")

    monkeypatch.setattr(lookup, "domain_age", no_http)
    for url in ("http://127.0.0.1/admin", "http://10.0.0.5:8080/", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/",
                "http://localhost/", "http://printer.local/", "http://intranet/", "http://[::1]/"):
        out = lookup.live_lookup(parse_url(url))
        assert out.get("blocked") is True, url

    # A public-looking name that resolves to a private address is reported and not looked up further.
    monkeypatch.setattr(lookup, "resolve", lambda host: {"ok": True, "addresses": ["10.1.2.3"], "internal": True})
    out = lookup.live_lookup(parse_url("http://rebind.example.com/"))
    assert out["blocked"] is True and out["factors"][0]["id"] == "lookup_internal_address"


def test_live_lookup_rejects_unsafe_domain_names():
    for bad in ("exa mple.com", "example.com/../../etc", "a..b", "-bad-.com", "exämple.com", "x" * 300 + ".com", ""):
        assert lookup.domain_age(bad)["ok"] is False, bad
    for ip in ("127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.0.1", "169.254.1.1", "::1", "fc00::1", "0.0.0.0", "not-an-ip"):
        assert lookup.is_internal_ip(ip) is True, ip
    assert lookup.is_internal_ip("8.8.8.8") is False


def test_live_lookup_new_domain_is_evidence(monkeypatch):
    monkeypatch.setattr(lookup, "resolve", lambda host: {"ok": True, "addresses": ["93.184.216.34"], "internal": False})
    monkeypatch.setattr(lookup, "domain_age", lambda d: {"ok": True, "registered": "2026-10-10", "age_days": 4, "registrar": "X"})
    out = lookup.live_lookup(parse_url("http://brand-new-site.com/"))
    assert out["factors"][0]["id"] == "lookup_new_domain" and out["factors"][0]["weight"] == 0.5
    monkeypatch.setattr(lookup, "domain_age", lambda d: {"ok": True, "registered": "2010-01-01", "age_days": 6000, "registrar": "X"})
    assert lookup.live_lookup(parse_url("http://old-site.com/"))["factors"] == []
    monkeypatch.setattr(lookup, "domain_age", lambda d: {"ok": False, "error": "RDAP service not reachable"})
    assert lookup.live_lookup(parse_url("http://old-site.com/"))["factors"] == []     # failure is not evidence


def test_very_large_and_odd_inputs_do_not_crash():
    for text in ("a" * 20000, "http://" + "a." * 500 + "com", "‮​" * 500, "🙂" * 3000, "." * 5000,
                 "@" * 3000, "http://" * 2000, "a@" * 4000, "(" * 9000, "9" * 15000, "\n" * 8000):
        r = analyze(text)
        assert 0 <= r["score"] <= 100


def test_analysis_time_is_bounded():
    """Guard against catastrophic regular-expression backtracking."""
    import time
    nasty = ["dear " * 3000, "pay rs " * 2500, "your account " * 1500 + "x", "call " + "1 " * 9000,
             "click " + "the " * 5000, "a-" * 9000 + ".com", "earn rs 1 " * 2000]
    for text in nasty:
        t0 = time.perf_counter()
        analyze(text, channel="sms")
        assert time.perf_counter() - t0 < 5.0, text[:20]


def test_database_file_is_the_test_database():
    assert "satark-test" in str(db.config.DB_PATH) or "pytest" in str(db.config.DB_PATH)
    assert Path(config.ROOT / "data" / "history.db") != db.config.DB_PATH
