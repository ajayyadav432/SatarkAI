"""Automatic checking: ingest endpoint, live alerts, pairing code, LAN guard, inbox watcher (fake mailbox)."""
import email
from email.message import EmailMessage
from email.policy import default as default_policy

import pytest

from app import config, ingest, mailwatch
from tests.conftest import OK_CHAT, SCAM_KYC

TOKEN = {"x-satark-token": "test-pairing-code"}


@pytest.fixture(autouse=True)
def clean_feed(monkeypatch):
    monkeypatch.setattr(ingest, "_seen", type(ingest._seen)())
    monkeypatch.setattr(ingest, "_alerts", type(ingest._alerts)(maxlen=ingest._MAX_ALERTS))
    monkeypatch.setattr(ingest, "_seq", 0)


def post(client, headers=TOKEN, **body):
    body = {"channel": "sms", "source": "sms-app", **body}
    return client.post("/api/ingest", json=body, headers=headers)


def test_ingest_analyses_saves_and_alerts(client):
    r = post(client, text=SCAM_KYC, sender="9876501234", ref="sms-1")
    assert r.status_code == 200
    out = r.json()
    assert out["level"] == "Critical" and out["case_id"] and out["reasons"]
    case = client.get(f"/api/cases/{out['case_id']}").json()
    assert case["source"] == "sms-app"
    alerts = client.get("/api/alerts?after=0").json()
    assert alerts["latest"] == 1 and alerts["alerts"][0]["case_id"] == out["case_id"]


def test_safe_message_is_saved_but_not_alerted(client):
    out = post(client, text=OK_CHAT, ref="sms-2").json()
    assert out["level"] == "Safe"
    assert client.get("/api/alerts?after=0").json()["alerts"] == []


def test_same_message_is_analysed_once(client):
    a = post(client, text=SCAM_KYC, ref="same").json()
    b = post(client, text=SCAM_KYC, ref="same").json()
    assert b["duplicate"] is True and b["case_id"] == a["case_id"]
    assert client.get("/api/alerts?after=0").json()["latest"] == 1


def test_pairing_code_required_from_other_devices(client):
    # The test client is not a loopback address, so it counts as another device.
    assert post(client, headers={}, text=SCAM_KYC).status_code == 401
    assert post(client, headers={"x-satark-token": "wrong"}, text=SCAM_KYC).status_code == 401


@pytest.mark.parametrize("body", [
    {"text": "hi", "source": "user"},          # only automatic sources
    {"text": "hi", "channel": "auto"},
    {"text": "", "ref": "x"},
    {"text": "hi", "extra": 1},
])
def test_ingest_rejects_bad_input(client, body):
    assert post(client, **body).status_code == 422


def test_visitors_without_login_cannot_see_admin_pages(anon, monkeypatch):
    """Other devices on the Wi-Fi reach the website, but History, Dashboard and alerts need an admin login."""
    monkeypatch.setattr(config, "LAN_MODE", True)
    for path in ("/api/cases", "/api/stats", "/api/alerts", "/api/auto-status", "/api/cases/export.csv"):
        assert anon.get(path).status_code == 401, path
    for path in ("/", "/api/meta", "/api/feed", "/api/stats/summary"):
        assert anon.get(path).status_code == 200, path
    assert "kpis" not in anon.get("/api/stats/summary").json()          # counts only, no messages
    assert post(anon, text=SCAM_KYC, ref="lan").status_code == 200       # the phone app (pairing code)


def test_check_urls_batch(client):
    r = client.post("/api/check-urls", json={"urls": ["http://sbi-kyc-update.xyz/login", "https://www.irctc.co.in/", "javascript:alert(1)"]}).json()["results"]
    assert r["http://sbi-kyc-update.xyz/login"]["needs_warning"] is True
    assert r["https://www.irctc.co.in/"]["level"] == "Safe"
    assert "javascript:alert(1)" not in r


# --- inbox watcher, with a fake IMAP connection -------------------------------------------------

def html_mail(subject, sender, html, msgid):
    m = EmailMessage(policy=default_policy)
    m["Subject"], m["From"], m["Message-ID"] = subject, sender, msgid
    m.set_content("This e-mail needs an HTML viewer.")
    m.add_alternative(html, subtype="html")
    return m


def test_message_text_finds_hidden_links():
    m = email.message_from_bytes(bytes(html_mail(
        "Account suspended", "PayPal <service@paypa1-secure.com>",
        '<p>Your account is limited. <a href="http://paypa1.com/signin">Log in to PayPal</a></p>', "<a@x>")),
        policy=default_policy)
    text, sender = mailwatch.message_text(m)
    assert sender == "service@paypa1-secure.com"
    assert "Account suspended" in text and "http://paypa1.com/signin" in text


class FakeIMAP:
    def __init__(self, mails):
        self.mails = mails          # {uid: bytes}
        self.flagged_seen = False

    def select(self, box, readonly=False):
        assert readonly is True     # the watcher must never change the mailbox
        return "OK", [b"1"]

    def response(self, name):
        return "OK", [b"777"]

    def uid(self, cmd, *args):
        if cmd == "search":
            return "OK", [b" ".join(str(u).encode() for u in sorted(self.mails))]
        assert "PEEK" in args[1]    # fetching must not mark mail as read
        uid = int(args[0])
        return "OK", [(b"1 (BODY[] {n})", self.mails[uid]), b")"]


def test_watcher_checks_only_new_mail(client, tmp_path, monkeypatch):
    monkeypatch.setattr(mailwatch, "STATE", tmp_path / "state.json")
    old = html_mail("Old newsletter", "news@shop.com", "<p>Hello</p>", "<old@x>")
    conn = FakeIMAP({1: bytes(old)})
    assert mailwatch.check_once(conn, "me@test") == 0          # first run: starts from now
    scam = html_mail("Your SBI account will be blocked", "alerts@sbi-kyc-update.xyz",
                     '<p>Dear customer, update your KYC immediately <a href="http://sbi-kyc-update.xyz/login">here</a>.</p>', "<new@x>")
    conn.mails[2] = bytes(scam)
    assert mailwatch.check_once(conn, "me@test") == 1
    assert mailwatch.check_once(conn, "me@test") == 0          # nothing new
    alerts = client.get("/api/alerts?after=0").json()["alerts"]
    assert len(alerts) == 1 and alerts[0]["source"] == "email-watch" and alerts[0]["level"] in ("High", "Critical")
