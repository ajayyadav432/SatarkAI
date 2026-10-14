"""Sender memory: follow-up messages, the same number in different formats, and the block recommendation."""
import sqlite3

import pytest

from app import config, db, ingest
from app.analysis.followup import refers_back
from tests.conftest import OK_CHAT

TOKEN = {"x-satark-token": "test-pairing-code"}
PHISH = "HDFC Bank: Your KYC has expired. Complete KYC here http://hdfc-kyc-online.xyz/login or your account will be blocked"
FOLLOW = "Dear customer, please open the link I sent you earlier and complete it today."


@pytest.fixture(autouse=True)
def clean_feed(monkeypatch):
    monkeypatch.setattr(ingest, "_seen", type(ingest._seen)())
    monkeypatch.setattr(ingest, "_alerts", type(ingest._alerts)(maxlen=ingest._MAX_ALERTS))
    monkeypatch.setattr(ingest, "_seq", 0)


def sms(client, text, sender, ref):
    return client.post("/api/ingest", json={"text": text, "channel": "sms", "source": "sms-app",
                                            "sender": sender, "ref": ref}, headers=TOKEN).json()


@pytest.mark.parametrize("raw,key", [
    ("+919876501234", "phone:9876501234"), ("09876501234", "phone:9876501234"), ("98765 01234", "phone:9876501234"),
    ("+91-98765-01234", "phone:9876501234"), ("AD-HDFCBK", "id:AD-HDFCBK"), ("ad-hdfcbk", "id:AD-HDFCBK"),
    ("PayPal <Service@PayPa1.com>", "email:service@paypa1.com"), ("service@paypa1.com", "email:service@paypa1.com"),
    ("", ""), (None, ""),
])
def test_sender_key(raw, key):
    assert db.sender_key(raw) == key


@pytest.mark.parametrize("text,hit", [
    (FOLLOW, True), ("Did you click the above link?", True), ("Sir upar wala link kholo jaldi", True),
    ("pichla message check karo", True), ("ऊपर दिए लिंक पर क्लिक करें", True),
    ("Hey, are we meeting at 6?", False), ("Do not share this message with anyone", False), ("Your OTP is 482910", False),
])
def test_refers_back(text, hit):
    assert bool(refers_back(text)) is hit


def test_follow_up_to_an_earlier_phishing_link(client):
    """The mentor's case: a phishing link first, then a harmless-looking 'open the link I sent'."""
    alone = client.post("/api/analyze", json={"text": FOLLOW, "sender": "9812345670", "save": False}).json()
    assert alone["score"] < 40                                   # on its own the follow-up looks harmless
    first = sms(client, PHISH, "+919812345670", "1")
    assert first["level"] == "Critical"
    second = sms(client, FOLLOW, "098123 45670", "2")            # same number, written differently
    assert second["score"] >= 65 and second["level"] in ("High", "Critical")
    assert "Points to an earlier phishing link from this sender" in second["reasons"]
    full = client.get(f"/api/cases/{second['case_id']}").json()["result"]
    f = next(x for x in full["factors"] if x["id"] == "followup_link")
    assert f["source"] == "sender-history" and "hdfc-kyc-online.xyz" in f["detail"]
    # A different sender with no history gets no boost.
    other = client.post("/api/analyze", json={"text": FOLLOW, "sender": "+919000000001", "save": False}).json()
    assert other["score"] == alone["score"]


def test_follow_up_with_its_own_link_is_judged_on_that_link(client):
    sms(client, PHISH, "+919812345670", "1")
    r = client.post("/api/analyze", json={"text": "Open the link: https://www.hdfcbank.com/", "sender": "9812345670",
                                          "save": False}).json()
    assert "followup_link" not in [f["id"] for f in r["factors"]]
    assert "repeat_sender" in [f["id"] for f in r["factors"]]


def test_block_recommended_after_three_risky_messages(client):
    a = sms(client, PHISH, "+919812345670", "1")
    b = sms(client, FOLLOW, "+919812345670", "2")
    assert a["block"] is None and b["block"] is None and b["sender_risky_count"] == 2
    c = sms(client, "Final reminder: your account is suspended today. Act now.", "9812345670", "3")
    assert c["sender_risky_count"] == config.BLOCK_AFTER and c["block"]["kind"] == "phone"
    assert "Blocked numbers" in c["block"]["how"]
    alerts = client.get("/api/alerts?after=0").json()["alerts"]
    assert alerts[-1]["block"]["count"] == 3
    # The website result says so too, and safe messages from the sender do not count.
    w = client.post("/api/analyze", json={"text": OK_CHAT, "sender": "+919812345670"}).json()
    assert w["case_id"] is None and w["block"]["count"] == 3


def test_dashboard_groups_one_sender_and_history_filter(client):
    for i, s in enumerate(("+919812345670", "09812345670", "98123 45670")):
        sms(client, PHISH, s, str(i))
    st = client.get("/api/stats", params={"days": 30}).json()
    row = next(x for x in st["repeat_senders"] if x["sender_key"] == "phone:9812345670")
    assert row["n"] == 3 and row["spellings"] == 3 and row["block"] is True and st["block_after"] == 3
    cases = client.get("/api/cases", params={"sender_key": "phone:9812345670"}).json()
    assert cases["total"] == 3


def test_old_database_gets_sender_keys(tmp_path, monkeypatch):
    """A history.db from before this feature is upgraded in place, keeping every case."""
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript(db.SCHEMA)
    con.execute("INSERT INTO cases (created_at, channel, sender, text, score, level, category, result_json) "
                "VALUES ('2026-10-01T00:00:00Z', 'sms', '+91 98123 45670', 'x', 90, 'Critical', 'KYC', '{}')")
    con.commit(); con.close()
    monkeypatch.setattr(config, "DB_PATH", path)
    db.init_db()
    assert db.sender_history("9812345670")["count"] == 1
