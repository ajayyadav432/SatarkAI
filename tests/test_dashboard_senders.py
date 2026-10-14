"""Saving rule (only score 50 or more is stored) and the dashboard's risky messages and repeat senders."""
from app import ingest
from tests.conftest import OK_CHAT, OK_OTP, SCAM_BILL, SCAM_KYC, SCAM_LOTTERY

TOKEN = {"x-satark-token": "test-pairing-code"}


def analyze(client, text, sender=None, save=True):
    return client.post("/api/analyze", json={"text": text, "sender": sender, "save": save}).json()


def test_only_score_50_or_more_is_saved(client):
    risky = analyze(client, SCAM_KYC, "9876501234")
    safe = analyze(client, OK_CHAT, "9876501234")
    assert risky["score"] >= 50 and risky["case_id"] is not None
    assert safe["score"] < 50 and safe["case_id"] is None and safe["saved_min_score"] == 50
    assert safe["level"] and safe["factors"] is not None      # still analysed and shown
    assert client.get("/api/cases").json()["total"] == 1


def test_phone_and_mail_follow_the_same_rule(client, monkeypatch):
    monkeypatch.setattr(ingest, "_seen", type(ingest._seen)())
    monkeypatch.setattr(ingest, "_alerts", type(ingest._alerts)(maxlen=ingest._MAX_ALERTS))
    monkeypatch.setattr(ingest, "_seq", 0)
    body = {"channel": "sms", "source": "sms-app", "sender": "+919876501234"}
    low = client.post("/api/ingest", json={**body, "text": OK_OTP, "ref": "a"}, headers=TOKEN).json()
    high = client.post("/api/ingest", json={**body, "text": SCAM_KYC, "ref": "b"}, headers=TOKEN).json()
    assert low["case_id"] is None and high["case_id"] is not None
    alerts = client.get("/api/alerts?after=0").json()["alerts"]
    assert [a["case_id"] for a in alerts] == [high["case_id"]]     # alerts only for saved messages


def test_repeat_senders_and_risky_messages(client):
    for text in (SCAM_KYC, SCAM_BILL, SCAM_LOTTERY):
        analyze(client, text, "+919876501234")
    analyze(client, SCAM_KYC, "alerts@sbi-kyc-update.xyz")
    analyze(client, SCAM_KYC, "AD-SBIBNK")
    analyze(client, OK_CHAT, "+919876501234")                # safe: not saved, not counted
    s = client.get("/api/stats", params={"days": 30}).json()
    senders = {x["sender"]: x for x in s["repeat_senders"]}
    phone = senders["+919876501234"]
    assert phone["n"] == 3 and phone["kind"] == "phone" and phone["max_score"] >= 80 and phone["top_category"]
    assert senders["alerts@sbi-kyc-update.xyz"]["kind"] == "email" and senders["alerts@sbi-kyc-update.xyz"]["n"] == 1
    assert senders["AD-SBIBNK"]["kind"] == "sender-id"
    assert s["repeat_senders"][0]["sender"] == "+919876501234"      # most risky messages first
    assert s["risky_sender_count"] == 3
    assert len(s["risky_messages"]) == 5 and all(m["score"] >= 50 for m in s["risky_messages"])
    # Clicking a sender searches History for that sender.
    found = client.get("/api/cases", params={"q": "+919876501234"}).json()
    assert found["total"] == 3


def test_dashboard_filters(client):
    analyze(client, SCAM_KYC, "+919876501234")
    analyze(client, SCAM_BILL, "+919876501234")
    analyze(client, SCAM_KYC, "alerts@sbi-kyc-update.xyz")
    analyze(client, SCAM_LOTTERY, "AD-PRIZES")
    analyze(client, SCAM_LOTTERY, None)
    st = lambda **f: client.get("/api/stats", params={"days": 30, **f}).json()
    assert st()["risky_total"] == 5
    assert {x["sender"] for x in st(kind="phone")["repeat_senders"]} == {"+919876501234"}
    assert st(kind="email")["risky_total"] == 1 and st(kind="sender-id")["risky_total"] == 1
    assert st(kind="none")["risky_total"] == 1 and st(kind="none")["repeat_senders"] == []
    assert st(category="KYC / account update")["risky_total"] == 2
    assert st(source="user")["risky_total"] == 5 and st(source="sms-app")["risky_total"] == 0
    assert st(sender="98765")["risky_total"] == 2 and st(sender="@sbi-kyc")["risky_total"] == 1
    assert st(sender="%")["risky_total"] == 0                      # % is a literal character, not a wildcard
    lvl = st()["filter_options"]["levels"][-1]
    assert all(m["level"] == lvl for m in st(level=lvl)["risky_messages"])
    combo = st(kind="phone", category="Utility bill scam")
    assert combo["risky_total"] == 1 and combo["repeat_senders"][0]["n"] == 1
    opts = st()["filter_options"]
    assert "KYC / account update" in opts["categories"] and opts["sources"] == ["user"]
    assert client.get("/api/stats", params={"kind": "fax"}).status_code == 422
    assert client.get("/api/stats", params={"level": "Safe"}).status_code == 422
