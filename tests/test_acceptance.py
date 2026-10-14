"""One end-to-end test per requirement of problem statement SKIT025, through the HTTP API.

The requirement text in each docstring is copied from the problem statement PDF.
"""
from tests.conftest import OK_CHAT, OK_OTP, SCAM_ARREST, SCAM_BILL, SCAM_HINDI, SCAM_KYC, SCAM_LOTTERY


def post(client, text, **kw):
    r = client.post("/api/analyze", json={"text": text, **kw})
    assert r.status_code == 200, r.text
    return r.json()


def test_R1_analyze_message_text_and_urls(client):
    """Analyze message text and URLs."""
    r = post(client, SCAM_KYC)
    sources = {f["source"] for f in r["factors"]}
    assert "rule" in sources                      # the text was analysed
    assert sources & {"url-check", "ml-url"}      # the URL was analysed
    assert r["urls"][0]["registered_domain"] == "sbi-kyc-update.xyz"
    # e-mail, SMS, social-media message and a bare URL are all accepted
    for channel in ("sms", "email", "social", "url"):
        assert post(client, "http://sbi-kyc-update.xyz/login", channel=channel, save=False)["channel"] == channel


def test_R2_identify_suspicious_linguistic_patterns(client):
    """Identify suspicious linguistic patterns."""
    r = post(client, SCAM_LOTTERY)
    groups = {f["id"] for f in r["factors"] if f["source"] == "rule"}
    assert {"rule_reward", "rule_payment_request"} <= groups
    reward = next(f for f in r["factors"] if f["id"] == "rule_reward")
    assert "Congratulations" in reward["evidence"]              # the exact words are reported
    assert any(h["kind"] == "rule" for h in r["highlights"])    # and marked in the message
    # Hindi works too
    hindi = {f["id"] for f in post(client, SCAM_HINDI)["factors"]}
    assert {"rule_kyc", "rule_threat", "rule_urgency"} <= hindi
    assert post(client, OK_CHAT)["factors"] == []


def test_R3_extract_and_analyze_urls_domains_and_metadata(client):
    """Extract and analyze URLs, domains and relevant metadata."""
    text = ("Verify at hxxps://secure-login.paypal[.]com.account-verify.top:8443/signin?id=7 or bit.ly/x1 "
            "mail help@pay-secure.in call +91 98765 43210 pay Rs 4,999 to refund@ybl")
    r = post(client, text)
    e = r["entities"]
    assert e["domains"] == ["account-verify.top", "bit.ly"]
    assert e["emails"] == ["help@pay-secure.in"] and e["upi_ids"] == ["refund@ybl"]
    assert e["phones"] == ["+91 98765 43210"] and e["amounts"] == ["Rs 4,999"]
    u = r["urls"][0]
    assert u["was_defanged"] and u["scheme"] == "https" and u["port"] == 8443
    assert u["registered_domain"] == "account-verify.top" and u["suffix"] == "top"
    assert u["subdomain"] == "secure-login.paypal.com" and u["query"] == "id=7"
    assert u["ml"]["used"] and len(u["ml"]["all_points"]) > 20        # lexical metadata behind the score
    assert r["urls"][1]["is_shortener"] is True


def test_R4_detect_impersonation_and_urgency_patterns(client):
    """Detect impersonation and urgency-based scam patterns."""
    r = post(client, SCAM_KYC, sender="9876501234")
    ids = {f["id"] for f in r["factors"]}
    assert "url_brand_in_host" in ids             # SBI name on a domain SBI does not own
    assert "sender_personal_number" in ids        # "SBI" writing from a private mobile number
    assert "rule_urgency" in ids and "rule_threat" in ids
    assert r["brands"] == ["State Bank of India"]
    look = post(client, "Your PayPal account is limited: https://paypa1.com/signin")
    assert any(f["id"] == "url_lookalike" and "PayPal" in f["title"] for f in look["factors"])
    # the real bank domain is not called impersonation
    real = post(client, "SBI: view your statement at https://www.onlinesbi.sbi/retail/login.htm")
    assert not any("brand" in f["id"] or "lookalike" in f["id"] for f in real["factors"])


def test_R5_classify_messages_by_risk_level(client):
    """Classify messages according to risk level."""
    levels = ["Safe", "Low", "Medium", "High", "Critical"]
    safe, low, crit = post(client, OK_OTP), post(client, "Call 9876543210 for the notes, urgent"), post(client, SCAM_KYC)
    assert safe["level"] == "Safe" and safe["score"] < 20
    assert low["level"] in ("Low", "Medium") and 20 <= low["score"] < 60
    assert crit["level"] == "Critical" and crit["score"] >= 80
    for r in (safe, low, crit, post(client, SCAM_BILL), post(client, SCAM_ARREST)):
        assert r["level"] in levels and 0 <= r["score"] <= 100
        lowest = {"Safe": 0, "Low": 20, "Medium": 40, "High": 60, "Critical": 80}[r["level"]]
        assert lowest <= r["score"] < lowest + 21
    assert post(client, SCAM_BILL)["category"] == "Utility bill scam"
    assert post(client, SCAM_ARREST)["category"] == "Authority impersonation / digital arrest"


def test_R6_explain_the_contributing_factors(client):
    """Explain the factors contributing to the risk classification."""
    r = post(client, SCAM_KYC)
    assert len(r["factors"]) >= 4
    remaining = 1.0
    for f in r["factors"]:
        assert f["title"] and f["detail"] and f["evidence"] is not None and f["points"] > 0
        remaining *= 1 - f["weight"]
    assert r["score"] == r["score_uncapped"] == round(100 * (1 - remaining))   # the shown weights reproduce the score
    assert "1 - (1 - w1)" in r["formula"] and r["summary"] and r["advice"]
    # a Safe verdict is explained as well
    otp = post(client, OK_OTP)
    assert otp["level"] == "Safe" and otp["notes"]


def test_R7_warn_before_interacting_with_suspicious_content(client):
    """Provide warnings before users interact with suspicious content."""
    r = post(client, SCAM_KYC)
    u = r["urls"][0]
    assert u["display"] == "hxxp://sbi-kyc-update[.]xyz/login"   # shown in a form that cannot be clicked
    assert "http://" not in u["display"]
    assert client.get("/go", params={"u": u["url"]}).status_code == 200          # the warning page exists
    check = client.get("/api/check-url", params={"u": u["url"]}).json()
    assert check["needs_warning"] is True and check["factors"]                   # and it carries the reasons
    assert client.get("/api/check-url", params={"u": "https://www.irctc.co.in/"}).json()["needs_warning"] is False
    page = client.get("/static/go.js").text
    assert "I understand the risk" in page and "aria-disabled" in page           # opening needs confirmation
    assert any("Do not" in a for a in r["advice"])


def test_R8_searchable_history(client):
    """Maintain a searchable history of analyzed cases."""
    a = post(client, SCAM_KYC)["case_id"]
    b = post(client, SCAM_BILL)["case_id"]
    c = post(client, OK_CHAT)["case_id"]
    listing = client.get("/api/cases").json()
    assert listing["total"] == 3 and [x["id"] for x in listing["items"]] == [c, b, a]
    search = lambda **p: [x["id"] for x in client.get("/api/cases", params=p).json()["items"]]
    assert search(q="electricity") == [b] and search(q="sbi-kyc-update.xyz") == [a] and search(q="9876543210") == [b]
    assert search(level="Safe") == [c] and search(category="Utility bill scam") == [b]
    full = client.get(f"/api/cases/{a}").json()
    assert full["result"]["factors"] and full["text"] == SCAM_KYC                # the whole analysis is kept
    client.patch(f"/api/cases/{a}", json={"status": "confirmed_scam", "notes": "forwarded to bank"})
    assert search(status="confirmed_scam") == [a] and search(q="forwarded") == [a]
    assert client.get("/api/cases/export.csv").text.count("\n") >= 4


def test_R9_dashboard_for_security_analysis(client):
    """Provide a dashboard for security analysis."""
    for text in (SCAM_KYC, SCAM_KYC, SCAM_BILL, SCAM_LOTTERY, OK_CHAT, OK_OTP):
        post(client, text)
    s = client.get("/api/stats", params={"days": 30}).json()
    assert s["kpis"]["total"] == 6 and s["kpis"]["high_risk"] == 4 and s["kpis"]["high_risk_share"] == 66.7
    assert {l["level"]: l["n"] for l in s["levels"]}["Safe"] == 2
    assert len(s["trend"]["days"]) == 30 and sum(s["trend"]["series"]["Critical"]) + sum(s["trend"]["series"]["High"]) == 4
    assert s["categories"][0]["category"] == "KYC / account update" and s["categories"][0]["n"] == 2
    assert s["factors"] and s["brands"] and s["domains"] and s["channels"] and s["recent_high_risk"]
    assert client.get("/").status_code == 200 and "view-dashboard" in client.get("/").text
