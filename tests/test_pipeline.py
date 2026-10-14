"""The full pipeline on hand-written scam and genuine messages."""
import pytest

from app.analysis.pipeline import analyze, analyze_url, detect_channel
from app.analysis.extract import extract_entities
from tests.conftest import (OK_CHAT, OK_DEBIT, OK_ORDER, OK_OTP, SCAM_ARREST, SCAM_BILL, SCAM_HINDI, SCAM_HINGLISH,
                            SCAM_KYC, SCAM_LOTTERY)

SCAMS = {
    "kyc": (SCAM_KYC, "KYC / account update"),
    "bill": (SCAM_BILL, "Utility bill scam"),
    "lottery": (SCAM_LOTTERY, "Lottery / prize scam"),
    "digital arrest": (SCAM_ARREST, "Authority impersonation / digital arrest"),
    "hinglish": (SCAM_HINGLISH, "KYC / account update"),
    "hindi": (SCAM_HINDI, "KYC / account update"),
    "courier": ("India Post: Your parcel could not be delivered due to incomplete address. Update your address within "
                "12 hours: https://indiapost-redelivery.top/track", "Courier / delivery scam"),
    "job": ("Hi, I am HR from Amazon. Part time job, work from home. Earn Rs 3000-8000 per day by liking YouTube videos. "
            "No experience needed. Contact on WhatsApp: wa.me/919812345678", "Job / task scam"),
    "mum": ("Hi mum, this is my new number. My phone is broken. Can you send me 15000 urgently? I will return it tomorrow.",
            "Impersonation of a known person"),
    "remote": ("Microsoft support: virus detected on your computer. Install AnyDesk and call tech support now.",
               "Tech support / remote access scam"),
}

GENUINE = {
    "otp": OK_OTP, "debit": OK_DEBIT, "chat": OK_CHAT, "order": OK_ORDER,
    "hinglish chat": "bhai kal college aa raha hai kya, assignment submit karna hai mujhe bhi bata dena",
    "irctc": "PNR 2345678901, Train 12951, 14-Oct, JP-BCT, B2 34. Chart prepared. Check status at https://www.irctc.co.in",
    "news": "Check this article https://www.thehindu.com/sci-tech/technology/ and https://en.wikipedia.org/wiki/Phishing",
    "mail": "Subject: Project review meeting\n\nHi team,\n\nPlease find attached the agenda for tomorrow's project "
            "review. We will meet at 10 am in the seminar hall.\n\nThanks,\nRahul",
    "bank promo": "Dear Customer, get up to 10% cashback on your HDFC Bank Credit Card at Flipkart. T&C apply. https://www.hdfcbank.com/offers",
}


@pytest.mark.parametrize("name", SCAMS)
def test_scam_examples_are_high_or_critical(name):
    text, category = SCAMS[name]
    r = analyze(text)
    assert r["level"] in ("High", "Critical"), (name, r["score"])
    assert r["category"] == category
    assert r["factors"] and r["advice"]


@pytest.mark.parametrize("name", GENUINE)
def test_genuine_examples_are_safe(name):
    r = analyze(GENUINE[name])
    assert r["level"] == "Safe", (name, r["score"], [f["id"] for f in r["factors"]])


def test_result_shape_and_arithmetic():
    r = analyze(SCAM_KYC, sender="9876501234")
    remaining = 1.0
    for f in r["factors"]:
        assert 0 < f["weight"] <= 1 and f["points"] == round(f["weight"] * 100)
        assert f["title"] and f["detail"] and f["source"]
        remaining *= 1 - f["weight"]
    assert r["score_uncapped"] == round(100 * (1 - remaining)) and r["cap_applied"] is False
    assert r["score"] == r["score_uncapped"]
    assert [f["weight"] for f in r["factors"]] == sorted((f["weight"] for f in r["factors"]), reverse=True)
    assert len({f["id"] for f in r["factors"]}) == len(r["factors"])


def test_highlights_point_at_real_text_and_do_not_overlap():
    r = analyze(SCAM_KYC)
    spans = [(h["start"], h["end"]) for h in r["highlights"]]
    assert spans == sorted(spans)
    for (s1, e1), (s2, _) in zip(spans, spans[1:]):
        assert e1 <= s2
    kinds = {h["kind"] for h in r["highlights"]}
    assert {"url", "rule", "brand"} <= kinds
    url_hl = next(h for h in r["highlights"] if h["kind"] == "url")
    assert r["text"][url_hl["start"]:url_hl["end"]] == "http://sbi-kyc-update.xyz/login"


def test_rules_do_not_match_inside_links():
    r = analyze("see http://kyc-urgent-lottery-winner.example.org/otp")
    assert not any(f["source"] == "rule" for f in r["factors"])


def test_sender_checks():
    free = analyze("Your SBI account needs attention", sender="sbi.helpdesk@gmail.com")
    assert any(f["id"] == "sender_free_mail" for f in free["factors"])
    fake = analyze("Your account has been limited", sender="PayPal <service@paypa1-secure.com>")
    assert any(f["id"] == "sender_lookalike" for f in fake["factors"])
    phone = analyze("Dear SBI customer, please update details", sender="9876501234")
    assert any(f["id"] == "sender_personal_number" for f in phone["factors"])
    real = analyze("Your statement is ready", sender="alerts@hdfcbank.com")
    assert not any(f["source"] == "sender" for f in real["factors"])
    sender_id = analyze(OK_OTP, sender="AD-HDFCBK")
    assert sender_id["level"] == "Safe"


def test_fake_debit_alert_with_a_mobile_number_is_not_treated_as_routine():
    fake = "Rs 49,999 debited from A/c XX1234. If not done by you call SBI customer care 9876543210 immediately"
    r = analyze(fake)
    assert r["level"] in ("Medium", "High", "Critical")
    assert any(f["id"] == "personal_number_callback" for f in r["factors"])


def test_text_model_skip_reasons_are_reported():
    hindi = analyze(SCAM_HINDI)
    assert hindi["ml_text"]["used"] is False and "words are known" in hindi["ml_text"]["reason"]
    otp = analyze(OK_OTP)
    assert otp["ml_text"].get("standard_alert") == "otp"
    assert any("routine" in n["title"] for n in otp["notes"])


def test_channel_detection_and_override():
    assert analyze("https://example.com/a")["channel"] == "url"
    assert analyze(GENUINE["mail"])["channel"] == "email"
    assert analyze(OK_CHAT)["channel"] == "sms" and analyze(OK_CHAT)["channel_detected"] is True
    forced = analyze(OK_CHAT, channel="email")
    assert forced["channel"] == "email" and forced["channel_detected"] is False
    assert detect_channel("Dear customer, pay now", extract_entities("Dear customer, pay now")) == "sms"


def test_defanged_link_is_analysed_and_reported():
    r = analyze("Your Netflix payment failed. Update billing at hxxps://netflix-billing[.]support/account now")
    assert r["urls"][0]["url"] == "https://netflix-billing.support/account" and r["urls"][0]["was_defanged"]
    assert any(n["title"] == "Disguised link was decoded" for n in r["notes"])
    assert r["level"] in ("High", "Critical")


def test_single_url_analysis():
    bad = analyze_url("https://secure-login.paypal.com.account-verify.top/signin")
    assert bad["level"] in ("High", "Critical") and bad["display"].startswith("hxxps://")
    good = analyze_url("https://www.onlinesbi.sbi/retail/login.htm")
    assert good["score"] == 0 and good["trusted"] and good["notes"]
    junk = analyze_url("https://")
    assert junk["valid"] is False and junk["score"] == 0


def test_same_trick_in_many_links_counts_once():
    one = analyze("http://sbi-kyc-update.xyz/a")
    many = analyze("http://sbi-kyc-update.xyz/a http://sbi-kyc-update.xyz/b http://sbi-kyc-update.xyz/c")
    assert len(many["urls"]) == 3
    assert many["score"] <= one["score"] + 3


def test_empty_and_whitespace_messages():
    for text in ("", "   ", "\n\n"):
        r = analyze(text)
        assert r["score"] == 0 and r["level"] == "Safe"


def test_weak_signals_plus_model_opinion_stop_at_medium():
    r = analyze("Call 9876543210 for the notes, urgent")
    assert r["level"] in ("Low", "Medium") and r["score"] <= 59
    if r["cap_applied"]:
        assert r["score_uncapped"] > 59 and any("limited" in n["title"] for n in r["notes"])
