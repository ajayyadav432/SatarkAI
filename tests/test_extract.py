"""Extraction of links, domains, phone numbers, UPI IDs, e-mail addresses and amounts."""
import pytest

from app.analysis.extract import defang, extract_entities, phone_kind, refang


def urls(text):
    return [u.url for u in extract_entities(text).urls]


def test_plain_url_with_trailing_punctuation():
    assert urls("Go to http://sbi-kyc-update.xyz/login now.") == ["http://sbi-kyc-update.xyz/login"]
    assert urls("(see https://example.com/a(1)).") == ["https://example.com/a(1)"]


def test_defanged_url_is_decoded():
    e = extract_entities("Visit hxxps://paypa1[.]com/verify today")
    assert e.urls[0].url == "https://paypa1.com/verify"
    assert e.urls[0].defanged is True
    assert refang("hxxp://evil[.]com") == "http://evil.com"


def test_defang_makes_a_link_unclickable():
    shown = defang("https://evil.example.com/a.b?c=d.e")
    assert shown == "hxxps://evil[.]example[.]com/a.b?c=d.e"
    assert "http" not in shown


def test_www_and_bare_domains():
    assert urls("open www.secure-login.top/a?b=1 please") == ["http://www.secure-login.top/a?b=1"]
    assert urls("offer at amaz0n-offers.in (limited)") == ["http://amaz0n-offers.in"]
    assert urls("join t.me/earnmoney or wa.me/919876543210") == ["http://t.me/earnmoney", "http://wa.me/919876543210"]
    assert urls("short bit.ly/3xYz") == ["http://bit.ly/3xYz"]


@pytest.mark.parametrize("text", [
    "No link here. Just text.Next sentence follows.",
    "Send me report.zip and setup.py",
    "I met my Wife.how are you",          # '.how' is a real TLD; sloppy typing is not a link
    "see you at home.love you",
    "ok.so what now",
    "Please come.in the evening",
    "Version 2.5 costs Rs.500",
])
def test_sloppy_typing_is_not_a_link(text):
    assert urls(text) == []


def test_ip_address_url():
    assert urls("apk at 192.168.1.10:8080/a.apk") == ["http://192.168.1.10:8080/a.apk"]
    assert urls("version 1.2.3.4567 released") == []


def test_unicode_and_punycode_hosts():
    assert urls("http://xn--pypal-4ve.com/x") == ["http://xn--pypal-4ve.com/x"]
    assert len(urls("लिंक: https://kyc-verify.co.in/update।")) == 1
    assert urls("लिंक: https://kyc-verify.co.in/update।")[0] == "https://kyc-verify.co.in/update"


def test_email_is_not_also_a_link_or_upi():
    e = extract_entities("Mail john.doe@example.com for help")
    assert e.emails == ["john.doe@example.com"]
    assert e.urls == [] and e.upi_ids == []


def test_upi_ids():
    e = extract_entities("Pay to scammer@ybl or 9876543210@paytm.")
    assert e.upi_ids == ["scammer@ybl", "9876543210@paytm"]
    assert e.emails == []


def test_phone_numbers():
    e = extract_entities("Call +91 98765 43210 or 1800-123-4567 or 08012345678")
    assert e.phones[0] == "+91 98765 43210"
    assert phone_kind(e.phones[0]) == "mobile"
    assert phone_kind("1800-123-4567") == "toll_free"
    assert phone_kind("9876543210") == "mobile"
    assert phone_kind("AD-HDFCBK") == "other"


def test_long_digit_strings_are_not_phones():
    assert extract_entities("Account 123456789012345 and PNR 2345678901").phones == []


def test_amounts():
    e = extract_entities("Pay Rs. 5,000 or ₹10 lakh, INR 2,499.00 and 500 rupees")
    assert e.amounts == ["Rs. 5,000", "₹10 lakh", "INR 2,499.00", "500 rupees"]


def test_html_in_message_does_not_break_extraction():
    e = extract_entities('<script>alert(1)</script> http://evil.com/<img src=x onerror=alert(1)>')
    assert e.urls[0].url == "http://evil.com/"


def test_many_urls_are_capped():
    text = " ".join(f"http://site{i}.example.com/a" for i in range(60))
    e = extract_entities(text)
    assert len(e.urls) == 25 and e.urls_truncated is True
