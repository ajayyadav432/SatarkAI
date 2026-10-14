"""URL parsing, link heuristics, brand impersonation and lookalike detection."""
import pytest

from app.analysis import brands
from app.analysis.url_features import heuristic_findings, parse_url


def ids(url, **kw):
    return {f["id"] for f in heuristic_findings(parse_url(url), **kw)}


def test_parse_parts():
    i = parse_url("https://www.shop.example.co.in:8443/a/b.php?x=1&y=2")
    assert (i.scheme, i.host, i.port) == ("https", "www.shop.example.co.in", 8443)
    assert i.registered_domain == "example.co.in" and i.suffix == "co.in" and i.subdomain == "shop"
    assert i.features["n_params"] == 2 and i.features["path_depth"] == 2


@pytest.mark.parametrize("url", ["https://", "http://foo..bar", "http://.com", "not a url at all"])
def test_invalid_urls_do_not_crash(url):
    i = parse_url(url)
    assert i.valid is False or i.host
    assert heuristic_findings(i) == [] or isinstance(heuristic_findings(i), list)


def test_ip_host_port_and_apk():
    assert {"url_ip_host", "url_port", "url_download"} <= ids("http://192.168.1.10:8080/a.apk")


def test_at_sign_hides_destination():
    i = parse_url("https://www.google.com@evil.example.net/x")
    assert i.host == "evil.example.net"
    assert "url_userinfo" in ids("https://www.google.com@evil.example.net/x")


@pytest.mark.parametrize("url,brand", [
    ("https://paypa1.com/verify", "PayPal"),
    ("https://rnicrosoft.com/", "Microsoft"),
    ("https://amaz0n-offers.in", "Amazon"),
    ("https://hdfcbankk.in/rewards", "HDFC Bank"),
    ("https://secure.1cicibank.co/update", "ICICI Bank"),
    ("https://faceb00k.com/login", "Facebook"),
])
def test_lookalike_domains(url, brand):
    found = [f for f in heuristic_findings(parse_url(url)) if f["id"] == "url_lookalike"]
    assert found and brand in found[0]["title"]


@pytest.mark.parametrize("url,brand", [
    ("http://sbi-kyc-update.xyz/login", "State Bank of India"),
    ("https://paypal.com.account-verify.top/signin", "PayPal"),
    ("https://jiooffer.site/recharge", "Jio"),
    ("http://echallan-parivahan.in/mParivahan.apk", "Parivahan"),
    ("https://indiapost-redelivery.top/track", "India Post"),
])
def test_brand_name_on_foreign_domain(url, brand):
    found = [f for f in heuristic_findings(parse_url(url)) if f["id"] == "url_brand_in_host"]
    assert found and brand in found[0]["title"]


def test_deceptive_subdomain():
    assert "url_deceptive_subdomain" in ids("https://paypal.com.account-verify.top/signin")


def test_brand_only_in_path_is_weaker():
    f = {x["id"]: x for x in heuristic_findings(parse_url("https://my-site.github.io/sbi/login.html"))}
    assert "url_brand_in_path" in f and "url_user_content" in f
    assert f["url_brand_in_path"]["weight"] < 0.6


@pytest.mark.parametrize("url", [
    "https://www.onlinesbi.sbi/retail/login.htm",
    "https://www.hdfcbank.com/personal/pay/cards",
    "https://incometax.gov.in/iec/foportal/",
    "https://www.irctc.co.in/nget/train-search",
    "https://www.amazon.in/gp/your-account/order-details",
    "https://uidai.gov.in/en/my-aadhaar/update-aadhaar.html",
    "https://www.skit.ac.in/",
    "https://sbi.bank.in/",          # restricted registry (bank.in)
])
def test_official_domains_are_trusted_and_not_flagged(url):
    i = parse_url(url)
    assert i.trusted is True
    assert heuristic_findings(i) == []


@pytest.mark.parametrize("url", [
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com/scikit-learn/scikit-learn",
    "https://www.thehindu.com/sci-tech/technology/",
    "https://www.video-site.com/watch",                # 'vi' inside 'video' is not Vodafone Idea
    "https://www.sbisolutions-consulting.com/",        # 'sbi' inside a longer word is not SBI
    "https://www.pineapple-farm.org/",                 # 'apple' is not on the list as a bare word
])
def test_ordinary_sites_have_no_impersonation_finding(url):
    found = ids(url)
    assert not found & {"url_lookalike", "url_brand_in_host", "url_brand_in_path"}


def test_shortener_messaging_and_platform():
    assert ids("https://bit.ly/3xYz") == {"url_shortener"}
    assert ids("https://t.me/earnmoney") == {"url_messaging"}
    assert "url_user_content" in ids("https://docs.google.com/forms/d/e/abc/viewform")
    # Content platforms are not "official" even though the company owns the domain.
    assert parse_url("https://docs.google.com/forms/d/e/abc").trusted is False


def test_idn_and_mixed_script():
    assert "url_mixed_script" in ids("https://раураl.com/login")       # Cyrillic letters + Latin l
    assert "url_mixed_script" in ids("http://xn--pypal-4ve.com")


def test_redirect_parameter_and_plain_http():
    assert "url_redirect" in ids("https://example.com/go?url=https://evil.com")
    assert "url_no_https" in ids("http://secure-login-update.com/verify")
    # A bare domain typed without http:// is not blamed for "no https".
    assert "url_no_https" not in ids("http://secure-login-update.com/verify", had_scheme=False)


def test_brand_helpers():
    assert brands.official_brand("paypal.com") == "PayPal"
    assert brands.official_brand("paypa1.com") is None
    assert brands.is_restricted("something.gov.in") and not brands.is_restricted("gov.in.evil.com")
    names = [b["brand"] for b in brands.brands_in_text("Dear SBI user, your HDFC bank and Paytm KYC")]
    assert names == ["State Bank of India", "HDFC Bank", "Paytm"]
    assert brands.brands_in_text("I ate an apple while watching a video") == []
    assert brands.skeletons("paypa1") >= {"paypal"}
