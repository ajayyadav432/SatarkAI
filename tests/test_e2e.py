"""End-to-end test in a real (headless) browser: analyse -> reasons -> history -> dashboard -> warning page.

Skipped automatically when Playwright or its Chromium is not installed:
    .venv/bin/python -m pip install playwright && .venv/bin/python -m playwright install chromium
"""
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

playwright_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed")
ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.e2e


def wait_until(page, expression: str, timeout: float = 8.0) -> None:
    """Poll a JavaScript expression until it is true.

    Playwright's built-in "wait for function" uses eval inside the page, which this app's
    Content-Security-Policy (correctly) blocks, so we poll from the outside instead.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if page.evaluate(expression):
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for: {expression}")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    port = _free_port()
    env = dict(os.environ, SATARK_DB=str(tmp_path_factory.mktemp("e2e") / "e2e.db"))
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/api/health", timeout=1).read()
                break
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError("server exited: " + proc.stdout.read().decode()[-2000:])
                time.sleep(0.2)
        else:
            raise RuntimeError("server did not start")
        yield base
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # browser binary missing
            pytest.skip(f"Chromium could not start: {str(exc)[:120]}")
        yield b
        b.close()


@pytest.fixture()
def page(browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    pg.problems = []
    pg.on("console", lambda m: pg.problems.append(f"{m.type}: {m.text}") if m.type == "error" else None)
    pg.on("pageerror", lambda e: pg.problems.append(f"pageerror: {e}"))
    # Fail the test if the page tries to reach anything except our own server.
    pg.external = []
    pg.on("request", lambda r: pg.external.append(r.url) if not r.url.startswith(("http://127.0.0.1", "data:", "about:")) else None)
    yield pg
    ctx.close()


def test_analyse_shows_level_reasons_and_safe_link(page, server):
    page.goto(server + "/")
    page.click("text=Bank KYC (SMS)")
    page.wait_for_selector(".score-num")
    assert int(page.inner_text(".score-num")) >= 80
    assert "Critical" in page.inner_text(".verdict-meta")
    assert page.locator(".factor").count() >= 4
    assert "State Bank of India" in page.inner_text("#result")
    assert page.inner_text(".url-text") == "hxxp://sbi-kyc-update[.]xyz/login"
    # The scam link is never a direct clickable link; opening goes through the warning page.
    hrefs = page.eval_on_selector_all("#result a", "els => els.map(e => e.getAttribute('href'))")
    assert hrefs and all(h.startswith("/go?u=") for h in hrefs)
    assert page.locator(".message mark.hl-rule").count() >= 2 and page.locator(".message mark.hl-url").count() == 1
    assert page.problems == [] and page.external == []


def test_critical_result_offers_report_with_complaint_text(page, server):
    page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=server)
    page.context.route("https://cybercrime.gov.in/**", lambda route: route.fulfill(body="portal"))  # stay offline
    page.goto(server + "/")
    page.click("text=Bank KYC (SMS)")
    page.wait_for_selector(".report-banner")
    with page.context.expect_page() as portal:
        page.click("text=Report on cybercrime.gov.in")
    assert portal.value.url.startswith("https://cybercrime.gov.in")
    portal.value.close()
    text = page.evaluate("navigator.clipboard.readText()")
    assert text.startswith("Suspected fraud message (checked with SatarkAI: Critical")
    assert "Update your KYC" in text and "hxxp://sbi-kyc-update[.]xyz/login" in text
    assert "Call 1930" in page.inner_text(".report-banner")
    # Only Critical results get the banner.
    page.click("text=Real OTP")
    wait_until(page, "!document.querySelector('.report-banner')")


def test_typed_message_with_html_is_shown_as_text(page, server):
    page.goto(server + "/")
    evil = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script> Dear customer update KYC'
    page.fill("#text", evil)
    page.fill("#sender", '"><svg onload="window.__xss=3">')
    page.click("#analyze-btn")
    page.wait_for_selector(".score-num")
    assert page.evaluate("window.__xss") is None
    assert page.inner_text(".message") == evil
    assert page.locator(".message img, .message script, #result svg[onload]").count() == 0
    page.goto(server + "/#history")
    page.wait_for_selector("#history-table tbody tr.clickable")
    assert page.evaluate("window.__xss") is None
    page.click("#history-table tbody tr.clickable")
    page.wait_for_selector("dialog[open] .message")
    assert page.evaluate("window.__xss") is None
    assert page.problems == []


def test_safe_message(page, server):
    page.goto(server + "/")
    page.click("text=Real OTP")
    page.wait_for_selector(".score-num")
    assert page.inner_text(".score-num") == "0" and "Safe" in page.inner_text(".verdict-meta")
    assert "routine" in page.inner_text("#result")


def test_history_search_review_and_dashboard(page, server):
    page.goto(server + "/")
    for sample in ("Electricity bill", "KBC lottery", "Normal chat"):
        page.click(f"text={sample}")
        wait_until(page, "document.querySelector('#analyze-btn').textContent === 'Analyze'")
        page.wait_for_selector(".score-num")
    page.click("nav >> text=History")
    page.wait_for_selector("#history-table tbody tr.clickable")
    total = page.locator("#history-table tbody tr.clickable").count()
    assert total >= 3
    page.fill("#f-q", "electricity")
    wait_until(page, "document.querySelectorAll('#history-table tbody tr.clickable').length === 1")
    assert "electricity" in page.inner_text("#history-table tbody").lower()
    page.click("#history-table tbody tr.clickable")
    page.wait_for_selector("dialog[open] #case-status")
    assert "Utility bill scam" in page.inner_text("#case-body")
    page.select_option("#case-status", "confirmed_scam")
    page.fill("#case-notes", "reported to the electricity board")
    page.click("dialog[open] >> text=Save")
    wait_until(page, "document.querySelector('#toast').textContent.includes('updated')")
    page.click("#case-close")
    page.fill("#f-q", "reported")
    wait_until(page, "document.querySelectorAll('#history-table tbody tr.clickable').length === 1")
    assert "Confirmed scam" in page.inner_text("#history-table tbody")
    page.fill("#f-q", "zzzznothing")
    page.wait_for_selector("#history-table tbody tr.empty-row")

    page.click("nav >> text=Dashboard")
    page.wait_for_selector(".kpis")
    assert int(page.inner_text(".kpi.hero .value")) >= 3
    assert page.locator("canvas").count() == 1 and page.locator(".barlist .row").count() >= 5
    assert "Utility bill scam" in page.inner_text("#dashboard-body")
    assert page.problems == [] and page.external == []


def test_how_it_works_page_shows_measured_numbers(page, server):
    page.goto(server + "/#about")
    page.wait_for_selector(".about .card")
    text = page.inner_text("#about-body")
    assert "How the score is calculated" in text and "Known limits" in text
    if page.locator(".metric-grid").count():           # models are trained
        assert "Accuracy" in text and "OpenPhish" in text
    assert page.problems == []


def test_warning_page_blocks_until_confirmed(page, server):
    page.goto(server + "/go?u=http%3A%2F%2Fsbi-kyc-update.xyz%2Flogin")
    page.wait_for_selector("#go-confirm")
    assert "Danger" in page.inner_text("#go-title") or "Warning" in page.inner_text("#go-title")
    link = page.locator("#go-actions a", has_text="Open the link anyway")
    assert link.get_attribute("aria-disabled") == "true"
    assert link.get_attribute("rel") == "noopener noreferrer nofollow"
    link.click(force=True)                              # a click while disabled must not navigate
    assert "/go?u=" in page.url
    page.check("#go-confirm")
    assert link.get_attribute("aria-disabled") == "true"            # still waiting for the countdown
    wait_until(page, "document.querySelector('#go-actions a[rel]').getAttribute('aria-disabled') === null", timeout=9.0)
    assert link.get_attribute("href") == "http://sbi-kyc-update.xyz/login"
    assert page.external == []                          # the scam site was never contacted


def test_warning_page_for_official_and_invalid_links(page, server):
    page.goto(server + "/go?u=https%3A%2F%2Fwww.irctc.co.in%2F")
    page.wait_for_selector("#go-actions a")
    assert "No problems found" in page.inner_text("#go-title")
    assert page.locator("#go-confirm").count() == 0
    page.goto(server + "/go?u=javascript%3Aalert(1)")
    wait_until(page, "document.querySelector('#go-title').textContent.includes('cannot be checked')")
    assert page.locator("#go-actions a[rel]").count() == 0
    page.goto(server + "/go")
    wait_until(page, "document.querySelector('#go-title').textContent.includes('cannot be checked')")


def test_phone_width_has_no_sideways_scroll(browser, server):
    ctx = browser.new_context(viewport={"width": 390, "height": 800})
    pg = ctx.new_page()
    pg.goto(server + "/")
    pg.click("text=PayPal e-mail")
    pg.wait_for_selector(".score-num")
    for hash_ in ("", "#history", "#dashboard", "#about"):
        pg.goto(server + "/" + hash_)
        pg.wait_for_timeout(400)
        assert pg.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), hash_
    ctx.close()


def test_dark_theme_toggle_is_remembered(page, server):
    page.goto(server + "/")
    page.wait_for_selector("#sample-list .chip")
    before = page.evaluate("getComputedStyle(document.body).backgroundColor")
    page.click("#theme-toggle")
    after = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert before != after and page.evaluate("document.documentElement.dataset.theme") == "dark"
    page.reload()
    assert page.evaluate("document.documentElement.dataset.theme") == "dark"
