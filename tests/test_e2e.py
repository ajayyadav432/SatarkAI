"""End-to-end test in a real (headless) browser: analyse -> reasons -> history -> dashboard -> warning page.

Skipped automatically when Playwright or its Chromium is not installed:
    .venv/bin/python -m pip install playwright && .venv/bin/python -m playwright install chromium
"""
import os
import socket
import subprocess
import sys
import time
import json
import urllib.request
from pathlib import Path

import pytest

playwright_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed")
ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.e2e
ADMIN = ("e2e-admin", "e2e-admin-password")


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
        # The first account made on this computer is the admin.
        req = urllib.request.Request(base + "/api/auth/register", data=json.dumps(
            {"username": ADMIN[0], "password": ADMIN[1]}).encode(), headers={"Content-Type": "application/json"})
        assert json.load(urllib.request.urlopen(req))["user"]["role"] == "admin"
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


def _new_page(browser, server, login=True):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    if login:   # same cookie jar as the page
        assert ctx.request.post(server + "/api/auth/login", data={"username": ADMIN[0], "password": ADMIN[1]}).ok
    pg = ctx.new_page()
    pg.problems = []
    pg.on("console", lambda m: pg.problems.append(f"{m.type}: {m.text}") if m.type == "error" else None)
    pg.on("pageerror", lambda e: pg.problems.append(f"pageerror: {e}"))
    # Fail the test if the page tries to reach anything except our own server.
    pg.external = []
    pg.on("request", lambda r: pg.external.append(r.url) if not r.url.startswith(("http://127.0.0.1", "data:", "about:", "blob:")) else None)
    return ctx, pg


@pytest.fixture()
def page(browser, server):
    """Logged in as the admin (admin panel)."""
    ctx, pg = _new_page(browser, server)
    yield pg
    ctx.close()


@pytest.fixture()
def guest(browser, server):
    ctx, pg = _new_page(browser, server, login=False)
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
    assert ctx.request.post(server + "/api/auth/login", data={"username": ADMIN[0], "password": ADMIN[1]}).ok
    pg = ctx.new_page()
    pg.goto(server + "/")
    pg.click("text=PayPal e-mail")
    pg.wait_for_selector(".score-num")
    for hash_ in ("", "#feed", "#history", "#dashboard", "#admin", "#about"):
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


def test_guest_sees_no_admin_pages_and_must_log_in_to_post(guest, server):
    guest.goto(server + "/#feed")
    guest.wait_for_selector(".composer-guest")
    assert guest.locator(".tabs a[data-view=history]").is_hidden()
    assert guest.inner_text("#profile-name") == "Log in"
    guest.goto(server + "/#history")
    guest.wait_for_selector("#auth-dialog[open]")
    assert "admins" in guest.inner_text("#auth-why")
    assert not guest.locator("#view-history").is_visible()


def test_register_post_vote_comment_and_report(guest, server):
    """A new user on 'another device': registers, shares a scan from Analyze, votes and comments.
    Text typed by users is shown as text, never run as HTML."""
    pg = guest
    pg.goto(server + "/")
    pg.click("#profile-btn")
    pg.click("#profile-menu >> text=Register")
    pg.fill("#auth-user", "neha_k")
    pg.fill("#auth-pass", "neha-password-1")
    pg.click("#auth-submit")
    wait_until(pg, "document.querySelector('#profile-name').textContent === 'neha_k'")
    assert pg.inner_text("#profile-role") == "User"
    assert pg.locator(".tabs a[data-view=admin]").is_hidden()

    pg.click("text=Bank KYC (SMS)")
    pg.wait_for_selector("#result >> text=Share to Feed")
    pg.click("#result >> text=Share to Feed")
    pg.wait_for_selector("#composer .attached")
    evil = '<img src=x onerror="window.__xss=1">Fake SBI KYC'
    pg.fill("#post-title", evil)
    pg.fill("#post-body", "<script>window.__xss=2</script>Came at 9 pm")
    pg.click("#post-submit")
    pg.wait_for_selector("#feed-list .post")
    card = pg.locator("#feed-list .post").first
    assert card.locator(".post-title").inner_text() == evil
    assert "Critical" in card.locator(".post-scan").inner_text()
    assert "hxxp://sbi-kyc-update[.]xyz" in card.locator(".post-scan-text").inner_text()   # link in safe form
    assert pg.evaluate("window.__xss") is None and card.locator(".post-title img, .post-body script").count() == 0

    card.locator(".vote-btn.up").click()
    wait_until(pg, "document.querySelector('#feed-list .vote-score').textContent === '1'")
    card.locator("text=Comments").click()
    card.locator(".comment-form textarea").fill("My mother got the same one")
    card.locator(".comment-form button").click()
    wait_until(pg, "document.querySelectorAll('#feed-list .comment').length === 1")

    with pg.expect_download() as dl:
        card.locator("text=PDF report").click()
    assert dl.value.suggested_filename.endswith(".pdf")
    assert pg.problems == [] and pg.external == []


def test_admin_panel_switch_and_moderation(page, server):
    page.goto(server + "/#feed")
    page.wait_for_selector("#feed-list .post")
    assert page.locator(".tabs a[data-view=history]").is_visible()
    assert page.locator("#feed-list .post .mod-bar").count() >= 1
    page.locator("#feed-list .post .mod-bar >> text=Pin").first.click()
    page.wait_for_selector("#feed-list .post.pinned")
    page.click("#profile-btn")
    page.check("#profile-menu input[name=panel][value=user]")
    wait_until(page, "!document.querySelector('.tabs a[data-view=history]').offsetParent")
    assert page.locator("#feed-list .post .mod-bar").count() == 0
    page.click("#profile-btn")
    page.check("#profile-menu input[name=panel][value=admin]")
    page.goto(server + "/#admin")
    page.wait_for_selector("#users-table tbody tr")
    assert "neha_k" in page.inner_text("#users-table") or page.locator("#users-table tbody tr").count() >= 1
    assert page.problems == []
