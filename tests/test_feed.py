"""Accounts, the community feed (posts, votes, comments, screenshots, moderation) and PDF reports."""
import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app import accounts, config, db
from app.main import app
from tests.conftest import ADMIN, OK_CHAT, SCAM_HINDI, SCAM_KYC


def user_client(name: str, password: str = "user-password-1") -> TestClient:
    """A second browser: registers from 'another device' (always a plain user) and stays logged in."""
    c = TestClient(app)
    r = c.post("/api/auth/register", json={"username": name, "password": password})
    assert r.status_code == 200, r.text
    return c


def png(size=(40, 30), exif=False) -> bytes:
    img = Image.new("RGB", size, (200, 30, 30))
    out = io.BytesIO()
    if exif:
        e = Image.Exif()
        e[0x010F] = "SecretPhoneMaker"           # camera make
        img.save(out, "JPEG", exif=e)
    else:
        img.save(out, "PNG")
    return out.getvalue()


def post(c, title="Fake SBI KYC SMS", body="Got this today, be careful", scan_text=SCAM_KYC, **extra):
    data = {"title": title, "body": body, "scan_text": scan_text, **extra.pop("data", {})}
    return c.post("/api/feed", data=data, **extra)


# --- accounts -------------------------------------------------------------------

def test_first_account_on_the_laptop_is_admin_others_are_users(fresh_db):
    assert accounts.register("owner", "password-123", local=True)["role"] == "admin"
    assert accounts.register("second", "password-123", local=True)["role"] == "user"


def test_network_registration_never_becomes_admin(anon):
    """Even on an empty server, an account made from another device is a plain user."""
    r = anon.post("/api/auth/register", json={"username": "stranger", "password": "password-123"})
    assert r.status_code == 200 and r.json()["user"]["role"] == "user"
    assert anon.get("/api/auth/me").json()["user"]["username"] == "stranger"
    assert anon.get("/api/cases").status_code == 403


@pytest.mark.parametrize("username,password,msg", [
    ("ab", "password-123", "Username"), ("bad name", "password-123", "Username"), ("<script>", "password-123", "Username"),
    ("goodname", "short", "Password"),
])
def test_register_validation(anon, username, password, msg):
    r = anon.post("/api/auth/register", json={"username": username, "password": password})
    assert r.status_code == 400 and msg in r.json()["detail"]


def test_username_taken_any_case(anon):
    user_client("Priya")
    r = anon.post("/api/auth/register", json={"username": "priya", "password": "password-123"})
    assert r.status_code == 400 and "taken" in r.json()["detail"]


def test_password_is_hashed_and_login_logout(anon):
    user_client("ravi", "ravi-password-9")
    with db.connect() as con:
        stored = con.execute("SELECT password_hash FROM users WHERE username = 'ravi'").fetchone()[0]
    assert "ravi-password-9" not in stored and stored.startswith("scrypt$")
    assert anon.post("/api/auth/login", json={"username": "ravi", "password": "wrong-password"}).status_code == 400
    assert anon.post("/api/auth/login", json={"username": "ravi", "password": "ravi-password-9"}).status_code == 200
    assert anon.get("/api/auth/me").json()["user"]["username"] == "ravi"
    anon.post("/api/auth/logout")
    assert anon.get("/api/auth/me").json()["user"] is None


def test_session_cookie_is_httponly(anon):
    r = anon.post("/api/auth/register", json={"username": "cookieuser", "password": "password-123"})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie


def test_too_many_wrong_passwords_pause_login(anon, monkeypatch):
    monkeypatch.setattr(accounts, "_fails", {})
    user_client("target")
    for _ in range(8):
        anon.post("/api/auth/login", json={"username": "target", "password": "nope-nope"})
    r = anon.post("/api/auth/login", json={"username": "target", "password": "user-password-1"})
    assert r.status_code == 400 and "Too many" in r.json()["detail"]


def test_other_website_cannot_use_the_login(client):
    r = client.post("/api/feed", data={"title": "x"}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


# --- feed -----------------------------------------------------------------------

def test_anyone_reads_the_feed_but_must_log_in_to_post(anon, client):
    assert post(anon).status_code == 401
    r = post(client)
    assert r.status_code == 200
    p = r.json()
    assert p["author"] == ADMIN[0] and p["scan"]["level"] == "Critical" and p["scan"]["score"] >= 80
    feed = anon.get("/api/feed").json()
    assert feed["total"] == 1 and feed["posts"][0]["title"] == "Fake SBI KYC SMS"
    assert feed["posts"][0]["can_delete"] is False


def test_scan_result_is_computed_by_the_server(client):
    """A browser cannot make a scam look safe: extra fields are ignored and the server analyses the text."""
    p = post(client, data={"scan_level": "Safe", "scan_score": "0"}).json()
    assert p["scan"]["level"] == "Critical"
    plain = post(client, title="Just a warning", scan_text="").json()
    assert plain["scan"] is None


def test_post_text_is_stored_as_written(client):
    p = post(client, title="<img src=x onerror=alert(1)>", body="<script>alert(2)</script>", scan_text="").json()
    assert p["title"] == "<img src=x onerror=alert(1)>"   # the web page shows it as text (see test_e2e)


def test_votes_and_top_sort(client):
    a = post(client, title="A", scan_text="").json()["id"]
    b = post(client, title="B", scan_text="").json()["id"]
    u1, u2 = user_client("user1"), user_client("user2")
    assert u1.post(f"/api/feed/{b}/vote", json={"value": 1}).json()["score"] == 1
    assert u2.post(f"/api/feed/{b}/vote", json={"value": 1}).json()["score"] == 2
    assert u2.post(f"/api/feed/{b}/vote", json={"value": -1}).json()["score"] == 0      # changed, not added
    assert u2.post(f"/api/feed/{b}/vote", json={"value": 1}).json()["score"] == 2
    u1.post(f"/api/feed/{a}/vote", json={"value": -1})
    assert [p["id"] for p in client.get("/api/feed?sort=top").json()["posts"]] == [b, a]
    assert u1.get("/api/feed?sort=top").json()["posts"][0]["my_vote"] == 1
    assert u1.post(f"/api/feed/{b}/vote", json={"value": 0}).json()["score"] == 1       # vote taken back
    assert u1.post(f"/api/feed/{b}/vote", json={"value": 5}).status_code == 422


def test_comments_and_who_may_delete(client):
    pid = post(client, scan_text="").json()["id"]
    u1, u2 = user_client("user1"), user_client("user2")
    p = u1.post(f"/api/feed/{pid}/comments", json={"body": "Same SMS came to my father"}).json()
    cid = p["comments"][0]["id"]
    assert p["comment_count"] == 1 and p["comments"][0]["author"] == "user1" and p["comments"][0]["can_delete"]
    assert u2.delete(f"/api/feed/comments/{cid}").status_code == 403
    assert u1.delete(f"/api/feed/comments/{cid}").status_code == 200
    u2.post(f"/api/feed/{pid}/comments", json={"body": "spam"})
    cid2 = client.get(f"/api/feed/{pid}").json()["comments"][0]["id"]
    assert client.delete(f"/api/feed/comments/{cid2}").status_code == 200              # admin may
    assert u1.post(f"/api/feed/{pid}/comments", json={"body": "   "}).status_code == 400


def test_delete_post_own_or_admin(client):
    u1, u2 = user_client("user1"), user_client("user2")
    pid = post(u1, scan_text="").json()["id"]
    assert u2.delete(f"/api/feed/{pid}").status_code == 403
    assert u1.delete(f"/api/feed/{pid}").status_code == 200
    pid = post(u1, scan_text="").json()["id"]
    assert client.delete(f"/api/feed/{pid}").status_code == 200
    assert client.get("/api/feed").json()["total"] == 0


def test_admin_moderation(client, anon):
    u1 = user_client("user1")
    first = post(u1, title="first", scan_text="").json()["id"]
    second = post(u1, title="second", scan_text="").json()["id"]
    assert u1.patch(f"/api/feed/{first}", json={"pinned": True}).status_code == 403
    p = client.patch(f"/api/feed/{first}", json={"pinned": True, "verified": True}).json()
    assert p["pinned"] and p["verified"]
    assert [x["id"] for x in anon.get("/api/feed").json()["posts"]] == [first, second]   # pinned on top
    client.patch(f"/api/feed/{second}", json={"hidden": True})
    assert [x["id"] for x in anon.get("/api/feed").json()["posts"]] == [first]
    assert anon.get(f"/api/feed/{second}").status_code == 404
    assert u1.post(f"/api/feed/{second}/vote", json={"value": 1}).status_code == 404
    assert anon.get("/api/feed?hidden=true").status_code == 403
    assert [x["id"] for x in client.get("/api/feed?hidden=true").json()["posts"]] == [second]


def test_admin_manages_users(client):
    u1 = user_client("user1")
    users = {u["username"]: u for u in client.get("/api/admin/users").json()["users"]}
    assert users["admin"]["role"] == "admin" and users["user1"]["role"] == "user"
    assert u1.get("/api/admin/users").status_code == 403
    # Blocking ends the user's sessions and stops posting and logging in.
    assert client.patch(f"/api/admin/users/{users["user1"]['id']}", json={"blocked": True}).json()["blocked"]
    assert post(u1, scan_text="").status_code == 401
    r = u1.post("/api/auth/login", json={"username": "user1", "password": "user-password-1"})
    assert r.status_code == 400 and "blocked" in r.json()["detail"]
    client.patch(f"/api/admin/users/{users["user1"]['id']}", json={"blocked": False, "role": "admin"})
    assert u1.post("/api/auth/login", json={"username": "user1", "password": "user-password-1"}).json()["user"]["role"] == "admin"
    assert client.patch(f"/api/admin/users/{users['admin']['id']}", json={"role": "user"}).status_code == 400


# --- screenshots -------------------------------------------------------------------

def test_screenshot_upload_is_checked_and_served(client, anon):
    r = post(client, scan_text="", files={"image": ("shot.png", png(), "image/png")})
    assert r.status_code == 200
    url = r.json()["image"]
    got = anon.get(url)
    assert got.status_code == 200 and got.headers["content-type"] == "image/png"
    assert got.headers["x-content-type-options"] == "nosniff"
    Image.open(io.BytesIO(got.content)).verify()


def test_screenshot_metadata_is_removed(client):
    r = post(client, scan_text="", files={"image": ("photo.jpg", png(exif=True), "image/jpeg")})
    stored = client.get(r.json()["image"]).content
    assert b"SecretPhoneMaker" not in stored and not Image.open(io.BytesIO(stored)).getexif()


@pytest.mark.parametrize("name,data", [
    ("evil.png", b"<script>alert(1)</script>"),
    ("x.svg", b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'),
    ("x.gif", b"GIF89a" + b"\x00" * 20),
])
def test_non_images_are_refused(client, name, data):
    r = post(client, scan_text="", files={"image": (name, data, "image/png")})
    assert r.status_code == 400
    assert client.get("/api/feed").json()["total"] == 0


def test_too_large_image_is_refused(client, monkeypatch):
    monkeypatch.setattr(config, "MAX_IMAGE_BYTES", 100)
    r = post(client, scan_text="", files={"image": ("shot.png", png((400, 400)), "image/png")})
    assert r.status_code == 400 and "larger" in r.json()["detail"]


@pytest.mark.parametrize("name", ["../../etc/passwd", "..%2F..%2Fapp%2Fmain.py", "abc.png", "a" * 32 + ".svg"])
def test_image_names_cannot_escape(anon, name):
    assert anon.get("/api/feed/images/" + name).status_code == 404


# --- PDF reports ---------------------------------------------------------------------

def test_post_pdf_needs_login(client, anon):
    pid = post(client).json()["id"]
    assert anon.get(f"/api/feed/{pid}/report.pdf").status_code == 401
    r = user_client("reader").get(f"/api/feed/{pid}/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert r.headers["content-type"] == "application/pdf" and "attachment" in r.headers["content-disposition"]
    no_scan = post(client, scan_text="").json()["id"]
    assert client.get(f"/api/feed/{no_scan}/report.pdf").status_code == 404


def test_report_of_a_fresh_analysis(anon):
    assert anon.post("/api/report.pdf", json={"text": SCAM_KYC}).status_code == 401
    c = user_client("someone")
    for text in (SCAM_KYC, SCAM_HINDI, OK_CHAT):
        r = c.post("/api/report.pdf", json={"text": text, "sender": "9876501234"})
        assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert db.list_cases()["total"] == 0                  # making a report saves nothing


def test_case_pdf_is_admin_only(client):
    case_id = client.post("/api/analyze", json={"text": SCAM_KYC}).json()["case_id"]
    assert client.get(f"/api/cases/{case_id}/report.pdf").content.startswith(b"%PDF")
    assert user_client("user1").get(f"/api/cases/{case_id}/report.pdf").status_code == 403
    assert client.get("/api/cases/99999/report.pdf").status_code == 404


def test_pdf_links_are_not_clickable(client):
    """The PDF shows links in safe form and contains no link annotations."""
    pid = post(client).json()["id"]
    pdf = client.get(f"/api/feed/{pid}/report.pdf").content
    assert b"/URI" not in pdf and b"/Annot" not in pdf


def test_history_and_dashboard_open_on_the_laptop_without_login(fresh_db):
    """Same as before accounts existed: on the laptop itself no login is needed; Admin still needs one."""
    with TestClient(app, client=("127.0.0.1", 50000)) as local:
        assert local.get("/api/auth/me").json() == {"user": None, "local": True}
        for path in ("/api/cases", "/api/stats", "/api/alerts", "/api/cases/export.csv"):
            assert local.get(path).status_code == 200, path
        case_id = local.post("/api/analyze", json={"text": SCAM_KYC}).json()["case_id"]
        assert local.get(f"/api/cases/{case_id}/report.pdf").status_code == 200
        assert local.get("/api/admin/users").status_code == 401
    with TestClient(app) as remote:                       # another device on the Wi-Fi
        assert remote.get("/api/auth/me").json()["local"] is False
        assert remote.get("/api/cases").status_code == 401


def test_one_click_guest_and_admin(fresh_db):
    """Guest works from any device; one-click admin only on the laptop and reuses the existing admin."""
    with TestClient(app) as remote:
        g = remote.post("/api/auth/quick", json={"who": "guest"})
        assert g.status_code == 200 and g.json()["user"] == {**g.json()["user"], "username": "guest", "role": "user"}
        assert post(remote, scan_text="").status_code == 200          # the guest can post
        r = remote.post("/api/auth/quick", json={"who": "admin"})
        assert r.status_code == 403 and "laptop" in r.json()["detail"]
        assert remote.get("/api/auth/me").json()["user"]["username"] == "guest"
        # The reserved names cannot be taken by registering.
        for name in ("guest", "Admin"):
            x = remote.post("/api/auth/register", json={"username": name, "password": "password-123"})
            assert x.status_code == 400 and "reserved" in x.json()["detail"]
    with TestClient(app, client=("127.0.0.1", 50001)) as local:
        a = local.post("/api/auth/quick", json={"who": "admin"}).json()["user"]
        assert a["username"] == "admin" and a["role"] == "admin"
        assert local.get("/api/admin/users").status_code == 200
        assert local.post("/api/auth/quick", json={"who": "guest"}).json()["user"]["id"] == g.json()["user"]["id"]


def test_one_click_admin_uses_the_registered_admin(fresh_db):
    accounts.register("ajay", "password-123", local=True)
    with TestClient(app, client=("127.0.0.1", 50002)) as local:
        assert local.post("/api/auth/quick", json={"who": "admin"}).json()["user"]["username"] == "ajay"


def test_blocked_guest_cannot_use_the_button(client, anon):
    gid = anon.post("/api/auth/quick", json={"who": "guest"}).json()["user"]["id"]
    client.patch(f"/api/admin/users/{gid}", json={"blocked": True})
    r = anon.post("/api/auth/quick", json={"who": "guest"})
    assert r.status_code == 400 and "blocked" in r.json()["detail"]


def test_demo_feed_posts_can_be_added_and_removed(client):
    """./run.sh seed adds demo posts from demo_ accounts; ./run.sh unseed removes them and nothing else."""
    from scripts import seed_demo
    real = post(client, title="A real post", scan_text="").json()["id"]
    seed_demo.seed_feed()
    feed = client.get("/api/feed").json()
    assert feed["total"] == len(seed_demo.POSTS) + 1
    assert feed["posts"][0]["pinned"] and feed["posts"][0]["author"].startswith("demo_")
    assert any(p["scan"] and p["scan"]["level"] == "Critical" for p in feed["posts"])
    assert sum(p["comment_count"] for p in feed["posts"]) >= 5 and max(p["score"] for p in feed["posts"]) >= 1
    seed_demo.seed_feed()                                   # running it twice does not double the posts
    assert client.get("/api/feed").json()["total"] == len(seed_demo.POSTS) + 1
    seed_demo.remove_feed()
    assert [p["id"] for p in client.get("/api/feed").json()["posts"]] == [real]
    r = client.post("/api/auth/register", json={"username": "demo_me", "password": "password-123"})
    assert r.status_code == 400 and "demo_" in r.json()["detail"]


def test_public_hosting_trusts_nobody_as_the_laptop(fresh_db, monkeypatch):
    """On Vercel every visitor may look like 127.0.0.1, so laptop-only rights are switched off."""
    monkeypatch.setattr(config, "PUBLIC", True)
    with TestClient(app, client=("127.0.0.1", 50003)) as c:
        assert c.get("/api/auth/me").json()["local"] is False
        assert c.get("/api/meta").json()["public_demo"] is True
        assert c.get("/api/cases").status_code == 401
        assert c.post("/api/auth/quick", json={"who": "admin"}).status_code == 403
        r = c.post("/api/auth/register", json={"username": "first_one", "password": "password-123"})
        assert r.json()["user"]["role"] == "user"                        # never admin by being first
        assert c.post("/api/ingest", json={"text": SCAM_KYC, "channel": "sms", "source": "sms-app"}).status_code == 401


def test_cloud_start_creates_admin_from_secret_and_demo_data(fresh_db, monkeypatch):
    from app import cloud
    monkeypatch.setenv("SATARK_ADMIN_PASSWORD", "secret-admin-pw-1")
    monkeypatch.setenv("SATARK_SEED", "1")
    cloud.prepare()
    cloud.prepare()                                                       # a second start changes nothing
    with db.connect() as con:
        assert [tuple(r) for r in con.execute("SELECT username, role FROM users WHERE role = 'admin'")] == [("admin", "admin")]
    assert db.list_cases()["total"] > 0
    with TestClient(app) as c:
        assert c.get("/api/feed").json()["total"] > 0
        assert c.post("/api/auth/login", json={"username": "admin", "password": "secret-admin-pw-1"}).status_code == 200
        assert c.get("/api/cases").status_code == 200
