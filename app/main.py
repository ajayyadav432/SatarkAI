"""FastAPI application: REST API + the static web UI."""
from __future__ import annotations

import csv
import io
import json
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import accounts, chat, config, db, downloads, feed, ingest, mailwatch, report_pdf
from app.analysis import brands, models, rules, shap_explain
from app.analysis.extract import normalise_url
from app.analysis.pipeline import analyze, analyze_url
from app.analysis.scoring import (CAP_REASON, CAP_WITHOUT_STRONG, ML_TEXT_MAX, ML_TEXT_MIN, ML_URL_MAX,
                                  ML_URL_MIN, level_rank)

VERSION = "1.0.0"


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    # Load the models once at start-up, so the first request is not slow.
    analyze("warm up http://example.com", channel="sms")
    mailwatch.start()
    yield


app = FastAPI(title=config.APP_NAME, version=VERSION, lifespan=lifespan,
              description=f"{config.APP_TAGLINE} ({config.PROBLEM_STATEMENT})")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


# Who may do what is decided per route: Analyze, the Feed (reading), log in / register and the downloads
# are open; posting, voting, comments and PDF reports need an account (accounts.require_user); History,
# Dashboard and live alerts are open on the laptop itself and need an admin from other devices
# (accounts.require_local_or_admin); user management needs an admin (accounts.require_admin). The phone app sends
# messages to /api/ingest with the pairing code.
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Another website must not use the visitor's login (cross-site request forgery). The cookie is
    # SameSite=Lax as well; this also refuses a changed Origin on requests that carry the session.
    origin = request.headers.get("origin")
    if (request.method in UNSAFE and origin and config.SESSION_COOKIE in request.cookies
            and origin.split("://", 1)[-1] != request.headers.get("host")):
        return JSONResponse({"detail": "Request from another website refused."}, status_code=403)
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/") or request.url.path in ("/", "/go"):
        response.headers["Cache-Control"] = "no-store"
    elif request.url.path.startswith("/static/"):
        # Always ask the server whether the file changed (cheap 304 if not), so updates show at once.
        response.headers["Cache-Control"] = "no-cache"
    return response


# --- request bodies --------------------------------------------------------

class AnalyzeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=config.MAX_TEXT_CHARS)
    channel: Literal["auto", "sms", "email", "social", "url"] = "auto"
    sender: str | None = Field(default=None, max_length=config.MAX_SENDER_CHARS)
    save: bool = True
    lookup: bool = False

    @field_validator("text")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("text must not be empty")
        return v


class ChatTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=2000)


class ChatContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=config.MAX_TEXT_CHARS)
    channel: Literal["auto", "sms", "email", "social", "url"] = "auto"
    sender: str | None = Field(default=None, max_length=config.MAX_SENDER_CHARS)


class ChatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=1000)
    history: list[ChatTurn] = Field(default_factory=list, max_length=8)
    context: ChatContext | None = None
    faq_id: str | None = Field(default=None, max_length=40)


class IngestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=config.MAX_TEXT_CHARS)
    channel: Literal["sms", "email", "social", "url"]
    sender: str | None = Field(default=None, max_length=config.MAX_SENDER_CHARS)
    source: Literal["sms-app", "gmail-web"]
    ref: str | None = Field(default=None, max_length=300)


class UrlsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    urls: list[str] = Field(min_length=1, max_length=200)


class AuthIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=60)
    password: str = Field(min_length=1, max_length=200)


class VoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: Literal[-1, 0, 1]


class CommentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=config.MAX_COMMENT)


class ModerateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pinned: bool | None = None
    verified: bool | None = None
    hidden: bool | None = None


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "admin"] | None = None
    blocked: bool | None = None


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=config.MAX_TEXT_CHARS)
    channel: Literal["auto", "sms", "email", "social", "url"] = "auto"
    sender: str | None = Field(default=None, max_length=config.MAX_SENDER_CHARS)


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["new", "reviewed", "confirmed_scam", "false_positive"] | None = None
    notes: str | None = Field(default=None, max_length=2000)


# --- pages -----------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(config.STATIC_DIR / "index.html")


@app.get("/go", include_in_schema=False)
def go():
    return FileResponse(config.STATIC_DIR / "go.html")


# --- API -------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "app": config.APP_NAME, "version": VERSION, "models": models.status()}


@app.get("/api/meta")
def meta():
    samples = json.loads((config.KNOWLEDGE_DIR / "samples.json").read_text(encoding="utf-8"))
    return {
        "app": config.APP_NAME, "tagline": config.APP_TAGLINE, "problem_statement": config.PROBLEM_STATEMENT,
        "version": VERSION,
        "levels": [{"name": n, "from": lo} for n, lo in config.RISK_LEVELS],
        "channels": config.CHANNELS, "statuses": config.CASE_STATUSES,
        "max_text_chars": config.MAX_TEXT_CHARS, "max_bulk_rows": config.MAX_BULK_ROWS,
        "warn_from_level": config.WARN_FROM_LEVEL,
        "public_demo": config.PUBLIC,
        "password_min": config.PASSWORD_MIN, "max_post_title": config.MAX_POST_TITLE,
        "max_post_body": config.MAX_POST_BODY, "max_comment": config.MAX_COMMENT,
        "samples": samples["samples"],
        "models": models.status(),
        "assistant": {**chat.status(), "questions": chat.faq_questions()},
    }


@app.post("/api/analyze")
def api_analyze(body: AnalyzeIn):
    history = db.sender_history(body.sender) if body.sender else None
    result = analyze(body.text, channel=body.channel, sender=body.sender, lookup=body.lookup, history=history)
    result["saved_min_score"] = config.SAVE_MIN_SCORE
    result["case_id"] = db.save_case(result, source="user") if body.save and config.worth_saving(result) else None
    earlier = history["count"] if history else 0
    result["block"] = db.block_advice(body.sender, earlier + (1 if result["case_id"] else 0))
    return result


@app.post("/api/chat")
def api_chat(body: ChatIn):
    """Safety assistant. The scan is re-run here, so the answer is based on the real result."""
    result = None
    if body.context:
        c = body.context
        result = analyze(c.text, channel=c.channel, sender=c.sender, lookup=False)
    history = [t.model_dump() for t in body.history]
    return chat.answer(body.message, history, result, faq_id=body.faq_id)


@app.post("/api/ingest")
def api_ingest(body: IngestIn, request: Request):
    """A message that arrived by itself: SMS on the phone, or an e-mail opened in Gmail.
    From another device the pairing code (header X-Satark-Token) is required."""
    if not accounts.is_local(request) and not ingest.token_ok(request.headers.get("x-satark-token")):
        raise HTTPException(status_code=401, detail="Wrong or missing pairing code.")
    if not body.text.strip():
        raise HTTPException(status_code=422, detail="text must not be empty")
    return ingest.ingest(body.text, body.channel, body.sender, body.source, ref=body.ref)


@app.get("/api/alerts")
def api_alerts(after: int = Query(default=0, ge=0), viewer: dict | None = Depends(accounts.require_local_or_admin)):
    """Risky messages that arrived automatically, newer than `after`. The web app polls this."""
    return ingest.alerts_after(after)


@app.get("/api/downloads")
def api_downloads():
    """What the home page offers for download (the APK only when it has been built)."""
    return {"apk": downloads.apk_info(), "extension": downloads.extension_info()}


@app.get("/download/" + downloads.APK_NAME, include_in_schema=False)
def download_apk():
    p = downloads.apk_path()
    if not p:
        raise HTTPException(status_code=404, detail="The Android app has not been built yet: cd android && ./gradlew assembleDebug")
    return FileResponse(p, media_type="application/vnd.android.package-archive", filename=downloads.APK_NAME)


@app.get("/download/" + downloads.EXT_NAME, include_in_schema=False)
def download_extension():
    return Response(downloads.extension_zip(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{downloads.EXT_NAME}"'})


@app.get("/api/auto-status")
def api_auto_status(viewer: dict | None = Depends(accounts.require_local_or_admin)):
    return {"lan_mode": config.LAN_MODE, "pairing_code_set": bool(ingest.token()),
            "mail_watcher": {k: mailwatch.status[k] for k in ("enabled", "running", "user", "last_check", "checked", "error")}}


@app.post("/api/check-urls")
def api_check_urls(body: UrlsIn):
    """Risk of many links at once (the browser extension marks risky links on a page). Nothing is saved."""
    out = {}
    for u in dict.fromkeys(body.urls):
        if not u.lower().startswith(("http://", "https://")):   # javascript:, mailto:, ... are not links to check
            continue
        url = normalise_url(u[: config.MAX_URL_CHARS])
        r = analyze_url(url, raw=u, lookup=False)
        out[u] = {"level": r["level"], "score": r["score"],
                  "reason": r["factors"][0]["title"] if r.get("factors") else None,
                  "needs_warning": level_rank(r["level"]) >= level_rank(config.WARN_FROM_LEVEL)}
    return {"results": out}


@app.get("/api/check-url")
def api_check_url(u: str = Query(min_length=1, max_length=config.MAX_URL_CHARS), lookup: bool = False):
    """Risk of one link. Used by the warning page and the browser extension. Nothing is saved."""
    url = normalise_url(u)
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Only http and https links can be checked.")
    result = analyze_url(url, raw=u, lookup=lookup)
    result["needs_warning"] = level_rank(result["level"]) >= level_rank(config.WARN_FROM_LEVEL)
    return result


def _case_filters(q, level, category, status, channel, source, date_from, date_to, min_score, sender_key=None) -> dict:
    return {"q": q, "level": level, "category": category, "status": status, "channel": channel,
            "source": source, "date_from": date_from, "date_to": date_to, "min_score": min_score,
            "sender_key": sender_key}


DATE = r"^\d{4}-\d{2}-\d{2}$"


@app.get("/api/cases")
def api_cases(
    q: str | None = Query(default=None, max_length=200),
    level: str | None = Query(default=None, max_length=60),
    category: str | None = Query(default=None, max_length=80),
    status: str | None = Query(default=None, max_length=80),
    channel: str | None = Query(default=None, max_length=40),
    source: str | None = Query(default=None, max_length=20),
    sender_key: str | None = Query(default=None, max_length=340),
    date_from: str | None = Query(default=None, pattern=DATE),
    date_to: str | None = Query(default=None, pattern=DATE),
    min_score: int | None = Query(default=None, ge=0, le=100),
    sort: Literal["newest", "oldest", "score_desc", "score_asc"] = "newest",
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    viewer: dict | None = Depends(accounts.require_local_or_admin),
):
    data = db.list_cases(page=page, page_size=page_size, sort=sort,
                         **_case_filters(q, level, category, status, channel, source, date_from, date_to, min_score, sender_key))
    data["categories"] = db.categories()
    return data


def _csv_safe(value) -> str:
    """Stop spreadsheet formula injection: a cell must not start with = + - @ tab or CR."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@app.get("/api/cases/export.csv")
def api_export(
    q: str | None = Query(default=None, max_length=200),
    level: str | None = Query(default=None, max_length=60),
    category: str | None = Query(default=None, max_length=80),
    status: str | None = Query(default=None, max_length=80),
    channel: str | None = Query(default=None, max_length=40),
    source: str | None = Query(default=None, max_length=20),
    sender_key: str | None = Query(default=None, max_length=340),
    date_from: str | None = Query(default=None, pattern=DATE),
    date_to: str | None = Query(default=None, pattern=DATE),
    min_score: int | None = Query(default=None, ge=0, le=100),
    viewer: dict | None = Depends(accounts.require_local_or_admin),
):
    rows = db.export_rows(**_case_filters(q, level, category, status, channel, source, date_from, date_to, min_score, sender_key))
    columns = ["id", "created_at", "channel", "sender", "score", "level", "category", "brands",
               "status", "notes", "source", "indicators", "text"]
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow(columns)
    for r in rows:
        writer.writerow([_csv_safe(r.get(c)) for c in columns])
    return Response(
        content="﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="satarkai-cases.csv"'},
    )


@app.get("/api/cases/{case_id}")
def api_case(case_id: int, viewer: dict | None = Depends(accounts.require_local_or_admin)):
    case = db.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.patch("/api/cases/{case_id}")
def api_case_update(case_id: int, body: CaseUpdate, viewer: dict | None = Depends(accounts.require_local_or_admin)):
    if not db.update_case(case_id, status=body.status, notes=body.notes):
        raise HTTPException(status_code=404, detail="Case not found")
    return db.get_case(case_id)


@app.delete("/api/cases/{case_id}")
def api_case_delete(case_id: int, viewer: dict | None = Depends(accounts.require_local_or_admin)):
    if not db.delete_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return {"deleted": case_id}


@app.get("/api/stats")
def api_stats(
    days: int = Query(default=30, ge=1, le=365),
    kind: Literal["phone", "email", "sender-id", "none"] | None = None,
    level: Literal["Medium", "High", "Critical"] | None = None,
    category: str | None = Query(default=None, max_length=80),
    source: str | None = Query(default=None, max_length=20),
    sender: str | None = Query(default=None, max_length=100),
    viewer: dict | None = Depends(accounts.require_local_or_admin),
):
    """Dashboard numbers. kind, level, category, source and sender filter the risky sections
    (Repeat senders, Risky SMS & e-mail); the other charts always show everything."""
    filters = {k: v for k, v in {"kind": kind, "level": level, "category": category, "source": source,
                                 "sender": (sender or "").strip() or None}.items() if v}
    return db.stats(days, min_score=config.SAVE_MIN_SCORE, filters=filters)


@app.get("/api/stats/summary")
def api_stats_summary():
    """The three numbers on the home page; open to everyone, no message content."""
    k = db.stats(90, min_score=config.SAVE_MIN_SCORE)["kpis"]
    return {"total": k["total"], "high_risk": k["high_risk"], "high_risk_share": k["high_risk_share"], "demo": k.get("demo", 0)}


@app.get("/api/model-card")
def api_model_card():
    """Everything shown on the 'How it works' page. Numbers come from models/metrics.json."""
    return {
        "metrics": models.metrics(),
        "rules": rules.group_info(),
        "brands": brands.brand_count(),
        "shap": shap_explain.summary(),
        "scoring": {
            "formula": "risk = 1 - (1 - w1) x (1 - w2) x ... ; score = risk x 100",
            "levels": [{"name": n, "from": lo} for n, lo in config.RISK_LEVELS],
            "text_model_weight": {"at_probability_0.5": ML_TEXT_MIN, "at_probability_1.0": ML_TEXT_MAX},
            "url_model_weight": {"at_threshold": ML_URL_MIN, "at_probability_1.0": ML_URL_MAX,
                                 "threshold": models.url_threshold()},
            "cap": {"limit": CAP_WITHOUT_STRONG, "reason": CAP_REASON},
        },
    }


def _rows_from_upload(name: str, raw: bytes) -> list[dict]:
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text.")
    if name.lower().endswith(".csv"):
        reader = csv.DictReader(io.StringIO(content))
        fields = {(f or "").strip().lower(): f for f in (reader.fieldnames or [])}
        text_col = next((fields[c] for c in ("text", "message", "body", "sms", "content") if c in fields), None)
        if text_col is None:
            raise HTTPException(status_code=400,
                                detail="CSV needs a column named text (or message / body / sms / content).")
        rows = []
        for row in reader:
            rows.append({"text": (row.get(text_col) or "").strip(),
                         "sender": (row.get(fields.get("sender", "")) or "").strip() if "sender" in fields else "",
                         "channel": (row.get(fields.get("channel", "")) or "").strip().lower() if "channel" in fields else "auto"})
        return rows
    return [{"text": line.strip(), "sender": "", "channel": "auto"} for line in content.splitlines()]


@app.post("/api/bulk")
async def api_bulk(file: UploadFile = File(...), viewer: dict | None = Depends(accounts.require_local_or_admin)):
    """Analyse many messages at once: a .csv with a 'text' column, or a .txt with one message per line."""
    raw = await file.read(config.MAX_BULK_BYTES + 1)
    if len(raw) > config.MAX_BULK_BYTES:
        raise HTTPException(status_code=413, detail=f"File is larger than {config.MAX_BULK_BYTES // 1024} KB.")
    rows = [r for r in _rows_from_upload(file.filename or "upload.txt", raw) if r["text"]]
    if not rows:
        raise HTTPException(status_code=400, detail="No messages found in the file.")
    truncated = len(rows) > config.MAX_BULK_ROWS
    items, by_level = [], {name: 0 for name, _ in config.RISK_LEVELS}
    for r in rows[: config.MAX_BULK_ROWS]:
        channel = r["channel"] if r["channel"] in config.CHANNELS else "auto"
        result = analyze(r["text"][: config.MAX_TEXT_CHARS], channel=channel, sender=r["sender"],
                         history=db.sender_history(r["sender"]) if r["sender"] else None)
        case_id = db.save_case(result, source="bulk") if config.worth_saving(result) else None
        by_level[result["level"]] += 1
        items.append({"case_id": case_id, "score": result["score"], "level": result["level"],
                      "category": result["category"], "text": result["text"][:160]})
    return {"analysed": len(items), "saved": sum(i["case_id"] is not None for i in items),
            "saved_min_score": config.SAVE_MIN_SCORE, "truncated": truncated, "max_rows": config.MAX_BULK_ROWS,
            "by_level": by_level, "items": items}


# --- accounts -----------------------------------------------------------------

def _client(request: Request) -> str:
    return request.client.host if request.client else ""


def _start_session(user: dict) -> JSONResponse:
    response = JSONResponse({"user": user})
    response.set_cookie(config.SESSION_COOKIE, accounts.new_session(user["id"]), max_age=config.SESSION_DAYS * 86400,
                        httponly=True, samesite="lax", path="/")
    return response


@app.post("/api/auth/register")
def api_register(body: AuthIn, request: Request):
    """Create an account and log in. The first account made on this laptop becomes admin."""
    try:
        user = accounts.register(body.username, body.password, local=accounts.is_local(request))
    except accounts.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return _start_session(user)


@app.post("/api/auth/login")
def api_login(body: AuthIn, request: Request):
    try:
        user = accounts.login(body.username, body.password, _client(request))
    except accounts.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return _start_session(user)


class QuickIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    who: Literal["guest", "admin"]


@app.post("/api/auth/quick")
def api_quick_login(body: QuickIn, request: Request):
    """One-click login as the shared guest, or (on the laptop only) as the admin."""
    try:
        user = accounts.quick_account(body.who, local=accounts.is_local(request))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    except accounts.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return _start_session(user)


@app.post("/api/auth/logout")
def api_logout(request: Request):
    accounts.end_session(request.cookies.get(config.SESSION_COOKIE))
    response = JSONResponse({"ok": True})
    response.delete_cookie(config.SESSION_COOKIE, path="/")
    return response


@app.get("/api/auth/me")
def api_me(request: Request, user: dict | None = Depends(accounts.current_user)):
    """local: the page is open on the laptop itself, where History and Dashboard need no login."""
    return {"user": user, "local": accounts.is_local(request)}


# --- community feed -------------------------------------------------------------

def _pdf(data: bytes, name: str) -> Response:
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/feed")
def api_feed(sort: Literal["new", "top"] = "new", page: int = Query(default=1, ge=1, le=10000),
             hidden: bool = False, user: dict | None = Depends(accounts.current_user)):
    """Posts, newest or most upvoted first. hidden=true lists hidden posts (admins only)."""
    if hidden and not (user and user["role"] == "admin"):
        raise HTTPException(status_code=403, detail="Only an admin can see hidden posts.")
    return feed.list_posts(user, sort=sort, page=page, hidden=hidden)


@app.post("/api/feed")
async def api_feed_create(
    title: str = Form(..., max_length=config.MAX_POST_TITLE),
    body: str = Form(default="", max_length=config.MAX_POST_BODY),
    scan_text: str = Form(default="", max_length=config.MAX_TEXT_CHARS),
    scan_channel: Literal["auto", "sms", "email", "social", "url"] = Form(default="auto"),
    scan_sender: str = Form(default="", max_length=config.MAX_SENDER_CHARS),
    image: UploadFile | None = File(default=None),
    user: dict = Depends(accounts.require_user),
):
    """New post. scan_text: the scam message; the server analyses it itself and attaches the result."""
    scan = None
    if scan_text.strip():
        sender = scan_sender.strip() or None
        result = analyze(scan_text, channel=scan_channel, sender=sender,
                         history=db.sender_history(sender) if sender else None)
        scan = feed.compact_scan(result)
    try:
        name = None
        if image is not None and image.filename:
            name = feed.save_image(await image.read(config.MAX_IMAGE_BYTES + 1))
        post_id = feed.create_post(user, title, body, scan, name)
    except feed.FeedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return feed.get_post(post_id, user)


@app.get("/api/feed/images/{name}", include_in_schema=False)
def api_feed_image(name: str):
    path = feed.image_path(name)
    if not path:
        raise HTTPException(status_code=404, detail="Image not found")
    return FileResponse(path, media_type="image/png" if name.endswith(".png") else "image/jpeg")


@app.get("/api/feed/{post_id}")
def api_post(post_id: int, user: dict | None = Depends(accounts.current_user)):
    post = feed.get_post(post_id, user)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post


@app.post("/api/feed/{post_id}/vote")
def api_vote(post_id: int, body: VoteIn, user: dict = Depends(accounts.require_user)):
    score = feed.vote(post_id, user, body.value)
    if score is None:
        raise HTTPException(status_code=404, detail="Post not found")
    return {"score": score, "my_vote": body.value}


@app.post("/api/feed/{post_id}/comments")
def api_comment(post_id: int, body: CommentIn, user: dict = Depends(accounts.require_user)):
    try:
        if feed.add_comment(post_id, user, body.body) is None:
            raise HTTPException(status_code=404, detail="Post not found")
    except feed.FeedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return feed.get_post(post_id, user)


@app.delete("/api/feed/comments/{comment_id}")
def api_comment_delete(comment_id: int, user: dict = Depends(accounts.require_user)):
    done = feed.delete_comment(comment_id, user)
    if done is None:
        raise HTTPException(status_code=404, detail="Comment not found")
    if not done:
        raise HTTPException(status_code=403, detail="You can only delete your own comments.")
    return {"deleted": comment_id}


@app.delete("/api/feed/{post_id}")
def api_post_delete(post_id: int, user: dict = Depends(accounts.require_user)):
    done = feed.delete_post(post_id, user)
    if done is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if not done:
        raise HTTPException(status_code=403, detail="You can only delete your own posts.")
    return {"deleted": post_id}


@app.patch("/api/feed/{post_id}")
def api_post_moderate(post_id: int, body: ModerateIn, admin: dict = Depends(accounts.require_admin)):
    if not feed.moderate(post_id, pinned=body.pinned, verified=body.verified, hidden=body.hidden):
        raise HTTPException(status_code=404, detail="Post not found")
    return feed.get_post(post_id, admin)


# --- PDF case reports --------------------------------------------------------------

@app.get("/api/feed/{post_id}/report.pdf")
def api_post_report(post_id: int, user: dict = Depends(accounts.require_user)):
    post = feed.get_post(post_id, user)
    if not post or not post["scan"]:
        raise HTTPException(status_code=404, detail="This post has no scanned message.")
    return _pdf(report_pdf.build(post["scan"], f"Feed post #{post_id}", f"posted by {post['author']}"),
                f"satarkai-post-{post_id}.pdf")


@app.get("/api/cases/{case_id}/report.pdf")
def api_case_report(case_id: int, viewer: dict | None = Depends(accounts.require_local_or_admin)):
    case = db.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return _pdf(report_pdf.build(case["result"], f"Case #{case_id}", f"status: {case['status']}"),
                f"satarkai-case-{case_id}.pdf")


@app.post("/api/report.pdf")
def api_report(body: ReportIn, user: dict = Depends(accounts.require_user)):
    """PDF of a message the user just analysed. The message is analysed again here (nothing is saved)."""
    sender = (body.sender or "").strip() or None
    result = analyze(body.text, channel=body.channel, sender=sender,
                     history=db.sender_history(sender) if sender else None)
    return _pdf(report_pdf.build(result, "Analysis", f"for {user['username']}"), "satarkai-report.pdf")


# --- admin: users -----------------------------------------------------------------

@app.get("/api/admin/users")
def api_users(admin: dict = Depends(accounts.require_admin)):
    return {"users": accounts.list_users()}


@app.patch("/api/admin/users/{user_id}")
def api_user_update(user_id: int, body: UserUpdate, admin: dict = Depends(accounts.require_admin)):
    try:
        user = accounts.update_user(user_id, admin, role=body.role, blocked=body.blocked)
    except accounts.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.exception_handler(404)
async def not_found(request: Request, exc):
    detail = getattr(exc, "detail", "Not found")
    return JSONResponse(status_code=404, content={"detail": detail})


app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
