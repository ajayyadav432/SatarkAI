"""FastAPI application: REST API + the static web UI."""
from __future__ import annotations

import csv
import io
import json
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import chat, config, db, downloads, ingest, mailwatch
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


# In LAN mode (SATARK_HOST=0.0.0.0, so the phone can reach the laptop) other devices may only call
# the ingest endpoint, with the pairing code. History, dashboard and the rest stay on this computer.
LAN_ALLOWED = {("POST", "/api/ingest"), ("GET", "/api/health")}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    client = request.client.host if request.client else ""
    if config.LAN_MODE and client not in config.LOOPBACK:
        lan_ok = (request.method, request.url.path) in LAN_ALLOWED or (
            request.method == "GET" and request.url.path.startswith("/download/"))   # the phone may fetch the app
        if not lan_ok:
            return JSONResponse({"detail": "Only the SatarkAI phone app may connect from the network."}, status_code=403)
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
    client = request.client.host if request.client else ""
    if client not in config.LOOPBACK and not ingest.token_ok(request.headers.get("x-satark-token")):
        raise HTTPException(status_code=401, detail="Wrong or missing pairing code.")
    if not body.text.strip():
        raise HTTPException(status_code=422, detail="text must not be empty")
    return ingest.ingest(body.text, body.channel, body.sender, body.source, ref=body.ref)


@app.get("/api/alerts")
def api_alerts(after: int = Query(default=0, ge=0)):
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
def api_auto_status():
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
def api_case(case_id: int):
    case = db.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.patch("/api/cases/{case_id}")
def api_case_update(case_id: int, body: CaseUpdate):
    if not db.update_case(case_id, status=body.status, notes=body.notes):
        raise HTTPException(status_code=404, detail="Case not found")
    return db.get_case(case_id)


@app.delete("/api/cases/{case_id}")
def api_case_delete(case_id: int):
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
):
    """Dashboard numbers. kind, level, category, source and sender filter the risky sections
    (Repeat senders, Risky SMS & e-mail); the other charts always show everything."""
    filters = {k: v for k, v in {"kind": kind, "level": level, "category": category, "source": source,
                                 "sender": (sender or "").strip() or None}.items() if v}
    return db.stats(days, min_score=config.SAVE_MIN_SCORE, filters=filters)


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
async def api_bulk(file: UploadFile = File(...)):
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


@app.exception_handler(404)
async def not_found(request: Request, exc):
    detail = getattr(exc, "detail", "Not found")
    return JSONResponse(status_code=404, content={"detail": detail})


app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
