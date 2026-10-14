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

from app import chat, config, db
from app.analysis import brands, models, rules
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
    yield


app = FastAPI(title=config.APP_NAME, version=VERSION, lifespan=lifespan,
              description=f"{config.APP_TAGLINE} ({config.PROBLEM_STATEMENT})")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/") or request.url.path in ("/", "/go"):
        response.headers["Cache-Control"] = "no-store"
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
    result = analyze(body.text, channel=body.channel, sender=body.sender, lookup=body.lookup)
    result["case_id"] = db.save_case(result, source="user") if body.save else None
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


@app.get("/api/check-url")
def api_check_url(u: str = Query(min_length=1, max_length=config.MAX_URL_CHARS), lookup: bool = False):
    """Risk of one link. Used by the warning page and the browser extension. Nothing is saved."""
    url = normalise_url(u)
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Only http and https links can be checked.")
    result = analyze_url(url, raw=u, lookup=lookup)
    result["needs_warning"] = level_rank(result["level"]) >= level_rank(config.WARN_FROM_LEVEL)
    return result


def _case_filters(q, level, category, status, channel, source, date_from, date_to, min_score) -> dict:
    return {"q": q, "level": level, "category": category, "status": status, "channel": channel,
            "source": source, "date_from": date_from, "date_to": date_to, "min_score": min_score}


DATE = r"^\d{4}-\d{2}-\d{2}$"


@app.get("/api/cases")
def api_cases(
    q: str | None = Query(default=None, max_length=200),
    level: str | None = Query(default=None, max_length=60),
    category: str | None = Query(default=None, max_length=80),
    status: str | None = Query(default=None, max_length=80),
    channel: str | None = Query(default=None, max_length=40),
    source: str | None = Query(default=None, max_length=20),
    date_from: str | None = Query(default=None, pattern=DATE),
    date_to: str | None = Query(default=None, pattern=DATE),
    min_score: int | None = Query(default=None, ge=0, le=100),
    sort: Literal["newest", "oldest", "score_desc", "score_asc"] = "newest",
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
):
    data = db.list_cases(page=page, page_size=page_size, sort=sort,
                         **_case_filters(q, level, category, status, channel, source, date_from, date_to, min_score))
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
    date_from: str | None = Query(default=None, pattern=DATE),
    date_to: str | None = Query(default=None, pattern=DATE),
    min_score: int | None = Query(default=None, ge=0, le=100),
):
    rows = db.export_rows(**_case_filters(q, level, category, status, channel, source, date_from, date_to, min_score))
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
def api_stats(days: int = Query(default=30, ge=1, le=365)):
    return db.stats(days)


@app.get("/api/model-card")
def api_model_card():
    """Everything shown on the 'How it works' page. Numbers come from models/metrics.json."""
    return {
        "metrics": models.metrics(),
        "rules": rules.group_info(),
        "brands": brands.brand_count(),
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
        result = analyze(r["text"][: config.MAX_TEXT_CHARS], channel=channel, sender=r["sender"])
        case_id = db.save_case(result, source="bulk")
        by_level[result["level"]] += 1
        items.append({"case_id": case_id, "score": result["score"], "level": result["level"],
                      "category": result["category"], "text": result["text"][:160]})
    return {"analysed": len(items), "truncated": truncated, "max_rows": config.MAX_BULK_ROWS,
            "by_level": by_level, "items": items}


@app.exception_handler(404)
async def not_found(request: Request, exc):
    detail = getattr(exc, "detail", "Not found")
    return JSONResponse(status_code=404, content={"detail": detail})


app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
