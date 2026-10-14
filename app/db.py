"""History of analysed cases: SQLite with full-text search (FTS5)."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from app import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT    NOT NULL,
    channel     TEXT    NOT NULL,
    sender      TEXT    NOT NULL DEFAULT '',
    text        TEXT    NOT NULL,
    score       INTEGER NOT NULL,
    level       TEXT    NOT NULL,
    category    TEXT    NOT NULL,
    brands      TEXT    NOT NULL DEFAULT '',
    indicators  TEXT    NOT NULL DEFAULT '',
    result_json TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'new',
    notes       TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT 'user'
);
CREATE INDEX IF NOT EXISTS idx_cases_created  ON cases(created_at);
CREATE INDEX IF NOT EXISTS idx_cases_level    ON cases(level);
CREATE INDEX IF NOT EXISTS idx_cases_category ON cases(category);
CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status);

CREATE TABLE IF NOT EXISTS case_factors (
    case_id   INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    factor_id TEXT    NOT NULL,
    title     TEXT    NOT NULL,
    weight    REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_factors_case ON case_factors(case_id);

CREATE TABLE IF NOT EXISTS case_indicators (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind    TEXT    NOT NULL,
    value   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_indicators_case ON case_indicators(case_id);
CREATE INDEX IF NOT EXISTS idx_indicators_kind ON case_indicators(kind, value);

CREATE VIRTUAL TABLE IF NOT EXISTS cases_fts USING fts5(
    text, sender, indicators, category, brands, notes,
    tokenize = "unicode61 categories 'L* N* Co Mn Mc'"
);
"""

LEVELS = [name for name, _ in config.RISK_LEVELS]
SORTS = {
    "newest": "c.created_at DESC, c.id DESC",
    "oldest": "c.created_at ASC, c.id ASC",
    "score_desc": "c.score DESC, c.id DESC",
    "score_asc": "c.score ASC, c.id DESC",
}
LIST_COLUMNS = ("c.id, c.created_at, c.channel, c.sender, c.text, c.score, c.level, c.category, "
                "c.brands, c.status, c.notes, c.source")


@contextmanager
def connect():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(config.DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db() -> None:
    with connect() as con:
        con.execute("PRAGMA journal_mode = WAL")
        con.executescript(SCHEMA)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _indicator_rows(result: dict) -> list[tuple[str, str]]:
    ent = result.get("entities", {})
    rows = [("url", u["display"]) for u in ent.get("urls", [])]
    rows += [("domain", d) for d in ent.get("domains", [])]
    rows += [("email", v) for v in ent.get("emails", [])]
    rows += [("phone", v) for v in ent.get("phones", [])]
    rows += [("upi", v) for v in ent.get("upi_ids", [])]
    rows += [("brand", b) for b in result.get("brands", [])]
    return rows


def save_case(result: dict, source: str = "user", created_at: str | None = None) -> int:
    """Store one analysis result and return its case id."""
    indicators = _indicator_rows(result)
    searchable = " ".join(v for kind, v in indicators if kind != "brand")
    # Also index the plain (clickable-form) links, so a search for "evil.com" finds "evil[.]com".
    searchable += " " + " ".join(u["url"] for u in result.get("urls", []))
    brands = ", ".join(result.get("brands", []))
    with connect() as con:
        cur = con.execute(
            "INSERT INTO cases (created_at, channel, sender, text, score, level, category, brands, "
            "indicators, result_json, source) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (created_at or now_iso(), result["channel"], result.get("sender", ""), result["text"],
             result["score"], result["level"], result["category"], brands, searchable,
             json.dumps(result, ensure_ascii=False), source),
        )
        case_id = cur.lastrowid
        con.executemany(
            "INSERT INTO case_factors (case_id, factor_id, title, weight) VALUES (?,?,?,?)",
            [(case_id, f["id"], _factor_label(f), f["weight"]) for f in result.get("factors", [])],
        )
        con.executemany(
            "INSERT INTO case_indicators (case_id, kind, value) VALUES (?,?,?)",
            [(case_id, kind, value) for kind, value in indicators],
        )
        con.execute(
            "INSERT INTO cases_fts (rowid, text, sender, indicators, category, brands, notes) VALUES (?,?,?,?,?,?,?)",
            (case_id, result["text"], result.get("sender", ""), searchable, result["category"], brands, ""),
        )
    return case_id


def _factor_label(f: dict) -> str:
    """Stable label for dashboards: model factors carry a changing percentage in the title."""
    if f["id"] == "ml_text":
        return "Text model flagged the wording"
    if f["id"] == "ml_url":
        return "URL model flagged the link"
    # 'Domain looks like a misspelling of PayPal' -> group all brands together
    generic = {
        "url_lookalike": "Lookalike (misspelled) brand domain",
        "url_brand_in_host": "Brand name on a domain it does not own",
        "url_brand_in_path": "Brand name in the link path",
        "brand_link_mismatch": "Names a brand but links elsewhere",
        "sender_lookalike": "Sender address imitates a brand",
        "sender_free_mail": "Brand claim from a free e-mail address",
        "sender_mismatch": "Sender domain does not match the brand",
        "sender_personal_number": "Brand claim from a personal mobile number",
        "url_download": "Link downloads an app or program",
    }
    return generic.get(f["id"], f["title"])


def fts_query(q: str) -> str | None:
    """Turn free text into a safe FTS5 query: every word must match (prefix allowed).

    Each word is wrapped in double quotes, so FTS5 operators typed by a user
    (AND, OR, NEAR, *, :, quotes) are treated as plain text.
    """
    parts = []
    for chunk in q.split():
        if not any(ch.isalnum() for ch in chunk):
            continue
        parts.append('"' + chunk.replace('"', '""') + '"*')
    return " ".join(parts[:12]) if parts else None


def _filters(q=None, level=None, category=None, status=None, channel=None, source=None,
             date_from=None, date_to=None, min_score=None) -> tuple[str, list, bool]:
    where, params = [], []
    match = fts_query(q) if q else None
    if q and not match:
        where.append("0")  # the search text had no searchable characters: no results
    if match:
        where.append("c.id IN (SELECT rowid FROM cases_fts WHERE cases_fts MATCH ?)")
        params.append(match)
    for column, value, allowed in (
        ("c.level", level, LEVELS), ("c.status", status, config.CASE_STATUSES),
        ("c.channel", channel, config.CHANNELS),
    ):
        if value:
            values = [v for v in str(value).split(",") if v in allowed]
            if not values:
                where.append("0")
                continue
            where.append(f"{column} IN ({','.join('?' * len(values))})")
            params.extend(values)
    if category:
        where.append("c.category = ?")
        params.append(category)
    if source:
        where.append("c.source = ?")
        params.append(source)
    if date_from:
        where.append("date(c.created_at, 'localtime') >= date(?)")
        params.append(date_from)
    if date_to:
        where.append("date(c.created_at, 'localtime') <= date(?)")
        params.append(date_to)
    if min_score is not None:
        where.append("c.score >= ?")
        params.append(int(min_score))
    return (" WHERE " + " AND ".join(where)) if where else "", params, bool(match)


def list_cases(page: int = 1, page_size: int = 20, sort: str = "newest", **filters) -> dict:
    page = max(1, int(page))
    page_size = max(1, min(100, int(page_size)))
    where, params, _ = _filters(**filters)
    order = SORTS.get(sort, SORTS["newest"])
    with connect() as con:
        total = con.execute(f"SELECT COUNT(*) FROM cases c{where}", params).fetchone()[0]
        rows = con.execute(
            f"SELECT {LIST_COLUMNS} FROM cases c{where} ORDER BY {order} LIMIT ? OFFSET ?",
            params + [page_size, (page - 1) * page_size],
        ).fetchall()
    return {
        "total": total, "page": page, "page_size": page_size,
        "pages": max(1, -(-total // page_size)),
        "items": [dict(r) for r in rows],
    }


def export_rows(limit: int = 5000, **filters) -> list[dict]:
    where, params, _ = _filters(**filters)
    with connect() as con:
        rows = con.execute(
            f"SELECT {LIST_COLUMNS}, c.indicators FROM cases c{where} ORDER BY c.created_at DESC, c.id DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    return [dict(r) for r in rows]


def get_case(case_id: int) -> dict | None:
    with connect() as con:
        row = con.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        return None
    case = dict(row)
    case["result"] = json.loads(case.pop("result_json"))
    return case


def update_case(case_id: int, status: str | None = None, notes: str | None = None) -> bool:
    sets, params = [], []
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if notes is not None:
        sets.append("notes = ?")
        params.append(notes)
    if not sets:
        return get_case(case_id) is not None
    with connect() as con:
        cur = con.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id = ?", params + [case_id])
        if cur.rowcount and notes is not None:
            con.execute("UPDATE cases_fts SET notes = ? WHERE rowid = ?", (notes, case_id))
        return bool(cur.rowcount)


def delete_case(case_id: int) -> bool:
    with connect() as con:
        cur = con.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        if cur.rowcount:
            con.execute("DELETE FROM cases_fts WHERE rowid = ?", (case_id,))
        return bool(cur.rowcount)


def delete_by_source(source: str) -> int:
    with connect() as con:
        ids = [r[0] for r in con.execute("SELECT id FROM cases WHERE source = ?", (source,))]
        con.executemany("DELETE FROM cases_fts WHERE rowid = ?", [(i,) for i in ids])
        con.execute("DELETE FROM cases WHERE source = ?", (source,))
    return len(ids)


def categories() -> list[str]:
    with connect() as con:
        return [r[0] for r in con.execute(
            "SELECT category FROM cases GROUP BY category ORDER BY COUNT(*) DESC")]


def stats(days: int = 30) -> dict:
    """Numbers for the security dashboard."""
    days = max(1, min(365, int(days)))
    since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).strftime("%Y-%m-%dT00:00:00Z")
    with connect() as con:
        def rows(sql: str, params=()):
            return [dict(r) for r in con.execute(sql, params).fetchall()]

        total_all = con.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        k = con.execute(
            "SELECT COUNT(*) AS total, COALESCE(ROUND(AVG(score), 1), 0) AS avg_score, "
            "COALESCE(SUM(level IN ('High','Critical')), 0) AS high_risk, "
            "COALESCE(SUM(level = 'Critical'), 0) AS critical, "
            "COALESCE(SUM(status = 'new' AND level IN ('High','Critical')), 0) AS needs_review, "
            "COALESCE(SUM(date(created_at, 'localtime') = date('now', 'localtime')), 0) AS today, "
            "COALESCE(SUM(status = 'confirmed_scam'), 0) AS confirmed, "
            "COALESCE(SUM(status = 'false_positive'), 0) AS false_positives, "
            "COALESCE(SUM(source = 'demo-seed'), 0) AS demo "
            "FROM cases WHERE created_at >= ?", (since,)).fetchone()
        kpis = dict(k)
        kpis["total_all_time"] = total_all
        kpis["high_risk_share"] = round(100 * kpis["high_risk"] / kpis["total"], 1) if kpis["total"] else 0.0

        by_level = {r["level"]: r["n"] for r in rows(
            "SELECT level, COUNT(*) AS n FROM cases WHERE created_at >= ? GROUP BY level", (since,))}
        trend = rows(
            "SELECT date(created_at, 'localtime') AS day, level, COUNT(*) AS n FROM cases "
            "WHERE created_at >= ? GROUP BY day, level ORDER BY day", (since,))
        cats = rows(
            "SELECT category, COUNT(*) AS n, ROUND(AVG(score), 0) AS avg_score FROM cases "
            "WHERE created_at >= ? AND category != 'None' GROUP BY category ORDER BY n DESC LIMIT 12", (since,))
        factors = rows(
            "SELECT f.title, COUNT(DISTINCT f.case_id) AS n FROM case_factors f JOIN cases c ON c.id = f.case_id "
            "WHERE c.created_at >= ? GROUP BY f.title ORDER BY n DESC LIMIT 10", (since,))
        brand_rows = rows(
            "SELECT i.value AS brand, COUNT(DISTINCT i.case_id) AS n FROM case_indicators i "
            "JOIN cases c ON c.id = i.case_id WHERE i.kind = 'brand' AND c.created_at >= ? "
            "AND c.level IN ('Medium','High','Critical') GROUP BY i.value ORDER BY n DESC LIMIT 10", (since,))
        domains = rows(
            "SELECT i.value AS domain, COUNT(DISTINCT i.case_id) AS n, MAX(c.score) AS max_score, "
            "MAX(c.created_at) AS last_seen FROM case_indicators i JOIN cases c ON c.id = i.case_id "
            "WHERE i.kind = 'domain' AND c.created_at >= ? AND c.level IN ('Medium','High','Critical') "
            "GROUP BY i.value ORDER BY n DESC, max_score DESC LIMIT 10", (since,))
        channels = rows(
            "SELECT channel, COUNT(*) AS n, COALESCE(SUM(level IN ('High','Critical')), 0) AS high_risk "
            "FROM cases WHERE created_at >= ? GROUP BY channel ORDER BY n DESC", (since,))
        statuses = {r["status"]: r["n"] for r in rows(
            "SELECT status, COUNT(*) AS n FROM cases WHERE created_at >= ? GROUP BY status", (since,))}
        recent = rows(
            "SELECT id, created_at, channel, score, level, category, substr(text, 1, 140) AS text, status, source "
            "FROM cases WHERE level IN ('High','Critical') AND created_at >= ? "
            "ORDER BY created_at DESC, id DESC LIMIT 6", (since,))

    # Fill days with no cases, so the trend chart has a continuous axis.
    today = datetime.now().date()
    day_list = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    series = {lvl: [0] * len(day_list) for lvl in LEVELS}
    index = {d: i for i, d in enumerate(day_list)}
    for r in trend:
        if r["day"] in index and r["level"] in series:
            series[r["level"]][index[r["day"]]] = r["n"]

    return {
        "days": days, "kpis": kpis,
        "levels": [{"level": lvl, "n": by_level.get(lvl, 0)} for lvl in LEVELS],
        "trend": {"days": day_list, "series": series},
        "categories": cats, "factors": factors, "brands": brand_rows, "domains": domains,
        "channels": channels, "statuses": [{"status": s, "n": statuses.get(s, 0)} for s in config.CASE_STATUSES],
        "recent_high_risk": recent,
    }
