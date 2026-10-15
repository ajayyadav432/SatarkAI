"""Community feed: users post scams they received so others learn to spot them.

Posts can carry a scan result (computed by this server from the message text, never taken from the
browser) and one screenshot. Screenshots are decoded and saved again with Pillow, which checks that the
file really is an image and drops hidden data such as the GPS position a phone camera may add.
"""
from __future__ import annotations

import io
import json
import secrets

from PIL import Image, UnidentifiedImageError

from app import config, db

IMAGE_FORMATS = {"PNG": ("png", "image/png"), "JPEG": ("jpg", "image/jpeg"), "WEBP": ("jpg", "image/jpeg")}
IMAGE_MAX_SIDE = 1600
IMAGE_MAX_PIXELS = 40_000_000   # refuse "decompression bombs" before decoding
IMAGE_NAME_CHARS = set("0123456789abcdef")
SORTS = {
    "new": "p.pinned DESC, p.created_at DESC, p.id DESC",
    "top": "p.pinned DESC, score DESC, p.created_at DESC, p.id DESC",
}


class FeedError(ValueError):
    """A problem with what the user sent; the message is shown to them."""


def compact_scan(r: dict) -> dict:
    """What a post keeps of an analysis: enough for the card, the complaint text and the PDF."""
    return {
        "score": r["score"], "level": r["level"], "category": r["category"], "summary": r["summary"],
        "advice": r.get("advice", []), "channel": r["channel"], "text": r["text"], "sender": r.get("sender", ""),
        "own_score": r.get("own_score"), "own_level": r.get("own_level"), "history_raised": r.get("history_raised"),
        "factors": [{"title": f["title"], "detail": f.get("detail", ""), "points": f.get("points"),
                     "source": f.get("source")} for f in r.get("factors", [])[:12]],
        "urls": [{"raw": u["raw"], "display": u["display"], "level": u["level"], "score": u["score"],
                  "registered_domain": u.get("registered_domain")} for u in r.get("urls", [])[:10]],
        "entities": {k: r.get("entities", {}).get(k, []) for k in ("phones", "upi_ids", "emails", "amounts", "domains")},
        "brands": r.get("brands", []),
    }


def save_image(data: bytes) -> str:
    """Check, shrink and re-save an uploaded screenshot. Returns the stored file name."""
    if len(data) > config.MAX_IMAGE_BYTES:
        raise FeedError(f"The image is larger than {config.MAX_IMAGE_BYTES // (1024 * 1024)} MB.")
    try:
        img = Image.open(io.BytesIO(data))
        if img.format not in IMAGE_FORMATS:
            raise FeedError("Only PNG, JPEG or WebP images can be attached.")
        if img.width * img.height > IMAGE_MAX_PIXELS:
            raise FeedError("The image is too large.")
        img.load()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise FeedError("This file is not a readable image.") from None
    ext, _ = IMAGE_FORMATS[img.format]
    img.thumbnail((IMAGE_MAX_SIDE, IMAGE_MAX_SIDE))
    out = io.BytesIO()
    if ext == "png":
        img.save(out, "PNG", optimize=True)      # no metadata is copied over
    else:
        img.convert("RGB").save(out, "JPEG", quality=85)
    name = secrets.token_hex(16) + "." + ext
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (config.UPLOAD_DIR / name).write_bytes(out.getvalue())
    return name


def image_path(name: str):
    """The stored file for a name from a URL, or None. Only names this module created are accepted."""
    stem, _, ext = name.partition(".")
    if len(stem) != 32 or not set(stem) <= IMAGE_NAME_CHARS or ext not in ("png", "jpg"):
        return None
    path = config.UPLOAD_DIR / name
    return path if path.is_file() else None


def create_post(user: dict, title: str, body: str, scan: dict | None, image: str | None) -> int:
    title, body = (title or "").strip(), (body or "").strip()
    if not title:
        raise FeedError("Give the post a title.")
    with db.connect() as con:
        cur = con.execute(
            "INSERT INTO posts (user_id, created_at, title, body, scan_json, image) VALUES (?, ?, ?, ?, ?, ?)",
            (user["id"], db.now_iso(), title[: config.MAX_POST_TITLE], body[: config.MAX_POST_BODY],
             json.dumps(scan, ensure_ascii=False) if scan else None, image))
        return cur.lastrowid


_POST_SELECT = (
    "SELECT p.*, u.username AS author, "
    "COALESCE((SELECT SUM(value) FROM votes v WHERE v.post_id = p.id), 0) AS score, "
    "(SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count, "
    "COALESCE((SELECT value FROM votes v WHERE v.post_id = p.id AND v.user_id = ?), 0) AS my_vote "
    "FROM posts p JOIN users u ON u.id = p.user_id ")


def _post(row, viewer: dict | None) -> dict:
    is_admin = bool(viewer and viewer["role"] == "admin")
    return {
        "id": row["id"], "created_at": row["created_at"], "title": row["title"], "body": row["body"],
        "author": row["author"], "score": row["score"], "my_vote": row["my_vote"],
        "comment_count": row["comment_count"], "pinned": bool(row["pinned"]), "verified": bool(row["verified"]),
        "hidden": bool(row["hidden"]),
        "scan": json.loads(row["scan_json"]) if row["scan_json"] else None,
        "image": f"/api/feed/images/{row['image']}" if row["image"] else None,
        "can_delete": bool(viewer and (is_admin or viewer["id"] == row["user_id"])),
    }


def list_posts(viewer: dict | None, sort: str = "new", page: int = 1, hidden: bool = False) -> dict:
    """hidden=True (admins only): list the posts admins have hidden instead of the visible ones."""
    order = SORTS.get(sort, SORTS["new"])
    size = config.FEED_PAGE_SIZE
    vid = viewer["id"] if viewer else 0
    with db.connect() as con:
        total = con.execute("SELECT COUNT(*) FROM posts WHERE hidden = ?", (int(hidden),)).fetchone()[0]
        rows = con.execute(_POST_SELECT + f"WHERE p.hidden = ? ORDER BY {order} LIMIT ? OFFSET ?",
                           (vid, int(hidden), size, (max(page, 1) - 1) * size)).fetchall()
    return {"total": total, "page": page, "page_size": size, "posts": [_post(r, viewer) for r in rows]}


def get_post(post_id: int, viewer: dict | None) -> dict | None:
    with db.connect() as con:
        row = con.execute(_POST_SELECT + "WHERE p.id = ?", (viewer["id"] if viewer else 0, post_id)).fetchone()
        if not row or (row["hidden"] and not (viewer and viewer["role"] == "admin")):
            return None
        comments = con.execute(
            "SELECT c.*, u.username AS author FROM comments c JOIN users u ON u.id = c.user_id "
            "WHERE c.post_id = ? ORDER BY c.created_at, c.id", (post_id,)).fetchall()
    post = _post(row, viewer)
    is_admin = bool(viewer and viewer["role"] == "admin")
    post["comments"] = [{"id": c["id"], "author": c["author"], "created_at": c["created_at"], "body": c["body"],
                         "can_delete": bool(viewer and (is_admin or viewer["id"] == c["user_id"]))} for c in comments]
    return post


def _visible(con, post_id: int) -> bool:
    return bool(con.execute("SELECT 1 FROM posts WHERE id = ? AND hidden = 0", (post_id,)).fetchone())


def vote(post_id: int, user: dict, value: int) -> int | None:
    """value 1, -1, or 0 to take the vote back. Returns the new score, or None if the post is not there."""
    with db.connect() as con:
        if not _visible(con, post_id):
            return None
        if value == 0:
            con.execute("DELETE FROM votes WHERE post_id = ? AND user_id = ?", (post_id, user["id"]))
        else:
            con.execute("INSERT INTO votes (post_id, user_id, value) VALUES (?, ?, ?) "
                        "ON CONFLICT(post_id, user_id) DO UPDATE SET value = excluded.value", (post_id, user["id"], value))
        return con.execute("SELECT COALESCE(SUM(value), 0) FROM votes WHERE post_id = ?", (post_id,)).fetchone()[0]


def add_comment(post_id: int, user: dict, body: str) -> int | None:
    body = (body or "").strip()
    if not body:
        raise FeedError("Write a comment first.")
    with db.connect() as con:
        if not _visible(con, post_id):
            return None
        return con.execute("INSERT INTO comments (post_id, user_id, created_at, body) VALUES (?, ?, ?, ?)",
                           (post_id, user["id"], db.now_iso(), body[: config.MAX_COMMENT])).lastrowid


def delete_comment(comment_id: int, user: dict) -> bool | None:
    """True if deleted, False if not allowed, None if there is no such comment."""
    with db.connect() as con:
        row = con.execute("SELECT user_id FROM comments WHERE id = ?", (comment_id,)).fetchone()
        if not row:
            return None
        if user["role"] != "admin" and user["id"] != row["user_id"]:
            return False
        con.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
        return True


def delete_post(post_id: int, user: dict) -> bool | None:
    """True if deleted, False if not allowed, None if there is no such post."""
    with db.connect() as con:
        row = con.execute("SELECT user_id, image FROM posts WHERE id = ?", (post_id,)).fetchone()
        if not row:
            return None
        if user["role"] != "admin" and user["id"] != row["user_id"]:
            return False
        con.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    if row["image"] and (path := image_path(row["image"])):
        path.unlink(missing_ok=True)
    return True


def moderate(post_id: int, **flags: bool | None) -> bool:
    """Admin: set pinned / verified / hidden. Returns False if there is no such post."""
    sets = [(k, int(v)) for k, v in flags.items() if v is not None and k in ("pinned", "verified", "hidden")]
    with db.connect() as con:
        if not con.execute("SELECT 1 FROM posts WHERE id = ?", (post_id,)).fetchone():
            return False
        for k, v in sets:
            con.execute(f"UPDATE posts SET {k} = ? WHERE id = ?", (v, post_id))
    return True
