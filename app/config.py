"""Central settings. Change the app name here and it changes everywhere."""
import os
from pathlib import Path

APP_NAME = "SatarkAI"
APP_TAGLINE = "Phishing, scam message and malicious URL detection"
PROBLEM_STATEMENT = "SKIT025"

ROOT = Path(__file__).resolve().parent.parent
APP_DIR = ROOT / "app"
KNOWLEDGE_DIR = APP_DIR / "data"
STATIC_DIR = APP_DIR / "static"
MODELS_DIR = ROOT / "models"
RAW_DATA_DIR = ROOT / "data" / "raw"

# Tests point this at a temporary file so they never touch real history.
DB_PATH = Path(os.environ.get("SATARK_DB", ROOT / "data" / "history.db"))

# Screenshots attached to feed posts. Tests point this at a temporary folder.
UPLOAD_DIR = Path(os.environ.get("SATARK_UPLOADS", ROOT / "data" / "uploads"))
FONTS_DIR = KNOWLEDGE_DIR / "fonts"   # Noto Sans (+ Devanagari) for PDF reports

HOST = os.environ.get("SATARK_HOST", "127.0.0.1")
PORT = int(os.environ.get("SATARK_PORT", "8000"))


def env(key: str, default: str | None = None) -> str | None:
    """A setting from the environment, else from the project's .env file (never committed)."""
    if os.environ.get(key):
        return os.environ[key]
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if k.strip() == key and v.strip():
                    return v.strip().strip('"').strip("'")
    except OSError:
        pass
    return default


# Automatic checking (phone app, inbox watcher, browser extension)
LAN_MODE = HOST not in ("127.0.0.1", "localhost", "::1")   # server reachable from other devices
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
# Public hosting (Vercel): nobody is "on the laptop", so laptop-only rights (one-click admin, History
# without login, ingest without pairing code) are switched off. The host may make every visitor look
# like 127.0.0.1, so the address alone cannot be trusted there.
PUBLIC = os.environ.get("SATARK_PUBLIC") == "1"
SOURCES_AUTO = ["sms-app", "email-watch", "gmail-web"]

# Accounts and the community feed
SESSION_COOKIE = "satark_session"
SESSION_DAYS = 7
PASSWORD_MIN = 8
MAX_POST_TITLE = 150
MAX_POST_BODY = 5_000
MAX_COMMENT = 2_000
MAX_IMAGE_BYTES = 3 * 1024 * 1024
FEED_PAGE_SIZE = 20

# Input limits
MAX_TEXT_CHARS = 20_000
MAX_SENDER_CHARS = 320
MAX_URLS_PER_MESSAGE = 25
MAX_URL_CHARS = 2_048
MAX_BULK_ROWS = 500
MAX_BULK_BYTES = 2 * 1024 * 1024

# Risk levels: (name, lowest score in the level)
RISK_LEVELS = [
    ("Safe", 0),
    ("Low", 20),
    ("Medium", 40),
    ("High", 60),
    ("Critical", 80),
]

# Only messages scoring at least this much are saved to History (and raise live alerts).
# Lower scores are still analysed and shown, but not stored.
SAVE_MIN_SCORE = 50


def worth_saving(result: dict) -> bool:
    return result["score"] >= SAVE_MIN_SCORE


# Recommend blocking a sender after this many risky (saved) messages, all time.
BLOCK_AFTER = 3


# The warning page asks for confirmation from this level upwards.
WARN_FROM_LEVEL = "Medium"

CHANNELS = ["sms", "email", "social", "url"]
CASE_STATUSES = ["new", "reviewed", "confirmed_scam", "false_positive"]
