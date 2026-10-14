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
SOURCES_AUTO = ["sms-app", "email-watch", "gmail-web"]

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

# The warning page asks for confirmation from this level upwards.
WARN_FROM_LEVEL = "Medium"

CHANNELS = ["sms", "email", "social", "url"]
CASE_STATUSES = ["new", "reviewed", "confirmed_scam", "false_positive"]
