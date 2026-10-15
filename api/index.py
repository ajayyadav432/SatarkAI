"""Vercel entry point: the whole SatarkAI app (API + web pages) as one Python function.

Settings for public hosting; see app/cloud.py for what happens at start-up.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("SATARK_PUBLIC", "1")
os.environ.setdefault("SATARK_DB", "/tmp/satarkai/history.db")
os.environ.setdefault("SATARK_UPLOADS", "/tmp/satarkai/uploads")
os.environ.setdefault("SATARK_NO_MAILWATCH", "1")
os.environ.setdefault("SATARK_SEED", "1")
os.environ.setdefault("TLDEXTRACT_CACHE", "/tmp/satarkai/tldextract")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import cloud  # noqa: E402

cloud.prepare()

from app.main import app  # noqa: E402,F401
