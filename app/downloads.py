"""Files offered on the home page: the Android app (APK) and the Chrome extension (zip).

- The APK is the latest build in android/ (`cd android && ./gradlew assembleDebug`); it is not stored in git.
- The extension zip is made from the extension/ folder on every request, so it always matches the code.
"""
from __future__ import annotations

import io
import json
import time
import zipfile

from app import config

APK_DIR = config.ROOT / "android" / "app" / "build" / "outputs" / "apk" / "debug"
APK_NAME = "satarkai-sms-guard.apk"
EXT_DIR = config.ROOT / "extension"
EXT_NAME = "satarkai-link-guard.zip"


def apk_path():
    p = APK_DIR / "app-debug.apk"
    return p if p.is_file() else None


def apk_info() -> dict:
    p = apk_path()
    if not p:
        return {"available": False, "build": "cd android && ./gradlew assembleDebug"}
    version = None
    try:
        meta = json.loads((APK_DIR / "output-metadata.json").read_text(encoding="utf-8"))
        version = meta["elements"][0].get("versionName")
    except (OSError, ValueError, KeyError, IndexError):
        pass
    st = p.stat()
    return {"available": True, "file": APK_NAME, "size": st.st_size, "version": version,
            "built": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))}


def _ext_files():
    return sorted(f for f in EXT_DIR.rglob("*") if f.is_file() and not f.name.startswith("."))


def extension_info() -> dict:
    manifest = json.loads((EXT_DIR / "manifest.json").read_text(encoding="utf-8"))
    return {"available": True, "file": EXT_NAME, "version": manifest.get("version"),
            "size": sum(f.stat().st_size for f in _ext_files())}


def extension_zip() -> bytes:
    """The extension folder as a zip with one top folder, ready for chrome://extensions > Load unpacked."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in _ext_files():
            z.write(f, "satarkai-link-guard/" + f.relative_to(EXT_DIR).as_posix())
    return buf.getvalue()
