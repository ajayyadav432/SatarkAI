"""Downloads offered on the home page: the Chrome extension (zip) and the Android app (APK)."""
import io
import json
import zipfile

from app import config, downloads


def test_extension_zip_is_complete(client):
    r = client.get("/download/" + downloads.EXT_NAME)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert "attachment" in r.headers["content-disposition"]
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    for f in ("manifest.json", "background.js", "content.js", "gmail.js", "popup.html", "popup.js", "icons/icon128.png"):
        assert "satarkai-link-guard/" + f in names, f
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(r.content)).read("satarkai-link-guard/manifest.json"))
    assert manifest["version"] == client.get("/api/downloads").json()["extension"]["version"]


def test_apk_served_when_built(client, tmp_path, monkeypatch):
    (tmp_path / "app-debug.apk").write_bytes(b"PK fake apk")
    (tmp_path / "output-metadata.json").write_text(json.dumps({"elements": [{"versionName": "9.9"}]}))
    monkeypatch.setattr(downloads, "APK_DIR", tmp_path)
    info = client.get("/api/downloads").json()["apk"]
    assert info["available"] and info["version"] == "9.9" and info["size"] == 11
    r = client.get("/download/" + downloads.APK_NAME)
    assert r.status_code == 200 and r.content == b"PK fake apk"
    assert r.headers["content-type"] == "application/vnd.android.package-archive"


def test_apk_missing_is_explained(client, tmp_path, monkeypatch):
    monkeypatch.setattr(downloads, "APK_DIR", tmp_path / "nothing")
    assert client.get("/api/downloads").json()["apk"] == {"available": False, "build": "cd android && ./gradlew assembleDebug"}
    r = client.get("/download/" + downloads.APK_NAME)
    assert r.status_code == 404 and "gradlew" in r.json()["detail"]


def test_lan_visitors_can_download_but_not_reach_history(anon, monkeypatch):
    monkeypatch.setattr(config, "LAN_MODE", True)
    assert anon.get("/download/" + downloads.EXT_NAME).status_code == 200
    assert anon.get("/api/downloads").status_code == 200
    assert anon.get("/download/../api/cases").status_code in (401, 404)
