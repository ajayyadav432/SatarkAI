"""Download the public datasets and record exactly what was downloaded.

Writes data/raw/<name>/... and data/raw/manifest.json (URL, size, SHA-256, time).
Run:  python -m ml.download_data
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"

DATASETS = [
    {
        "name": "sms_spam",
        "title": "SMS Spam Collection",
        "host": "UCI Machine Learning Repository (dataset 228)",
        "page": "https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
        "url": "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
        "file": "sms_spam.zip",
        "unzip": True,
    },
    {
        "name": "phishing_email",
        "title": "Phishing Email Dataset",
        "host": "Hugging Face (zefang-liu/phishing-email-dataset)",
        "page": "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset",
        "url": "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv",
        "file": "Phishing_Email.csv",
        "unzip": False,
    },
    {
        "name": "phiusiil",
        "title": "PhiUSIIL Phishing URL Dataset",
        "host": "UCI Machine Learning Repository (dataset 967)",
        "page": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
        "url": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
        "file": "phiusiil.zip",
        "unzip": True,
    },
    {
        "name": "web_page_phishing",
        "title": "Web page phishing URL dataset (train)",
        "host": "Hugging Face (pirocheto/phishing-url)",
        "page": "https://huggingface.co/datasets/pirocheto/phishing-url",
        "url": "https://huggingface.co/datasets/pirocheto/phishing-url/resolve/main/data/train.parquet",
        "file": "train.parquet",
        "unzip": False,
    },
    {
        "name": "web_page_phishing",
        "title": "Web page phishing URL dataset (test)",
        "host": "Hugging Face (pirocheto/phishing-url)",
        "page": "https://huggingface.co/datasets/pirocheto/phishing-url",
        "url": "https://huggingface.co/datasets/pirocheto/phishing-url/resolve/main/data/test.parquet",
        "file": "test.parquet",
        "unzip": False,
    },
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "satarkai-hackathon/1.0"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
    tmp.replace(dest)


def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    manifest_path = RAW / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    failed = []

    for ds in DATASETS:
        folder = RAW / ds["name"]
        folder.mkdir(parents=True, exist_ok=True)
        dest = folder / ds["file"]
        key = f"{ds['name']}/{ds['file']}"

        if dest.exists() and key in manifest:
            print(f"[skip] {key} already downloaded")
        else:
            print(f"[get ] {ds['url']}")
            try:
                download(ds["url"], dest)
            except Exception as exc:  # report and continue with the other datasets
                print(f"[FAIL] {key}: {exc}")
                failed.append(key)
                continue
            manifest[key] = {
                "title": ds["title"],
                "host": ds["host"],
                "page": ds["page"],
                "url": ds["url"],
                "bytes": dest.stat().st_size,
                "sha256": sha256(dest),
                "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            }

        if ds["unzip"] and dest.exists():
            with zipfile.ZipFile(dest) as z:
                root = folder.resolve()
                for member in z.infolist():
                    # Refuse archive entries that would land outside the folder.
                    target = (folder / member.filename).resolve()
                    if root != target and root not in target.parents:
                        raise RuntimeError(f"unsafe path in zip: {member.filename}")
                z.extractall(folder)
            manifest[key]["zip_members"] = [m.filename for m in zipfile.ZipFile(dest).infolist()]

        manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"\nmanifest: {manifest_path}")
    for key, info in manifest.items():
        print(f"  {key}: {info['bytes']:,} bytes  sha256={info['sha256'][:16]}...")
    if failed:
        print("\nFAILED:", ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
