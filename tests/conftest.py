"""Shared fixtures. Every test run uses its own temporary database, never the real history."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Must be set before app.config is imported.
_TMP = tempfile.mkdtemp(prefix="satark-test-")
os.environ["SATARK_DB"] = str(Path(_TMP) / "test.db")

import pytest  # noqa: E402

from app import config, db  # noqa: E402
from app.analysis import models  # noqa: E402

MODELS_READY = all(models.status().values())
needs_models = pytest.mark.skipif(not MODELS_READY, reason="models not trained: run ./run.sh train")


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    """An empty database for one test."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "cases.db")
    db.init_db()
    return tmp_path / "cases.db"


@pytest.fixture()
def client(fresh_db):
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        yield c


# Hand-written examples used by several tests.
SCAM_KYC = "Dear customer, your SBI account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.xyz/login"
SCAM_BILL = ("Dear Consumer, your electricity power will be disconnected tonight at 9.30 pm because your previous month "
             "bill was not updated. Please contact our electricity officer 9876543210 immediately.")
SCAM_LOTTERY = ("Congratulations! You have won Rs 25,00,000 in KBC lucky draw. To claim your prize pay processing fee "
                "Rs 5,000 to kbcoffice@ybl. Call 8765432109")
SCAM_ARREST = ("This is Inspector Sharma from CBI. Your Aadhaar is linked to a money laundering case. You are under "
               "digital arrest. Join the video call now and do not tell anyone. Transfer Rs 2,00,000 for verification.")
SCAM_HINGLISH = "Priya grahak, aapka HDFC khata band ho jayega. Turant KYC update karein, link par click karein: hdfc-kyc.co.in/verify"
SCAM_HINDI = "प्रिय ग्राहक, आपका एसबीआई खाता आज बंद हो जाएगा। तुरंत केवाईसी अपडेट करने के लिए नीचे दिए गए लिंक पर क्लिक करें: https://sbi-kyc.in/update"
OK_OTP = "482913 is your OTP for transaction of INR 2,499.00 at AMAZON. Do not share it with anyone. -HDFC Bank"
OK_DEBIT = "Rs 5,000.00 debited from A/c XX1234 on 12-Oct-26. Avl Bal Rs 12,340.55. If not you, call 18001234567 -SBI"
OK_CHAT = "Hey are we still meeting for lunch tomorrow at 1? Let me know"
OK_ORDER = "Your Amazon order #402-1234567 has been shipped and will arrive tomorrow. Track: https://www.amazon.in/gp/your-account/order-details"
