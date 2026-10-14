"""Trained models: they load, their reported metrics clear a floor, and explanations are exact."""
import json
import math

import pytest

from app import config
from app.analysis import models
from app.analysis.url_features import parse_url
from tests.conftest import needs_models

pytestmark = needs_models


@pytest.fixture(scope="module")
def M():
    return json.loads((config.MODELS_DIR / "metrics.json").read_text())


def test_models_load():
    assert models.status() == {"text_model": True, "url_model": True, "metrics": True}
    assert 0.5 <= models.url_threshold() <= 0.95


def test_text_model_metrics_floor(M):
    for name, floor_acc, floor_recall in (("sms", 0.97, 0.85), ("email", 0.96, 0.92)):
        t = M["text_model"]["channels"][name]["test"]
        assert t["accuracy"] >= floor_acc and t["recall"] >= floor_recall and t["precision"] >= 0.95
        assert t["false_positive_rate"] <= 0.02
        assert t["accuracy"] > t["majority_class_accuracy"] + 0.05      # clearly better than guessing
        c = t["confusion"]
        assert c["tp"] + c["fn"] == t["n_scam"] and sum(c.values()) == t["n"]


def test_text_models_do_not_transfer_across_channels(M):
    """Documented finding: this is the reason for one model per channel."""
    for name in ("sms", "email"):
        assert M["text_model"]["channels"][name]["tested_on_other_channel"]["accuracy"] < 0.75


def test_url_model_metrics_floor(M):
    u = M["url_model"]
    assert u["test"]["all"]["roc_auc"] >= 0.80
    assert u["test"]["all"]["precision"] >= 0.90
    assert u["test"]["all"]["false_positive_rate"] <= 0.05
    assert u["test"]["web_page_phishing"]["false_positive_rate"] <= 0.08
    assert u["sanity"]["hand_written_legitimate_urls"]["false_positive_rate"] <= 0.05


def test_train_and_test_never_share_rows(M):
    for name in ("sms", "email"):
        c = M["text_model"]["channels"][name]
        used = M["datasets"]["sms_spam" if name == "sms" else "phishing_email"]["rows_used"]
        assert c["train_rows"] + c["test_rows"] == used
    assert "by registered domain" in M["url_model"]["split"]


def test_metrics_file_is_complete(M):
    assert set(M["datasets"]) == {"sms_spam", "phishing_email", "phiusiil", "web_page_phishing"}
    for d in M["datasets"].values():
        assert d["rows_used"] <= d["rows_raw"] and d["notes"]
    legit = M["datasets"]["phiusiil"]["structure_by_class"]["legitimate"]
    assert legit["has_path_pct"] == 0.0 and legit["https_pct"] == 100.0     # the bias that was designed around
    assert M["downloads"], "download manifest missing"
    for info in M["downloads"].values():
        assert len(info["sha256"]) == 64


def test_text_explanation_adds_up_exactly():
    r = models.predict_text("WINNER!! You have won a 900 pound prize reward! To claim call 09061701461 now. Valid 12 hours only.", "sms")
    assert r["used"] and r["probability"] > 0.9
    assert math.isclose(1 / (1 + math.exp(-r["log_odds"])), r["probability"], abs_tol=1e-3)
    assert r["scam_terms"] and all(t["contribution"] > 0 for t in r["scam_terms"])


def test_text_model_separates_obvious_cases():
    spam = models.predict_text("URGENT! You have won a free prize. Call 09061701461 now to claim your cash reward. Txt STOP to 87121", "sms")
    ham = models.predict_text("Ok I will be home late tonight, see you at dinner then. Sorry about that", "sms")
    assert spam["probability"] > 0.9 and ham["probability"] < 0.1


def test_text_model_gate():
    assert models.predict_text("आपका खाता बंद हो जाएगा तुरंत केवाईसी अपडेट करें", "sms")["used"] is False
    assert models.predict_text("bhai kal college aa raha hai kya mujhe bhi bata dena", "sms")["used"] is False
    assert models.predict_text("ok", "sms")["used"] is False
    assert models.predict_text("anything", "url")["used"] is False


def test_url_scorecard_adds_up_exactly():
    info = parse_url("http://secure-login.account-verify-update.top/signin/confirm.php?id=123")
    r = models.predict_url(info)
    total = r["intercept"] + sum(p["points"] for p in r["all_points"])
    assert math.isclose(total, r["log_odds"], abs_tol=0.02)
    assert math.isclose(1 / (1 + math.exp(-r["log_odds"])), r["probability"], abs_tol=1e-3)
    assert r["probability"] >= r["threshold"]


def test_url_model_sanity():
    def p(u):
        return models.predict_url(parse_url(u))

    assert p("https://en.wikipedia.org/wiki/Phishing")["probability"] < models.url_threshold()
    assert p("https://github.com/scikit-learn/scikit-learn/issues")["probability"] < models.url_threshold()
    assert p("https://www.onlinesbi.sbi/retail/login.htm")["used"] is False       # official domain: model not needed
    assert p("https://")["used"] is False


def test_scheme_and_www_do_not_change_the_url_score():
    """These were label leaks in the training data, so they must not be features."""
    variants = ["http://example-shop.com/a", "https://example-shop.com/a", "https://www.example-shop.com/a"]
    probs = {round(models.predict_url(parse_url(v))["probability"], 6) for v in variants}
    assert len(probs) == 1
