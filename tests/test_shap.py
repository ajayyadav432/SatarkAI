"""SHAP explanations: exact additivity, equality with the official shap library, and the background."""
import json
import warnings

import joblib
import numpy as np
import pytest

from app import config
from app.analysis import shap_explain
from app.analysis.pipeline import analyze
from app.analysis.url_features import parse_url
from app.analysis.url_scorecard import BINS, FEATURES, _OFFSETS, bin_index, tld_risk
from tests.conftest import OK_CHAT, OK_ORDER, SCAM_ARREST, SCAM_KYC, SCAM_LOTTERY, needs_models

pytestmark = [needs_models, pytest.mark.skipif(not shap_explain.available(),
                                               reason="SHAP background missing: python -m ml.shap_background")]

EMAIL = ("Dear user, your mailbox storage is full. Verify your account within 24 hours or it will be "
         "suspended. Click here to verify: http://mail-verify-account.top/login")
URLS = ["http://sbi-kyc-update.xyz/login", "https://www.wikipedia.org/wiki/Phishing",
        "http://paypa1.com/signin?account=verify", "http://192.168.10.5/sbi/netbanking/login.php"]


@pytest.mark.parametrize("text,channel", [(SCAM_KYC, "sms"), (SCAM_LOTTERY, "sms"), (OK_CHAT, "sms"),
                                          (SCAM_ARREST, "social"), (EMAIL, "email")])
def test_text_shap_adds_up_to_the_model_output(text, channel):
    ml = analyze(text, channel=channel)["ml_text"]
    if not ml.get("used"):
        pytest.skip("text model not used for this message")
    s = ml["shap"]
    assert abs(s["check"]) < 1e-9                                   # base + all SHAP values == log-odds
    shown = sum(f["shap"] for f in s["features"]) + s["other"]["shap"]
    assert abs(s["base_value"] + shown - s["output_value"]) < 1e-3   # also with the rounded, shown values
    assert abs(s["output_value"] - ml["log_odds"]) < 1e-3
    assert abs(s["probability"] - ml["probability"]) < 1e-3
    assert [abs(f["shap"]) for f in s["features"]] == sorted((abs(f["shap"]) for f in s["features"]), reverse=True)


@pytest.mark.parametrize("url", URLS)
def test_url_shap_adds_up_to_the_model_output(url):
    r = analyze(url, channel="url")
    ml = r["urls"][0]["ml"]
    if not ml.get("used"):
        pytest.skip("URL model not used (official domain)")
    s = ml["shap"]
    assert abs(s["check"]) < 1e-9
    assert abs(s["output_value"] - ml["log_odds"]) < 1e-3
    assert all(f["display"] for f in s["features"])


@pytest.mark.parametrize("channel,text", [("sms", SCAM_KYC), ("sms", OK_ORDER), ("email", EMAIL)])
def test_text_shap_equals_shap_library(channel, text):
    shap = pytest.importorskip("shap")
    model = joblib.load(config.MODELS_DIR / "text_model.joblib")[channel]
    coef, b = model["coef"].astype(np.float64), float(model["intercept"])
    mean = shap_explain._background()["text"][channel]["mean"].astype(np.float64)
    x = model["vectoriser"].transform([text])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ex = shap.LinearExplainer((coef, b), (mean, np.eye(1)), feature_perturbation="interventional")
        lib = np.asarray(ex.shap_values(x.toarray())).ravel()
    names = list(model["vectoriser"].get_feature_names_out())
    ours = shap_explain.explain_text(x.tocsr(), model, channel, np.array(names))
    assert abs(float(np.ravel(ex.expected_value)[0]) - ours["base_value"]) < 1e-3
    for f in ours["features"]:
        assert abs(f["shap"] - lib[names.index(f["feature"])]) < 1e-3, f["feature"]
    assert abs(lib.sum() - (ours["output_value"] - ours["base_value"])) < 1e-3


@pytest.mark.parametrize("url", URLS)
def test_url_shap_equals_shap_library(url):
    shap = pytest.importorskip("shap")
    model = joblib.load(config.MODELS_DIR / "url_model.joblib")
    coef, b = np.asarray(model["coef"], dtype=np.float64), float(model["intercept"])
    mean = np.asarray(shap_explain._background()["url"]["mean"], dtype=np.float64)
    info = parse_url(url)
    x = np.zeros(len(coef))
    risk, _ = tld_risk(info, model)
    for name in FEATURES:
        value = risk if name == "tld_risk" else info.features.get(name, 0)
        x[_OFFSETS[name] + int(bin_index(name, [value])[0])] = 1.0
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ex = shap.LinearExplainer((coef, b), (mean, np.eye(1)), feature_perturbation="interventional")
        lib = np.asarray(ex.shap_values(x.reshape(1, -1))).ravel()
    ours = shap_explain.explain_url(info, model)
    for f in ours["features"]:   # ours = one value per feature = sum of its one-hot bin columns
        off, k = _OFFSETS[f["feature"]], len(BINS[f["feature"]])
        assert abs(f["shap"] - lib[off:off + k].sum()) < 1e-3, f["feature"]
    assert abs(float(np.ravel(ex.expected_value)[0]) - ours["base_value"]) < 1e-3


def test_background_is_the_training_split():
    summary = shap_explain.summary()
    metrics = json.loads((config.MODELS_DIR / "metrics.json").read_text())
    for ch in ("sms", "email"):
        m = metrics["text_model"]["channels"][ch]
        assert summary["text"][ch]["background_rows"] == m["train_rows"]
        assert summary["text"][ch]["test_accuracy_reproduced"] == m["test"]["accuracy"]
    assert summary["url"]["background_rows"] == metrics["url_model"]["train_rows"]
    assert summary["url"]["test_accuracy_reproduced"] == metrics["url_model"]["test"]["all"]["accuracy"]


def test_api_returns_shap_and_global_importance(client):
    r = client.post("/api/analyze", json={"text": SCAM_KYC, "channel": "sms", "save": False}).json()
    assert r["ml_text"]["shap"]["features"] and r["urls"][0]["ml"]["shap"]["features"]
    card = client.get("/api/model-card").json()
    assert card["shap"]["text"]["sms"]["top_features"] and card["shap"]["url"]["top_features"]
