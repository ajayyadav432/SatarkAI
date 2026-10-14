"""Load the trained models and produce a probability together with its exact reasons."""
from __future__ import annotations

import json
import math
from functools import lru_cache

import joblib
import numpy as np

from app import config
from app.analysis import shap_explain, textprep
from app.analysis.url_scorecard import LABELS as URL_LABELS, score_url

TEXT_MODEL_FILE = "text_model.joblib"
URL_MODEL_FILE = "url_model.joblib"

# Which text model serves which channel.
CHANNEL_MODEL = {"sms": "sms", "social": "sms", "email": "email"}
MODEL_TRAINED_ON = {
    "sms": "English SMS (UK / Singapore, 2006-2012)",
    "email": "English e-mail (older spam, phishing and business mail)",
}


@lru_cache(maxsize=1)
def _text_models() -> dict | None:
    path = config.MODELS_DIR / TEXT_MODEL_FILE
    return joblib.load(path) if path.exists() else None


@lru_cache(maxsize=1)
def _url_model() -> dict | None:
    path = config.MODELS_DIR / URL_MODEL_FILE
    return joblib.load(path) if path.exists() else None


@lru_cache(maxsize=1)
def metrics() -> dict | None:
    path = config.MODELS_DIR / "metrics.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def status() -> dict:
    return {"text_model": _text_models() is not None, "url_model": _url_model() is not None,
            "metrics": metrics() is not None}


def url_threshold() -> float:
    model = _url_model()
    return float(model.get("threshold", 0.5)) if model else 0.5


def _display(term: str) -> str:
    return " ".join(textprep.PLACEHOLDERS.get(w, w) for w in term.split(" "))


def predict_text(text: str, channel: str) -> dict:
    """Scam probability for a message, or the reason the model was not used.

    Contribution of a term = its TF-IDF value x its learned weight. The contributions and
    the intercept add up to the model's log-odds exactly.
    """
    models = _text_models()
    key = CHANNEL_MODEL.get(channel)
    if models is None or key is None or key not in models:
        return {"used": False, "reason": "Text model is not available. Run ./run.sh train."
                if models is None else "No text model for this channel."}
    model = models[key]
    base = {"model": key, "trained_on": MODEL_TRAINED_ON[key]}

    toks = textprep.content_tokens(text)
    gate = model["gate"]
    known = sum(t in model["vocab_words"] for t in toks) / len(toks) if toks else 0.0
    base.update({"known_word_share": round(known, 2), "words": len(toks)})
    if len(toks) < gate["min_tokens"]:
        return {**base, "used": False,
                "reason": "Too few words for the text model to judge."}
    if known < gate["min_known_fraction"]:
        return {**base, "used": False,
                "reason": f"Only {known:.0%} of the words are known to the text model, which was trained on "
                          f"{MODEL_TRAINED_ON[key]}. It was skipped instead of guessing. "
                          "Rules and link checks still apply."}

    vec = model["vectoriser"]
    row = vec.transform([text[: config.MAX_TEXT_CHARS]])
    coef = model["coef"]
    contrib = row.data * coef[row.indices]
    logit = float(model["intercept"] + contrib.sum())
    prob = 1.0 / (1.0 + math.exp(-logit))
    names = vec.get_feature_names_out()
    order = np.argsort(contrib)
    terms = [{"term": str(names[row.indices[i]]), "display": _display(str(names[row.indices[i]])),
              "contribution": round(float(contrib[i]), 3)} for i in order[::-1] if contrib[i] > 0.02][:10]
    safe_terms = [{"term": str(names[row.indices[i]]), "display": _display(str(names[row.indices[i]])),
                   "contribution": round(float(contrib[i]), 3)} for i in order if contrib[i] < -0.02][:6]
    shap = shap_explain.explain_text(row, model, key, names)
    if shap:
        for f in shap["features"]:
            f["display"] = _display(f["feature"])
    highlight = []
    for t in terms:
        for w in t["term"].split(" "):
            if w not in textprep.PLACEHOLDERS and w not in highlight:
                highlight.append(w)
    return {**base, "used": True, "shap": shap, "probability": round(prob, 4), "log_odds": round(logit, 3),
            "intercept": round(float(model["intercept"]), 3), "scam_terms": terms,
            "safe_terms": safe_terms, "highlight_words": highlight}


def predict_url(info) -> dict:
    """Phishing probability for a parsed URL with the scorecard points behind it."""
    model = _url_model()
    if model is None:
        return {"used": False, "reason": "URL model is not available. Run ./run.sh train."}
    if not info.valid:
        return {"used": False, "reason": "Not a valid link."}
    if info.trusted:
        return {"used": False, "reason": "Official domain: the model is not needed."}
    res = score_url(info, model)
    shap = shap_explain.explain_url(info, model)
    if shap:   # readable label for each feature, also when the feature is "not present"
        labels = {p["feature"]: p["label"] for p in res["parts"]}
        for f in shap["features"]:
            lab = labels.get(f["feature"])
            f["display"] = lab if lab else "Not: " + URL_LABELS[f["feature"]][0].lower() + URL_LABELS[f["feature"]][1:]
    parts = [p for p in res["parts"] if p["label"]]
    up = sorted((p for p in parts if p["points"] > 0.05), key=lambda p: -p["points"])[:6]
    down = sorted((p for p in parts if p["points"] < -0.05), key=lambda p: p["points"])[:4]
    return {"used": True, "probability": round(res["probability"], 4), "log_odds": round(res["logit"], 3),
            "intercept": round(res["intercept"], 3), "threshold": url_threshold(),
            "raises_risk": up, "lowers_risk": down, "all_points": res["parts"], "shap": shap}
