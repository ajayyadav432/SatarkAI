"""SHAP explanations for the two linear models (exact, no sampling).

For a linear model in log-odds space with a background of training data, the SHAP values are
(interventional / independent features, as shap.LinearExplainer computes them):

    shap_i     = w_i * (x_i - mean_i)
    base value = b + sum_i w_i * mean_i                 (an "average" training example)
    base value + sum_i shap_i = b + sum_i w_i * x_i     (this message's log-odds), exactly

Features absent from a message also have SHAP values (w_i * (0 - mean_i)): not containing a word that
usually appears in safe messages pushes the score up a little. They are included in the totals and
the strongest ones are listed.

The background (feature means of the training split) is written by `python -m ml.shap_background`.
"""
from __future__ import annotations

import json
import math
from functools import lru_cache

import joblib
import numpy as np

from app import config
from app.analysis.url_scorecard import BINS, FEATURES, _OFFSETS, bin_index, tld_risk

SHOW = 10          # features shown one by one in the waterfall; the rest are summed as "other features"
MIN_SHOW = 0.01    # smaller contributions go into "other features"


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


@lru_cache(maxsize=1)
def _background():
    p = config.MODELS_DIR / "shap_background.joblib"
    return joblib.load(p) if p.exists() else None


@lru_cache(maxsize=1)
def summary() -> dict | None:
    p = config.MODELS_DIR / "shap_summary.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


_ABSENT_ORDER: dict[tuple[str, int], np.ndarray] = {}


def _absent_order(channel: str, coef: np.ndarray, mean: np.ndarray) -> np.ndarray:
    """The 300 features with the largest |w_i * mean_i|: the absent features that can matter most.
    Computed once per model (sorting 135,000 e-mail features on every message would be wasteful)."""
    key = (channel, len(coef))
    if key not in _ABSENT_ORDER:
        _ABSENT_ORDER[key] = np.argsort(-np.abs(coef * mean))[:300]
    return _ABSENT_ORDER[key]


def available() -> bool:
    return _background() is not None


def _pack(base: float, items: list[dict], other_value: float, other_count: int, output: float) -> dict:
    """Waterfall-ready result. items are sorted by |shap|, largest first."""
    return {
        "method": "SHAP (exact, linear model, training-data background)",
        "base_value": round(base, 4), "base_probability": round(_sigmoid(base), 4),
        "output_value": round(output, 4), "probability": round(_sigmoid(output), 4),
        "features": items,
        "other": {"count": other_count, "shap": round(other_value, 4)},
        "units": "log-odds",
    }


def explain_text(row, model: dict, channel: str, names) -> dict | None:
    """SHAP values for one message. row: 1 x F sparse TF-IDF vector from the model's vectoriser."""
    bg = _background()
    if bg is None or channel not in bg.get("text", {}):
        return None
    mean = bg["text"][channel]["mean"].astype(np.float64)
    coef = np.asarray(model["coef"], dtype=np.float64)
    b = float(model["intercept"])
    if len(mean) != len(coef):
        return None   # background belongs to an older model: run python -m ml.shap_background

    base = b + float(coef @ mean)
    idx, val = row.indices, row.data.astype(np.float64)
    shap_present = coef[idx] * (val - mean[idx])
    # Absent features: shap = -w_i * mean_i. Their total is everything minus the present ones.
    absent_all = -(coef * mean)
    absent_total = float(absent_all.sum() - absent_all[idx].sum())
    output = b + float(coef[idx] @ val)

    items = [{"feature": str(names[i]), "value": round(float(v), 4), "present": True, "shap": float(s)}
             for i, v, s in zip(idx, val, shap_present)]
    # The strongest absent features (largest |w_i * mean_i|) that are not in the message.
    present = set(idx.tolist())
    for i in _absent_order(channel, coef, mean):
        if int(i) not in present and abs(absent_all[i]) >= MIN_SHOW:
            items.append({"feature": str(names[i]), "value": 0.0, "present": False, "shap": float(absent_all[i])})
    items.sort(key=lambda x: -abs(x["shap"]))
    shown = [x for x in items if abs(x["shap"]) >= MIN_SHOW][:SHOW]
    total = float(shap_present.sum()) + absent_total
    other = total - sum(x["shap"] for x in shown)
    other_count = len(coef) - len(shown)
    for x in shown:
        x["shap"] = round(x["shap"], 4)
    return _pack(base, shown, other, other_count, output) | {"total_features": int(len(coef)), "check": round(base + total - output, 9)}


def explain_url(info, model: dict) -> dict | None:
    """SHAP values for one link, one value per original feature (sum of its one-hot bin columns)."""
    bg = _background()
    if bg is None or "url" not in bg:
        return None
    mean = np.asarray(bg["url"]["mean"], dtype=np.float64)
    coef = np.asarray(model["coef"], dtype=np.float64)
    if len(mean) != len(coef):
        return None
    b = float(model["intercept"])
    base = b + float(coef @ mean)
    risk, _ = tld_risk(info, model)
    items, output = [], b
    for name in FEATURES:
        value = risk if name == "tld_risk" else info.features.get(name, 0)
        j = int(bin_index(name, [value])[0])
        off, k = _OFFSETS[name], len(BINS[name])
        w = coef[off:off + k]
        x = np.zeros(k)
        x[j] = 1.0
        s = float(w @ (x - mean[off:off + k]))
        output += float(w[j])
        shown = round(float(value), 2) if not float(value).is_integer() else int(value)
        items.append({"feature": name, "value": shown, "present": True, "shap": s})
    items.sort(key=lambda x: -abs(x["shap"]))
    total = sum(x["shap"] for x in items)
    shown = [x for x in items if abs(x["shap"]) >= MIN_SHOW][:SHOW]
    other = total - sum(x["shap"] for x in shown)
    for x in shown:
        x["shap"] = round(x["shap"], 4)
    return _pack(base, shown, other, len(items) - len(shown), output) | {"total_features": len(items), "check": round(base + total - output, 9)}
