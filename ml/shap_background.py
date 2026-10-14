"""SHAP background for the trained models. Run once after training:  python -m ml.shap_background

Both models are linear (logistic regression), so SHAP values have an exact closed form
(interventional / independent features, as shap.LinearExplainer computes them):

    shap_i     = w_i * (x_i - mean_i)          mean_i = average of feature i over the TRAINING data
    base value = b + sum_i w_i * mean_i        (log-odds of an "average" training example)
    base value + sum_i shap_i = model output   (log-odds), exactly

This script rebuilds the exact training and test splits used by ml/train.py (same loaders, same seed),
checks that the saved models still give the test accuracy recorded in models/metrics.json, and writes:

    models/shap_background.joblib   feature means of the training data (the SHAP background)
    models/shap_summary.json        global importance: mean |SHAP| per feature on the test data
"""
from __future__ import annotations

import json
import time

import joblib
import numpy as np
from scipy import sparse
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from ml.train import (MODELS, SEED, encode, featurise, load_email, load_phiusiil_domains, load_sms,
                      load_web_page, log)
from app.analysis.url_scorecard import BINS, FEATURES, LABELS

TOP = 25


def text_part(name: str, df, saved: dict, recorded_acc: float) -> tuple[dict, dict]:
    train, test = train_test_split(df, test_size=0.2, random_state=SEED, stratify=df.y)
    vec, coef, b = saved["vectoriser"], saved["coef"].astype(np.float64), saved["intercept"]
    Xtr = vec.transform(train.text)
    Xte = vec.transform(test.text)
    mean = np.asarray(Xtr.mean(axis=0)).ravel()

    # Same split as training? The saved model must reproduce the recorded test accuracy.
    acc = float(((Xte @ coef + b > 0).astype(int) == test.y.to_numpy()).mean())
    if round(acc, 4) != recorded_acc:
        raise SystemExit(f"[{name}] split does not match training: accuracy {acc:.4f} vs recorded {recorded_acc}")

    # Global importance: mean |shap_i| over the test set, computed on the sparse matrix.
    n = Xte.shape[0]
    Xc = Xte.tocsc()
    abs_sum = np.zeros(len(coef))
    for j in range(Xc.shape[1]):   # present values: |x - mean|; absent rows contribute |0 - mean| = mean
        col = Xc.data[Xc.indptr[j]:Xc.indptr[j + 1]]
        abs_sum[j] = np.abs(col - mean[j]).sum() + (n - len(col)) * mean[j]
    mean_abs = np.abs(coef) * abs_sum / n
    names = vec.get_feature_names_out()
    order = np.argsort(-mean_abs)[:TOP]
    importance = [{"feature": str(names[i]), "mean_abs_shap": round(float(mean_abs[i]), 4),
                   "weight": round(float(coef[i]), 3), "pushes": "scam" if coef[i] > 0 else "safe"} for i in order]
    base = float(b + coef @ mean)
    log(f"[{name}] background rows={Xtr.shape[0]:,} features={len(mean):,} base log-odds={base:.3f} "
        f"test accuracy reproduced={acc:.4f}")
    return ({"mean": mean.astype(np.float32), "rows": int(Xtr.shape[0])},
            {"base_log_odds": round(base, 4), "base_probability": round(float(1 / (1 + np.exp(-base))), 4),
             "background_rows": int(Xtr.shape[0]), "test_rows": int(n), "test_accuracy_reproduced": round(acc, 4),
             "top_features": importance})


def url_part(model: dict, recorded_acc: float) -> tuple[dict, dict]:
    import pandas as pd
    ph, _ = load_phiusiil_domains()
    wp, _ = load_web_page()
    df = pd.concat([ph, wp], ignore_index=True)
    t0 = time.time()
    feats, tlds, groups = featurise(df.url)
    log(f"URL features for {len(df):,} URLs in {time.time() - t0:.0f}s")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr_idx, te_idx = next(gss.split(df, df.y, groups))

    # Encode exactly as the app does when it explains a link: domain-ending risk from the saved table.
    def risk(idx):
        return np.array([model["tld_table"].get(t, {"risk": model["prior"]})["risk"] for t in tlds.iloc[idx]])

    Xtr = encode(feats.iloc[tr_idx].reset_index(drop=True), risk(tr_idx))
    Xte = encode(feats.iloc[te_idx].reset_index(drop=True), risk(te_idx))
    coef, b = model["coef"], model["intercept"]
    mean = np.asarray(Xtr.mean(axis=0)).ravel()
    y_te = df.y.to_numpy()[te_idx]
    acc = float(((1 / (1 + np.exp(-(Xte @ coef + b))) >= model["threshold"]).astype(int) == y_te).mean())
    if round(acc, 4) != recorded_acc:
        raise SystemExit(f"[url] split does not match training: accuracy {acc:.4f} vs recorded {recorded_acc}")

    # SHAP per original feature = sum over its one-hot bin columns (SHAP values are additive).
    shap_cols = (Xte.toarray() - mean) * coef
    groups_out, off = [], 0
    for name in FEATURES:
        k = len(BINS[name])
        g = shap_cols[:, off:off + k].sum(axis=1)
        label = "Domain ending (.xyz, .top, .com …)" if name == "tld_risk" else LABELS[name].replace("{v}", "N")
        groups_out.append({"feature": name, "label": label,
                           "mean_abs_shap": round(float(np.abs(g).mean()), 4)})
        off += k
    groups_out.sort(key=lambda g: -g["mean_abs_shap"])
    base = float(b + coef @ mean)
    log(f"[url] background rows={Xtr.shape[0]:,} base log-odds={base:.3f} test accuracy reproduced={acc:.4f}")
    return ({"mean": mean.astype(np.float64), "rows": int(Xtr.shape[0])},
            {"base_log_odds": round(base, 4), "base_probability": round(float(1 / (1 + np.exp(-base))), 4),
             "background_rows": int(Xtr.shape[0]), "test_rows": int(len(te_idx)), "test_accuracy_reproduced": round(acc, 4),
             "top_features": groups_out})


def main() -> int:
    metrics = json.loads((MODELS / "metrics.json").read_text(encoding="utf-8"))
    text_models = joblib.load(MODELS / "text_model.joblib")
    url_model = joblib.load(MODELS / "url_model.joblib")
    background, summary = {"text": {}}, {"method": "Exact SHAP for linear models: shap_i = w_i * (x_i - mean_i) in "
                                                   "log-odds, background = feature means of the training split "
                                                   "(same as shap.LinearExplainer, interventional).", "text": {}}
    loaders = {"sms": load_sms, "email": load_email}
    for name in ("sms", "email"):
        df, _ = loaders[name]()
        recorded = metrics["text_model"]["channels"][name]["test"]["accuracy"]
        background["text"][name], summary["text"][name] = text_part(name, df, text_models[name], recorded)
    background["url"], summary["url"] = url_part(url_model, metrics["url_model"]["test"]["all"]["accuracy"])
    background["generated_at"] = summary["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    joblib.dump(background, MODELS / "shap_background.joblib", compress=3)
    (MODELS / "shap_summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    log("wrote models/shap_background.joblib and models/shap_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
