"""Train and evaluate both models. Every number shown in the app comes from this script.

Outputs
  models/text_model.joblib   TF-IDF vectoriser + logistic-regression weights
  models/url_model.joblib    scorecard: bin edges + logistic-regression weights + TLD table
  models/metrics.json        dataset facts and held-out test metrics

Run:  python -m ml.train
"""
from __future__ import annotations

import json
import platform
import sys
import time
import urllib.request
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from scipy import sparse
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, StratifiedKFold, train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.analysis import textprep  # noqa: E402
from app.analysis.url_features import parse_url, tld_of  # noqa: E402
from app.analysis.url_scorecard import BINS, FEATURES, bin_index, n_columns  # noqa: E402

RAW = ROOT / "data" / "raw"
MODELS = ROOT / "models"
SEED = 42
TEXT_MAX_CHARS = 5_000


def log(msg: str) -> None:
    print(msg, flush=True)


def metrics(y_true, prob, threshold: float = 0.5) -> dict:
    y_true = np.asarray(y_true)
    pred = (np.asarray(prob) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y_true)),
        "n_scam": int(y_true.sum()),
        "accuracy": round(float(accuracy_score(y_true, pred)), 4),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)), 4) if (fp + tn) else None,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "majority_class_accuracy": round(float(max(y_true.mean(), 1 - y_true.mean())), 4),
    }
    if 0 < y_true.sum() < len(y_true):
        out["roc_auc"] = round(float(roc_auc_score(y_true, prob)), 4)
        out["pr_auc"] = round(float(average_precision_score(y_true, prob)), 4)
    return out


# ----------------------------------------------------------------------------
# Text model
# ----------------------------------------------------------------------------

def load_sms() -> tuple[pd.DataFrame, dict]:
    df = pd.read_csv(RAW / "sms_spam" / "SMSSpamCollection", sep="\t", header=None,
                     names=["label", "text"], quoting=3, encoding="utf-8")
    raw_rows = len(df)
    raw_balance = df.label.value_counts().to_dict()
    df["y"] = (df.label == "spam").astype(int)
    df["key"] = df.text.str.lower().str.split().str.join(" ")
    dupes = int(df.key.duplicated().sum())
    df = df.drop_duplicates("key")[["text", "y"]].assign(source="sms")
    facts = {
        "rows_raw": raw_rows, "class_balance_raw": {"safe": int(raw_balance["ham"]), "scam": int(raw_balance["spam"])},
        "duplicates_removed": dupes, "rows_used": len(df),
        "class_balance_used": {"safe": int((df.y == 0).sum()), "scam": int((df.y == 1).sum())},
        "notes": [
            "English SMS collected mostly in the UK and Singapore, 2006-2012.",
            "'Spam' here is advertising and premium-rate scams, not modern bank phishing.",
        ],
    }
    return df, facts


def load_email() -> tuple[pd.DataFrame, dict]:
    df = pd.read_csv(RAW / "phishing_email" / "Phishing_Email.csv")
    raw_rows = len(df)
    raw_balance = df["Email Type"].value_counts().to_dict()
    df = df.rename(columns={"Email Text": "text"})
    df["y"] = (df["Email Type"] == "Phishing Email").astype(int)
    null_rows = int(df.text.isna().sum())
    df = df.dropna(subset=["text"])
    stripped = df.text.str.strip()
    placeholder = int((stripped.str.lower() == "empty").sum())
    too_short = int(((stripped.str.len() < 20) & (stripped.str.lower() != "empty")).sum())
    df = df[stripped.str.len() >= 20].copy()
    longest = int(df.text.str.len().max())
    df["text"] = df.text.str.slice(0, TEXT_MAX_CHARS)
    df["key"] = df.text.str.lower().str.split().str.join(" ")
    dupes = int(df.key.duplicated().sum())
    df = df.drop_duplicates("key")[["text", "y"]].assign(source="email")
    facts = {
        "rows_raw": raw_rows,
        "class_balance_raw": {"safe": int(raw_balance["Safe Email"]), "scam": int(raw_balance["Phishing Email"])},
        "rows_removed": {"missing_text": null_rows, "text_is_the_word_empty": placeholder,
                         "shorter_than_20_chars": too_short, "duplicates": dupes},
        "rows_used": len(df),
        "class_balance_used": {"safe": int((df.y == 0).sum()), "scam": int((df.y == 1).sum())},
        "notes": [
            f"Texts are cut to the first {TEXT_MAX_CHARS:,} characters (longest raw e-mail: {longest:,} characters).",
            "'Safe' e-mails are old business and mailing-list mail; 'Phishing' also contains ordinary spam.",
            "Text is lower-cased and pre-tokenised by the dataset authors.",
        ],
    }
    return df, facts


def make_vectoriser(min_df: int) -> TfidfVectorizer:
    return TfidfVectorizer(
        preprocessor=textprep.normalise, token_pattern=textprep.TOKEN_PATTERN,
        stop_words=textprep.STOP_WORDS, ngram_range=(1, 2), min_df=min_df, max_df=0.95,
        sublinear_tf=True, max_features=150_000, dtype=np.float32,
    )


def known_fraction(vocab_words: set, text: str) -> tuple[float, int]:
    """Share of a message's meaningful words that the model has seen in training."""
    toks = textprep.content_tokens(text)
    if not toks:
        return 0.0, 0
    return sum(t in vocab_words for t in toks) / len(toks), len(toks)


TEXT_SETUP = {
    # channel: (min_df, C values tried)
    "sms": (2, (3.0, 10.0, 30.0, 100.0)),
    "email": (3, (3.0, 10.0, 30.0, 100.0)),
}
GATE_MIN_KNOWN = 0.6
GATE_MIN_TOKENS = 3


def fit_text(train: pd.DataFrame, min_df: int, C: float):
    vec = make_vectoriser(min_df)
    X = vec.fit_transform(train.text)
    clf = LogisticRegression(C=C, max_iter=5000).fit(X, train.y)
    return vec, clf


def train_text(report: dict) -> None:
    log("\n=== TEXT MODELS ===")
    data = {}
    data["sms"], report["datasets"]["sms_spam"] = load_sms()
    data["email"], report["datasets"]["phishing_email"] = load_email()
    splits = {}
    for name, df in data.items():
        log(f"{name:<5} used={len(df):,} {report['datasets']['sms_spam' if name == 'sms' else 'phishing_email']['class_balance_used']}")
        splits[name] = train_test_split(df, test_size=0.2, random_state=SEED, stratify=df.y)

    saved, out = {}, {}
    for name, (train, test) in splits.items():
        min_df, grid = TEXT_SETUP[name]
        # Choose C by 3-fold cross-validation on the training split only.
        skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)
        cv = {}
        for C in grid:
            scores = []
            for tr_idx, va_idx in skf.split(train, train.y):
                vec, clf = fit_text(train.iloc[tr_idx], min_df, C)
                p = clf.predict_proba(vec.transform(train.text.iloc[va_idx]))[:, 1]
                scores.append(f1_score(train.y.iloc[va_idx], p >= 0.5))
            cv[C] = round(float(np.mean(scores)), 4)
        best_C = max(cv, key=cv.get)
        log(f"[{name}] cv F1 by C: {cv} -> C={best_C}")

        vec, clf = fit_text(train, min_df, best_C)
        prob = clf.predict_proba(vec.transform(test.text))[:, 1]
        m = metrics(test.y, prob)
        log(f"[{name}] test n={m['n']} acc={m['accuracy']} prec={m['precision']} rec={m['recall']} "
            f"f1={m['f1']} auc={m['roc_auc']} fpr={m['false_positive_rate']}")

        # The same model on the OTHER channel's test set: does it transfer?
        other = "email" if name == "sms" else "sms"
        other_test = splits[other][1]
        cross = metrics(other_test.y, clf.predict_proba(vec.transform(other_test.text))[:, 1])
        log(f"[{name}] on {other} test: acc={cross['accuracy']} prec={cross['precision']} rec={cross['recall']} fpr={cross['false_positive_rate']}")

        names = np.array(vec.get_feature_names_out())
        coef = clf.coef_[0]
        order = np.argsort(coef)
        top_scam = [{"term": str(names[i]), "weight": round(float(coef[i]), 3)} for i in order[::-1][:40]]
        top_safe = [{"term": str(names[i]), "weight": round(float(coef[i]), 3)} for i in order[:40]]
        log(f"[{name}] top scam terms: " + ", ".join(t["term"] for t in top_scam[:30]))
        log(f"[{name}] top safe terms: " + ", ".join(t["term"] for t in top_safe[:30]))

        vocab_words = {w for term in names for w in term.split(" ")}
        kf = np.array([known_fraction(vocab_words, t) for t in test.text])
        passing = (kf[:, 0] >= GATE_MIN_KNOWN) & (kf[:, 1] >= GATE_MIN_TOKENS)
        gate = {
            "min_known_fraction": GATE_MIN_KNOWN, "min_tokens": GATE_MIN_TOKENS,
            "test_messages_passing_gate": round(float(passing.mean()), 4),
            "known_fraction_percentiles": {str(q): round(float(np.percentile(kf[:, 0], q)), 3) for q in (1, 5, 25, 50)},
            "metrics_on_passing_messages": metrics(test.y[passing], prob[passing]),
        }
        log(f"[{name}] gate: pass={gate['test_messages_passing_gate']} pct={gate['known_fraction_percentiles']}")

        saved[name] = {"vectoriser": vec, "coef": coef.astype(np.float32),
                       "intercept": float(clf.intercept_[0]), "vocab_words": vocab_words, "gate": gate}
        out[name] = {
            "trained_on": "sms_spam" if name == "sms" else "phishing_email",
            "params": {"C": best_C, "ngram_range": [1, 2], "min_df": min_df, "sublinear_tf": True},
            "cv_f1_by_C": {str(k): v for k, v in cv.items()},
            "n_features": int(len(names)), "train_rows": int(len(train)), "test_rows": int(len(test)),
            "test": m, "tested_on_other_channel": {"channel": other, **cross},
            "top_scam_terms": top_scam, "top_safe_terms": top_safe, "gate": gate,
        }

    MODELS.mkdir(exist_ok=True)
    joblib.dump(saved, MODELS / "text_model.joblib", compress=3)
    report["text_model"] = {
        "algorithm": "TF-IDF (word 1-2 grams) + Logistic Regression, one model per channel",
        "why": "Linear model: each word's contribution to the score is exact and can be shown.",
        "why_two_models": "Measured: a model trained on one channel fails on the other "
                          "(see tested_on_other_channel), so SMS/chat and e-mail each get their own model.",
        "split": "80/20 stratified after removing duplicates, seed 42",
        "threshold": 0.5,
        "stop_words": len(textprep.STOP_WORDS),
        "corpus_words_removed": sorted(textprep.CORPUS_ARTIFACTS),
        "channels": out,
    }


# ----------------------------------------------------------------------------
# URL model
# ----------------------------------------------------------------------------

def load_phiusiil_domains() -> tuple[pd.DataFrame, dict]:
    """PhiUSIIL reduced to registered domains (see the bias note written into the report)."""
    from urllib.parse import urlsplit

    df = pd.read_csv(RAW / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])
    raw_rows = len(df)
    raw_safe = int((df.label == 1).sum())
    df["y"] = (df.label == 0).astype(int)  # dataset: 1 = legitimate, 0 = phishing

    def structure(sub: pd.DataFrame) -> dict:
        sp = sub.URL.map(urlsplit)
        return {
            "https_pct": round(100 * float((sp.map(lambda u: u.scheme) == "https").mean()), 1),
            "starts_with_www_pct": round(100 * float(sp.map(lambda u: u.netloc.startswith("www.")).mean()), 1),
            "has_path_pct": round(100 * float(sp.map(lambda u: len(u.path) > 1).mean()), 1),
            "has_query_pct": round(100 * float(sp.map(lambda u: bool(u.query)).mean()), 1),
        }

    structure_facts = {"legitimate": structure(df[df.y == 0]), "phishing": structure(df[df.y == 1])}

    def domain_of(u: str) -> str:
        info = parse_url(u)
        return info.registered_domain if info.valid else ""

    df["domain"] = df.URL.map(domain_of)
    df = df[df.domain != ""]
    legit_with_subdomain = float((df[df.y == 0].URL.map(lambda u: parse_url(u).subdomain != "")).mean())
    structure_facts["legitimate"]["has_subdomain_other_than_www_pct"] = round(100 * legit_with_subdomain, 1)
    nunique = df.groupby("domain").y.nunique()
    conflict = set(nunique[nunique > 1].index)
    kept = df[~df.domain.isin(conflict)]
    out = kept.drop_duplicates("domain")
    out = pd.DataFrame({"url": "http://" + out.domain, "y": out.y, "source": "phiusiil_domains"})
    facts = {
        "rows_raw": raw_rows,
        "class_balance_raw": {"safe": raw_safe, "scam": raw_rows - raw_safe},
        "structure_by_class": structure_facts,
        "domains_in_both_classes_removed": len(conflict),
        "rows_on_those_domains": int(len(df) - len(kept)),
        "duplicate_domains_removed": int(len(kept) - len(out)),
        "rows_used": len(out),
        "class_balance_used": {"safe": int((out.y == 0).sum()), "scam": int((out.y == 1).sum())},
        "notes": [
            "Bias found: every legitimate URL is 'https://www.<domain>' with no subdomain and no "
            "path, while phishing URLs vary. Scheme, 'www', subdomains and paths would give the label away.",
            "Fix: only the registered domain is used from this dataset. Scheme and 'www' are never "
            "features. Subdomain and path features are learned from the other URL dataset only.",
        ],
    }
    return out, facts


def load_web_page() -> tuple[pd.DataFrame, dict]:
    parts = [pd.read_parquet(RAW / "web_page_phishing" / f"{s}.parquet", columns=["url", "status"])
             for s in ("train", "test")]
    df = pd.concat(parts, ignore_index=True)
    raw_rows = len(df)
    raw_balance = df.status.value_counts().to_dict()
    df["y"] = (df.status == "phishing").astype(int)
    dupes = int(df.url.duplicated().sum())
    df = df.drop_duplicates("url")
    out = df[["url", "y"]].assign(source="web_page_phishing")
    facts = {
        "rows_raw": raw_rows,
        "class_balance_raw": {"safe": int(raw_balance.get("legitimate", 0)), "scam": int(raw_balance.get("phishing", 0))},
        "duplicates_removed": dupes, "rows_used": len(out),
        "class_balance_used": {"safe": int((out.y == 0).sum()), "scam": int((out.y == 1).sum())},
        "notes": [
            "Full URLs. Legitimate URLs here do have paths and subdomains, so this dataset is the "
            "only source for path features.",
            "The dataset's own train and test files are merged and re-split by domain (below).",
        ],
    }
    return out, facts


def featurise(urls: pd.Series) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    rows, tlds, groups = [], [], []
    for u in urls:
        info = parse_url(u)
        rows.append(info.features if info.valid else {})
        tlds.append(tld_of(info) if info.valid else "")
        groups.append(info.registered_domain if info.valid else u)
    feats = pd.DataFrame(rows, index=urls.index).fillna(0)
    return feats, pd.Series(tlds, index=urls.index), pd.Series(groups, index=urls.index)


def tld_table(tlds: pd.Series, y: pd.Series, prior: float, m: int = 20) -> dict:
    """Smoothed share of phishing per TLD: (phish + m*prior) / (n + m)."""
    g = pd.DataFrame({"tld": tlds, "y": y}).groupby("tld").y.agg(["sum", "count"])
    return {t: {"n": int(r["count"]), "phish": int(r["sum"]),
                "risk": round(float((r["sum"] + m * prior) / (r["count"] + m)), 4)}
            for t, r in g.iterrows() if t}


def encode(feats: pd.DataFrame, tld_risk: np.ndarray) -> sparse.csr_matrix:
    """One-hot encode every feature into its bin."""
    n = len(feats)
    cols, offset = [], 0
    for name in FEATURES:
        values = tld_risk if name == "tld_risk" else feats[name].to_numpy()
        cols.append(offset + bin_index(name, values))
        offset += len(BINS[name])
    col = np.concatenate(cols)
    row = np.tile(np.arange(n), len(FEATURES))
    return sparse.csr_matrix((np.ones(len(col), dtype=np.float32), (row, col)), shape=(n, n_columns()))


def balanced_weights(df: pd.DataFrame) -> np.ndarray:
    """Each (dataset, class) cell gets the same total weight."""
    w = np.zeros(len(df))
    cells = df.groupby(["source", "y"]).size()
    for (src, y), count in cells.items():
        w[((df.source == src) & (df.y == y)).to_numpy()] = 1.0 / (len(cells) * count)
    return w * len(df)


def fetch_openphish() -> tuple[list[str], dict]:
    """Live phishing feed, used only as an extra test. Skipped when offline."""
    folder = RAW / "openphish"
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / "feed.txt"
    info = {}
    if not dest.exists():
        for url in ("https://openphish.com/feed.txt",
                    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "satarkai-hackathon/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read()
                if data.strip():
                    dest.write_bytes(data)
                    (folder / "source.json").write_text(json.dumps(
                        {"url": url, "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "bytes": len(data)}))
                    break
            except Exception as exc:
                info.setdefault("errors", []).append(f"{url}: {exc}")
    if not dest.exists():
        return [], info
    src = folder / "source.json"
    if src.exists():
        info.update(json.loads(src.read_text()))
    urls = [u.strip() for u in dest.read_text(encoding="utf-8", errors="replace").splitlines() if u.strip()]
    return sorted(set(urls)), info


TARGET_FPR = 0.05


def train_url(report: dict) -> None:
    log("\n=== URL MODEL ===")
    ph, ph_facts = load_phiusiil_domains()
    wp, wp_facts = load_web_page()
    report["datasets"]["phiusiil"] = ph_facts
    report["datasets"]["web_page_phishing"] = wp_facts
    log(f"phiusiil domains used={len(ph):,} {ph_facts['class_balance_used']}")
    log(f"  structure: {ph_facts['structure_by_class']}")
    log(f"web_page   used={len(wp):,} {wp_facts['class_balance_used']}")

    df = pd.concat([ph, wp], ignore_index=True)
    t0 = time.time()
    feats, tlds, groups = featurise(df.url)
    log(f"features for {len(df):,} URLs in {time.time() - t0:.0f}s")

    # Split by registered domain: a domain is never in both train and test.
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr_idx, te_idx = next(gss.split(df, df.y, groups))
    tr, te = df.iloc[tr_idx].reset_index(drop=True), df.iloc[te_idx].reset_index(drop=True)
    f_tr, f_te = feats.iloc[tr_idx].reset_index(drop=True), feats.iloc[te_idx].reset_index(drop=True)
    t_tr, t_te = tlds.iloc[tr_idx].reset_index(drop=True), tlds.iloc[te_idx].reset_index(drop=True)
    g_tr = groups.iloc[tr_idx].reset_index(drop=True)
    prior = float(tr.y.mean())

    # TLD risk for training rows is computed out-of-fold, so a row never sees its own label.
    risk_tr = np.full(len(tr), prior)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    for a_idx, b_idx in skf.split(t_tr, tr.y):
        fold = tld_table(t_tr.iloc[a_idx], tr.y.iloc[a_idx], prior)
        risk_tr[b_idx] = [fold.get(t, {"risk": prior})["risk"] for t in t_tr.iloc[b_idx]]
    table = tld_table(t_tr, tr.y, prior)
    risk_te = np.array([table.get(t, {"risk": prior})["risk"] for t in t_te])

    Xtr, Xte = encode(f_tr, risk_tr), encode(f_te, risk_te)
    w = balanced_weights(tr)
    is_wp_tr = (tr.source == "web_page_phishing").to_numpy()

    # Validation part of the training split (again split by domain): choose C and the
    # alert threshold here. The test split is not touched until the very end.
    inner = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED)
    a_idx, b_idx = next(inner.split(tr, tr.y, g_tr))
    yb, wp_b = tr.y.to_numpy()[b_idx], is_wp_tr[b_idx]
    val = {}
    for C in (0.03, 0.1, 0.3, 1.0, 3.0):
        clf = LogisticRegression(C=C, max_iter=5000).fit(Xtr[a_idx], tr.y.iloc[a_idx], sample_weight=w[a_idx])
        pb = clf.predict_proba(Xtr[b_idx])[:, 1]
        val[C] = {"auc_full_urls": round(float(roc_auc_score(yb[wp_b], pb[wp_b])), 4),
                  "auc_domains": round(float(roc_auc_score(yb[~wp_b], pb[~wp_b])), 4)}
        val[C]["mean_auc"] = round((val[C]["auc_full_urls"] + val[C]["auc_domains"]) / 2, 4)
        log(f"  val C={C:<5} {val[C]}")
    best_C = max(val, key=lambda c: val[c]["mean_auc"])
    clf = LogisticRegression(C=best_C, max_iter=5000).fit(Xtr[a_idx], tr.y.iloc[a_idx], sample_weight=w[a_idx])
    pb = clf.predict_proba(Xtr[b_idx])[:, 1]
    # Alert threshold: the lowest one that keeps false alarms on legitimate full URLs <= 5 %.
    legit_scores = np.sort(pb[wp_b & (yb == 0)])
    threshold = 0.5
    for t in np.arange(0.5, 0.96, 0.01):
        if float((legit_scores >= t).mean()) <= TARGET_FPR:
            threshold = round(float(t), 2)
            break
    else:
        threshold = 0.95
    log(f"  chosen C={best_C}, alert threshold={threshold} (validation false alarms on full legitimate URLs <= {TARGET_FPR:.0%})")

    clf = LogisticRegression(C=best_C, max_iter=5000).fit(Xtr, tr.y, sample_weight=w)
    prob = clf.predict_proba(Xte)[:, 1]

    def by_source(p: np.ndarray, t: float) -> dict:
        res = {"all": metrics(te.y, p, t)}
        for src in te.source.unique():
            mask = (te.source == src).to_numpy()
            res[src] = metrics(te.y[mask], p[mask], t)
        return res

    results = by_source(prob, threshold)
    results_050 = by_source(prob, 0.5)
    for name, m in results.items():
        log(f"  test@{threshold}[{name:<18}] n={m['n']:<6} acc={m['accuracy']} prec={m['precision']} rec={m['recall']} "
            f"f1={m['f1']} auc={m.get('roc_auc')} fpr={m['false_positive_rate']}")
    for name, m in results_050.items():
        log(f"  test@0.5 [{name:<18}] acc={m['accuracy']} prec={m['precision']} rec={m['recall']} fpr={m['false_positive_rate']}")

    # Black-box comparison: how much accuracy does the explainable model give up?
    raw_tr, raw_te = f_tr.assign(tld_risk=risk_tr)[FEATURES], f_te.assign(tld_risk=risk_te)[FEATURES]
    gbm = HistGradientBoostingClassifier(random_state=SEED, max_iter=300).fit(raw_tr, tr.y, sample_weight=w)
    gprob = gbm.predict_proba(raw_te)[:, 1]
    gbm_results = by_source(gprob, 0.5)
    for name, m in gbm_results.items():
        log(f"  gbm@0.5  [{name:<18}] acc={m['accuracy']} prec={m['precision']} rec={m['recall']} auc={m.get('roc_auc')} fpr={m['false_positive_rate']}")

    coef, intercept = clf.coef_[0], float(clf.intercept_[0])
    scorecard, offset = [], 0
    for name in FEATURES:
        for j, lo in enumerate(BINS[name]):
            hi = BINS[name][j + 1] if j + 1 < len(BINS[name]) else None
            scorecard.append({"feature": name, "from": lo, "to": hi, "points": round(float(coef[offset + j]), 3),
                              "train_rows": int(Xtr[:, offset + j].sum())})
        offset += len(BINS[name])

    MODELS.mkdir(exist_ok=True)
    model = {"coef": coef.astype(np.float64), "intercept": intercept, "tld_table": table,
             "prior": prior, "threshold": threshold}
    joblib.dump(model, MODELS / "url_model.joblib", compress=3)

    # Extra checks that use the saved model exactly as the app does.
    from app.analysis.url_scorecard import score_url
    sanity = {}
    legit_file = ROOT / "ml" / "sanity_legit_urls.txt"
    legit = [u.strip() for u in legit_file.read_text(encoding="utf-8").splitlines() if u.strip() and not u.startswith("#")]
    lp = np.array([score_url(parse_url(u), model)["probability"] for u in legit])
    flagged = [{"url": u, "probability": round(float(p), 3)} for u, p in zip(legit, lp) if p >= threshold]
    sanity["hand_written_legitimate_urls"] = {
        "n": len(legit), "flagged_as_phishing": len(flagged),
        "false_positive_rate": round(len(flagged) / len(legit), 4), "flagged": flagged,
        "note": "URLs of well-known sites typed by hand. A small set: it only shows whether deep "
                "legitimate links raise false alarms.",
    }
    log(f"  sanity legit: {len(flagged)}/{len(legit)} flagged: {[(f['url'], f['probability']) for f in flagged]}")

    feed, feed_info = fetch_openphish()
    if feed:
        train_domains = set(g_tr)
        infos = [i for i in (parse_url(u) for u in feed) if i.valid]
        unseen = [i for i in infos if i.registered_domain not in train_domains]
        fp = np.array([score_url(i, model)["probability"] for i in unseen])
        sanity["openphish_feed"] = {
            **{k: v for k, v in feed_info.items() if k != "errors"},
            "urls_in_feed": len(infos), "urls_on_domains_not_in_training": len(unseen),
            "detected": int((fp >= threshold).sum()),
            "recall": round(float((fp >= threshold).mean()), 4) if len(unseen) else None,
            "note": "Live phishing URLs reported after the training data was collected. Phishing "
                    "only, so it measures recall, not false alarms.",
        }
        log(f"  openphish: {sanity['openphish_feed']['detected']}/{len(unseen)} detected at {threshold}")
    else:
        sanity["openphish_feed"] = {"skipped": True, "reason": "feed could not be downloaded", **feed_info}
        log(f"  openphish skipped: {feed_info}")

    report["url_model"] = {
        "algorithm": "Scorecard: binned URL features + Logistic Regression",
        "why": "Each feature adds a fixed number of points, so the reason for a score is exact.",
        "params": {"C": best_C, "features": len(FEATURES), "columns": n_columns(),
                   "sample_weight": "equal total weight for each (dataset, class) cell"},
        "validation_by_C": {str(k): v for k, v in val.items()},
        "train_rows": int(len(tr)), "test_rows": int(len(te)),
        "split": "80/20 by registered domain (a domain is never in both parts), seed 42",
        "threshold": threshold,
        "threshold_rule": f"lowest threshold with at most {TARGET_FPR:.0%} false alarms on legitimate full URLs in the validation part",
        "test": results,
        "test_at_0.5": results_050,
        "black_box_comparison": {"algorithm": "HistGradientBoostingClassifier on the same features, threshold 0.5",
                                 "test": gbm_results},
        "sanity": sanity,
        "scorecard": scorecard,
        "intercept": round(intercept, 3),
        "tlds_in_table": len(table),
    }


def main() -> int:
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                     "numpy": np.__version__, "pandas": pd.__version__},
        "seed": SEED,
        "downloads": json.loads((RAW / "manifest.json").read_text()) if (RAW / "manifest.json").exists() else {},
        "datasets": {},
    }
    only = sys.argv[1] if len(sys.argv) > 1 else "all"
    metrics_path = MODELS / "metrics.json"
    if only != "all" and metrics_path.exists():
        old = json.loads(metrics_path.read_text())
        report["datasets"] = old.get("datasets", {})
        for k in ("text_model", "url_model"):
            if k in old:
                report[k] = old[k]
    if only in ("all", "text"):
        train_text(report)
    if only in ("all", "url"):
        train_url(report)
    MODELS.mkdir(exist_ok=True)
    metrics_path.write_text(json.dumps(report, indent=2, default=str))
    log(f"\nwrote {metrics_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
