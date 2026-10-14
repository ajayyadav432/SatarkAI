"""The URL model as a scorecard.

Every feature is cut into a few ranges ("bins"). Each bin has a fixed number of points,
learned by logistic regression. The points of a URL's bins are added up:

    log-odds = intercept + points(bin of feature 1) + points(bin of feature 2) + ...
    probability = 1 / (1 + e^-log-odds)

So the explanation of a score is exact: it is the list of points that were added.
"""
from __future__ import annotations

import math

import numpy as np

# Lower edge of each bin. A value falls in the last bin whose edge is <= value.
BINS: dict[str, list[float]] = {
    # domain group: learned from both URL datasets
    "domain_label_len":  [0, 5, 8, 12, 16, 20, 30],
    "n_hyphens_domain":  [0, 1, 2, 3],
    "n_digits_domain":   [0, 1, 3, 6],
    "domain_entropy":    [0, 2.0, 2.5, 3.0, 3.5],
    "vowel_ratio":       [0, 0.2, 0.3, 0.45, 0.6],
    "is_ip":             [0, 1],
    "has_punycode":      [0, 1],
    "private_suffix":    [0, 1],
    "domain_sensitive":  [0, 1, 2],
    "tld_risk":          [0, 0.2, 0.4, 0.6, 0.8],
    # subdomain group: learned from the full-URL dataset only
    "n_subdomains":      [0, 1, 2, 3],
    "subdomain_len":     [0, 1, 8, 16, 30],
    "n_hyphens_sub":     [0, 1, 2],
    "n_digits_sub":      [0, 1, 4],
    "sub_sensitive":     [0, 1],
    # path group: learned from the full-URL dataset only
    "path_len":          [0, 1, 10, 25, 50, 100],
    "path_depth":        [0, 1, 2, 3, 5],
    "query_len":         [0, 1, 20, 60],
    "n_params":          [0, 1, 2, 4],
    "n_digits_path":     [0, 1, 5, 15],
    "n_dots_path":       [0, 1, 2, 3],
    "n_special_path":    [0, 1, 3, 6],
    "path_sensitive":    [0, 1, 2],
    "has_exec_ext":      [0, 1],
    "embedded_domain":   [0, 1],
    "has_at":            [0, 1],
    "double_slash_path": [0, 1],
}
FEATURES = list(BINS)
DOMAIN_FEATURES = FEATURES[:FEATURES.index("n_subdomains")]

# How each feature is described to the user. {v} is the feature's value.
LABELS: dict[str, str] = {
    "domain_label_len":  "Domain name is {v} characters long",
    "n_hyphens_domain":  "{v} hyphen(s) in the domain name",
    "n_digits_domain":   "{v} digit(s) in the domain name",
    "domain_entropy":    "Domain name character randomness is {v}",
    "vowel_ratio":       "Share of vowels in the domain name is {v}",
    "is_ip":             "Host is an IP address",
    "has_punycode":      "Hostname uses punycode (xn--)",
    "private_suffix":    "Hosted on a shared / free hosting platform",
    "domain_sensitive":  "{v} trust word(s) such as login / secure in the domain name",
    "tld_risk":          "Domain ending {tld}",
    "n_subdomains":      "{v} subdomain level(s)",
    "subdomain_len":     "Subdomain is {v} characters long",
    "n_hyphens_sub":     "{v} hyphen(s) in the subdomain",
    "n_digits_sub":      "{v} digit(s) in the subdomain",
    "sub_sensitive":     "{v} trust word(s) such as login / secure in the subdomain",
    "path_len":          "Path is {v} characters long",
    "path_depth":        "Path has {v} level(s)",
    "query_len":         "Query string is {v} characters long",
    "n_params":          "{v} query parameter(s)",
    "n_digits_path":     "{v} digit(s) in the path",
    "n_dots_path":       "{v} dot(s) in the path",
    "n_special_path":    "{v} special character(s) in the path",
    "path_sensitive":    "{v} trust word(s) such as login / verify in the path",
    "has_exec_ext":      "Path ends in a downloadable file type",
    "embedded_domain":   "Another domain name appears inside the path",
    "has_at":            "'@' appears in the link",
    "double_slash_path": "'//' appears inside the path",
}
_BINARY = {"is_ip", "has_punycode", "private_suffix", "has_exec_ext", "embedded_domain", "has_at",
           "double_slash_path"}


def n_columns() -> int:
    return sum(len(b) for b in BINS.values())


def bin_index(name: str, values) -> np.ndarray:
    """Bin number for each value (vectorised)."""
    edges = np.asarray(BINS[name], dtype=float)
    idx = np.searchsorted(edges, np.asarray(values, dtype=float), side="right") - 1
    return np.clip(idx, 0, len(edges) - 1)


def _offsets() -> dict[str, int]:
    out, off = {}, 0
    for name in FEATURES:
        out[name] = off
        off += len(BINS[name])
    return out


_OFFSETS = _offsets()


def tld_risk(info, model: dict) -> tuple[float, dict | None]:
    from app.analysis.url_features import tld_of
    entry = model["tld_table"].get(tld_of(info))
    return (entry["risk"], entry) if entry else (model["prior"], None)


def score_url(info, model: dict) -> dict:
    """Probability that the URL is phishing, plus the exact points behind it."""
    from app.analysis.url_features import tld_of

    risk, entry = tld_risk(info, model)
    coef = model["coef"]
    logit = model["intercept"]
    parts = []
    for name in FEATURES:
        value = risk if name == "tld_risk" else info.features.get(name, 0)
        j = int(bin_index(name, [value])[0])
        points = float(coef[_OFFSETS[name] + j])
        logit += points
        if name == "tld_risk":
            tld = tld_of(info)
            if entry:
                label = (f"Domain ending .{tld}: {entry['phish']:,} of {entry['n']:,} training "
                         f"URLs with this ending were phishing")
            elif tld:
                label = f"Domain ending .{tld} was not seen in training (average risk assumed)"
            else:
                label = "No domain ending (IP address host)"
            shown = round(risk, 2)
        else:
            shown = value if isinstance(value, int) or float(value).is_integer() else round(float(value), 2)
            if name in _BINARY:
                if not value:
                    label = None
                else:
                    label = LABELS[name]
            else:
                label = LABELS[name].format(v=int(shown) if float(shown).is_integer() else shown)
        parts.append({"feature": name, "value": shown, "points": round(points, 3), "label": label})
    prob = 1.0 / (1.0 + math.exp(-logit))
    return {"probability": prob, "logit": logit, "intercept": model["intercept"], "parts": parts}
