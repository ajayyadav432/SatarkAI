"""Risk score arithmetic, level boundaries and monotonic behaviour."""
import itertools

import pytest

from app.analysis import scoring


@pytest.mark.parametrize("score,level", [
    (0, "Safe"), (19, "Safe"), (20, "Low"), (39, "Low"), (40, "Medium"), (59, "Medium"),
    (60, "High"), (79, "High"), (80, "Critical"), (100, "Critical"),
])
def test_level_boundaries(score, level):
    assert scoring.level_for(score) == level


def test_noisy_or_formula():
    assert scoring.combine([]) == 0
    assert scoring.combine([0.25]) == 25
    assert scoring.combine([0.5, 0.5]) == 75
    assert scoring.combine([0.6, 0.4, 0.35]) == round(100 * (1 - 0.4 * 0.6 * 0.65))
    assert scoring.combine([1.0, 0.3]) == 100


def test_score_never_leaves_0_to_100():
    assert scoring.combine([5.0, -3.0]) == 100
    assert 0 <= scoring.combine([0.99] * 50) <= 100


def test_more_evidence_never_lowers_the_score():
    weights = [0.1, 0.15, 0.25, 0.35, 0.5, 0.6, 0.7]
    for subset in itertools.combinations(weights, 3):
        base = scoring.combine(subset)
        for extra in weights:
            assert scoring.combine(list(subset) + [extra]) >= base


def test_order_does_not_matter():
    assert scoring.combine([0.6, 0.25, 0.1]) == scoring.combine([0.1, 0.6, 0.25])


def test_model_weights():
    assert scoring.ml_text_weight(0.49) == 0
    assert scoring.ml_text_weight(0.5) == scoring.ML_TEXT_MIN
    assert scoring.ml_text_weight(1.0) == scoring.ML_TEXT_MAX
    assert scoring.ml_url_weight(0.83, 0.84) == 0
    assert scoring.ml_url_weight(0.84, 0.84) == scoring.ML_URL_MIN
    assert scoring.ml_url_weight(1.0, 0.84) == scoring.ML_URL_MAX
    # A model on its own can never produce High.
    assert scoring.level_for(scoring.combine([scoring.ML_TEXT_MAX])) in ("Low", "Medium")
    assert scoring.level_for(scoring.combine([scoring.ML_URL_MAX])) in ("Low", "Medium")


def test_dedupe_keeps_strongest_of_each_kind():
    ev = [{"id": "a", "weight": 0.2}, {"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.3}, {"id": "c", "weight": 0}]
    out = scoring.dedupe(ev)
    assert [(e["id"], e["weight"]) for e in out] == [("a", 0.5), ("b", 0.3)]


def test_category_choice():
    ev = [{"id": "rule_kyc", "weight": 0.4, "category": "KYC / account update"},
          {"id": "rule_reward", "weight": 0.35, "category": "Lottery / prize scam"}]
    assert scoring.pick_category(ev, "High") == "KYC / account update"
    assert scoring.pick_category(ev, "Safe") == "None"
    assert scoring.pick_category([{"id": "url_lookalike", "weight": 0.7}], "High") == "Brand impersonation"
    assert scoring.pick_category([{"id": "url_shortener", "weight": 0.25}], "Low") == "Suspicious link"
    assert scoring.pick_category([{"id": "ml_text", "weight": 0.4}], "Medium") == "Spam / unsolicited message"


def test_advice_exists_for_every_level():
    for level, _ in [(n, lo) for n, lo in __import__("app.config", fromlist=["x"]).RISK_LEVELS]:
        assert scoring.advice_for(level, "None")
        assert scoring.LEVEL_SUMMARY[level]


def test_high_needs_a_strong_non_model_indicator():
    weak = [{"weight": 0.12, "source": "rule"}, {"weight": 0.25, "source": "rule"}, {"weight": 0.45, "source": "ml-text"}]
    raw = scoring.combine(f["weight"] for f in weak)
    assert raw >= 60
    assert scoring.apply_cap(raw, weak) == (59, True)
    strong = weak + [{"weight": 0.35, "source": "rule"}]
    raw2 = scoring.combine(f["weight"] for f in strong)
    assert scoring.apply_cap(raw2, strong) == (raw2, False)
    models_only = [{"weight": 0.55, "source": "ml-url"}, {"weight": 0.45, "source": "ml-text"}]
    assert scoring.apply_cap(scoring.combine(f["weight"] for f in models_only), models_only)[0] == 59
    assert scoring.apply_cap(30, weak) == (30, False)      # the cap never raises a score
