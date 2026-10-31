"""Unit tests for the leakage guards, calibration and threshold logic."""
import numpy as np
import pandas as pd
import pytest

import train_model as tm
from model_wrapper import CalibratedPhishingModel, apply_calibrator, fit_calibrator


def test_template_key_ignores_domain_numbers_and_random_tokens():
    a = tm.template_key("appleid.apple.com.verify0.id8-eu.co.uk/identify-customer=1hJmtMByghjwxGNNZnsoQbzKTqZH175F/",
                        "id8-eu.co.uk")
    b = tm.template_key("appleid.apple.com.verify0.id-app7.co.uk/identify-customer=6kwiunPwY39RJ1SqtbTDB41xwbnmtti2/",
                        "id-app7.co.uk")
    assert a == b


def test_phishing_kit_spread_over_domains_forms_one_group():
    rows = []
    for d in ["aaa.co.uk", "bbb.net", "ccc.com"]:
        rows.append((f"login.secure.verify.account.{d}/identify-customer=Abcdef123456Xyz/", d))
    rows += [("other.org/page", "other.org"), ("other.org/page2", "other.org"), ("solo.com/x", "solo.com")]
    df = pd.DataFrame(rows, columns=["url", "domain"])
    g = tm.make_groups(df)
    assert len(set(g[:3])) == 1          # the three kit domains merged
    assert g[3] == g[4]                  # same domain, same group
    assert g[0] != g[3] and g[3] != g[5]


def test_splits_never_share_a_group():
    rng = np.random.RandomState(0)
    groups = rng.randint(0, 600, 3000)
    y = (groups % 5 == 0).astype(int)    # label is a property of the group
    split = tm.assign_splits(y, groups)  # raises AssertionError on leakage
    assert set(split) == {"train", "validation", "calibration", "test"}


def test_expected_calibration_error_perfect_and_bad():
    p = np.array([0.1] * 90 + [0.9] * 10)
    y_good = np.array([0] * 81 + [1] * 9 + [0] * 1 + [1] * 9)
    assert tm.expected_calibration_error(y_good, p) < 0.05
    assert tm.expected_calibration_error(np.zeros(100), np.full(100, 0.9)) > 0.8


def test_suggest_thresholds_creates_a_unknown_band_for_noisy_scores():
    rng = np.random.RandomState(1)
    y = rng.randint(0, 2, 5000)
    p = np.clip(y * 0.5 + rng.normal(0.25, 0.2, 5000), 0, 1)   # overlapping classes
    th = tm.suggest_thresholds(y, p)
    assert th["t_safe"] < th["t_phish"]
    sel = tm.selective_report(y, p, th["t_safe"], th["t_phish"])
    assert sel["share_unknown"] > 0
    assert sel["phishing_rate_among_called_legitimate"] <= 0.03
    assert sel["precision_among_called_phishing"] >= 0.94


@pytest.mark.parametrize("method", ["platt", "isotonic"])
def test_calibration_improves_or_keeps_reliability(method):
    rng = np.random.RandomState(2)
    raw = rng.uniform(0, 1, 6000)
    y = (rng.uniform(0, 1, 6000) < raw ** 3).astype(int)         # raw score over-states risk
    cal = fit_calibrator(method, raw, y)
    out = apply_calibrator(method, cal, raw)
    assert tm.expected_calibration_error(y, out) < tm.expected_calibration_error(y, raw)
    assert out.min() >= 0.001 and out.max() <= 0.999


def test_wrapper_orders_columns_and_rejects_wrong_width():
    from sklearn.linear_model import LogisticRegression
    names = ["a", "b"]
    X = pd.DataFrame({"a": [0, 1, 0, 1], "b": [1, 1, 0, 0]})
    y = np.array([0, 1, 0, 1])
    base = LogisticRegression().fit(X, y)
    m = CalibratedPhishingModel(base, None, None, names, "lr")
    swapped = X[["b", "a"]]
    assert np.allclose(m.predict_phishing_proba(swapped), m.predict_phishing_proba(X))
    with pytest.raises(ValueError):
        m.predict_phishing_proba(np.zeros((2, 3)))
