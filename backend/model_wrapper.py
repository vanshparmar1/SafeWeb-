"""
model_wrapper.py - the object we save with joblib.

It bundles three things so they can never get separated:
  1. the trained classifier (e.g. gradient boosting),
  2. a probability calibrator (Platt scaling or isotonic regression),
  3. the exact list of feature names (and their order) it was trained with.

It lives in its own module (not inside train_model.py) on purpose: joblib
stores the class's import path, so the web server must be able to import it.
"""
from __future__ import annotations

from typing import List, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

CALIBRATION_METHODS = ("platt", "isotonic")
_EPS = 1e-6
# Never claim absolute certainty: isotonic regression can output exactly 0 or 1.
_PROB_FLOOR, _PROB_CEIL = 0.001, 0.999


def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, _EPS, 1 - _EPS)
    return np.log(p / (1 - p))


def fit_calibrator(method: str, raw_p: np.ndarray, y: np.ndarray):
    """Learn a mapping raw model score -> real-world probability of phishing."""
    if method == "platt":  # logistic regression on the logit of the score
        return LogisticRegression(C=1e6, max_iter=1000).fit(_logit(raw_p).reshape(-1, 1), y)
    if method == "isotonic":  # monotone step function
        return IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(raw_p, y)
    raise ValueError(f"unknown calibration method: {method}")


def apply_calibrator(method: Optional[str], calibrator, raw_p: np.ndarray) -> np.ndarray:
    if method is None:
        out = np.asarray(raw_p, dtype=float)
    elif method == "platt":
        out = calibrator.predict_proba(_logit(raw_p).reshape(-1, 1))[:, 1]
    elif method == "isotonic":
        out = calibrator.predict(raw_p)
    else:
        raise ValueError(f"unknown calibration method: {method}")
    return np.clip(out, _PROB_FLOOR, _PROB_CEIL)


class CalibratedPhishingModel:
    """predict_phishing_proba(X) -> calibrated probability that the URL is phishing."""

    def __init__(self, base, method: Optional[str], calibrator,
                 feature_names: Sequence[str], base_name: str) -> None:
        self.base = base
        self.method = method
        self.calibrator = calibrator
        self.feature_names: List[str] = list(feature_names)
        self.base_name = base_name

    def _frame(self, X) -> pd.DataFrame:
        if isinstance(X, pd.DataFrame):
            return X[self.feature_names]  # selects AND orders columns; KeyError if one is missing
        arr = np.asarray(X, dtype=float)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.shape[1] != len(self.feature_names):
            raise ValueError(f"expected {len(self.feature_names)} features, got {arr.shape[1]}")
        return pd.DataFrame(arr, columns=self.feature_names)

    def predict_raw(self, X) -> np.ndarray:
        """Uncalibrated score (NOT a trustworthy probability)."""
        return self.base.predict_proba(self._frame(X))[:, 1]

    def calibrate(self, raw_p: np.ndarray) -> np.ndarray:
        return apply_calibrator(self.method, self.calibrator, raw_p)

    def predict_phishing_proba(self, X) -> np.ndarray:
        return self.calibrate(self.predict_raw(X))
