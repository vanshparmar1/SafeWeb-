"""
train_model.py - train, compare, calibrate and evaluate the SafeWeb URL model.

Run:   python train_model.py            (full run)
       python train_model.py --fast     (quick smoke test on a subsample)

Pipeline (each step prevents a specific mistake):
  1. Load dataset/phishing_dataset.csv (made by prepare_dataset.py).
  2. Extract features with features.py (the same code the API uses).
  3. Build GROUPS: URLs of the same registered domain, and URLs of the same
     phishing-kit template spread over several domains, stay together.
     -> prevents "the model memorised this domain/campaign" leakage.
  4. Split into train / validation / calibration / test using those groups.
       train       (70%) fit the models
       validation  (10%) compare models, pick the calibration method + thresholds
       calibration (10%) fit the probability calibrator
       test        (10%) touched ONCE at the end for the honest final numbers
  5. Compare Logistic Regression, Decision Tree, Random Forest, Gradient
     Boosting (+ XGBoost if installed) with cross-validation on the train set.
  6. Calibrate the winner so "0.9" really means ~90% of such URLs are phishing.
  7. Evaluate on the test set: overall, per URL-structure slice, and with
     ablations that show how much the model leans on dataset shortcuts.
  8. Save the model, feature schema, metadata and reports.

Nothing here is hard-coded: every number comes from the data you give it.
"""
from __future__ import annotations

import argparse
import io
import json
import platform
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.base import clone
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

from features import (FEATURE_NAMES, FEATURE_VERSION, NORMALIZATION_STEPS,
                      extract_feature_vector, parse_url)
from model_wrapper import (CALIBRATION_METHODS, CalibratedPhishingModel,
                           apply_calibrator, fit_calibrator)

try:  # optional
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover
    XGBClassifier = None

try:  # optional (plots are skipped if matplotlib is missing)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception:  # pragma: no cover
    plt = None

SEED = 42
BASE = Path(__file__).resolve().parent
DATA_PATH = BASE / "dataset" / "phishing_dataset.csv"
MODELS_DIR = BASE / "models"
REPORTS_DIR = BASE / "reports"

SPLIT_FOLDS = {"test": 0, "calibration": 1, "validation": 2}  # remaining 7 of 10 folds = train

# Feature subsets for the shortcut ablations
HOST_FEATURES = ["domain_length", "host_hyphens", "num_subdomains", "has_ip_address",
                 "has_at_symbol", "has_unusual_port", "has_punycode", "is_shortener",
                 "domain_entropy", "longest_domain_token", "digits_in_domain", "tld_length"]
STRUCTURE_FEATURES = ["url_length", "path_length", "query_length", "num_path_segments",
                      "num_query_params", "path_entropy"]
assert set(HOST_FEATURES + STRUCTURE_FEATURES) <= set(FEATURE_NAMES)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_LOG = io.StringIO()


def log(msg: str = "") -> None:
    print(msg)
    _LOG.write(msg + "\n")


# ==========================================================================
# 1-2. Data and features
# ==========================================================================
def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        sys.exit(f"Dataset not found: {path}\nRun prepare_dataset.py first.")
    df = pd.read_csv(path, dtype={"url": str, "domain": str})
    df = df.dropna(subset=["url", "label", "domain"])
    df["label"] = df["label"].astype(int)
    if not set(df["label"].unique()) <= {0, 1}:
        sys.exit("Labels must be 0 (legitimate) or 1 (phishing).")
    n = len(df)
    df = df.drop_duplicates("url").reset_index(drop=True)
    log(f"Loaded {n:,} rows; {n - len(df):,} duplicate URLs dropped.")
    return df


def build_feature_matrix(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Extract features for every URL; rows that fail are dropped (and counted)."""
    rows, keep = [], []
    for i, u in enumerate(df["url"].tolist()):
        try:
            rows.append(extract_feature_vector(u))
            keep.append(True)
        except Exception:
            keep.append(False)
        if (i + 1) % 100_000 == 0:
            print(f"  features: {i + 1:,}/{len(df):,}")
    keep_arr = np.array(keep)
    if (~keep_arr).any():
        log(f"Feature extraction failed for {int((~keep_arr).sum()):,} rows (dropped).")
    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    X = X.replace([np.inf, -np.inf], np.nan)
    df = df[keep_arr].reset_index(drop=True)
    if X.isna().any().any():  # should not happen; handled explicitly, never silently
        bad = X.isna().any(axis=1)
        log(f"Rows with missing/infinite features dropped: {int(bad.sum()):,}")
        X, df = X[~bad].reset_index(drop=True), df[~bad.values].reset_index(drop=True)
    return X, df


# ==========================================================================
# 3. Groups (leakage prevention)
# ==========================================================================
_LONG_TOKEN = re.compile(r"[a-z0-9]{12,}")
_DIGITS = re.compile(r"\d+")


def template_key(url: str, domain: str) -> str:
    """Shape of a URL with the registered domain, random tokens and numbers
    blanked out. Phishing kits reuse the same shape on many domains."""
    p = parse_url(url)
    sub = p.host[: -len(domain)] if p.host.endswith(domain) else ""
    s = f"{sub}|{p.path}?{p.query}".lower()
    return _DIGITS.sub("0", _LONG_TOKEN.sub("T", s))


def make_groups(df: pd.DataFrame, min_domains: int = 3, min_len: int = 20) -> np.ndarray:
    """Group id per row. Rows share a group if they have the same registered
    domain, OR the same distinctive template across >= min_domains domains."""
    domains = df["domain"].tolist()
    tpls = [template_key(u, d) for u, d in zip(df["url"], domains)]
    counts = pd.DataFrame({"t": tpls, "d": domains}).groupby("t")["d"].nunique()
    qualifying = set(counts[(counts >= min_domains) & (counts.index.str.len() >= min_len)].index)

    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for d, t in zip(domains, tpls):
        find("d:" + d)
        if t in qualifying:
            a, b = find("d:" + d), find("t:" + t)
            if a != b:
                parent[a] = b
    gid = pd.factorize(pd.Series(["d:" + d for d in domains]).map(find))[0]
    sizes = pd.Series(gid).value_counts()
    log(f"Groups: {len(sizes):,} (from {len(set(domains)):,} domains; "
        f"{len(qualifying):,} shared phishing-kit templates merged). "
        f"Largest group = {sizes.iloc[0]:,} rows ({sizes.iloc[0] / len(df):.2%}).")
    return gid


# ==========================================================================
# 4. Splits
# ==========================================================================
def assign_splits(y: np.ndarray, groups: np.ndarray, seed: int = SEED) -> np.ndarray:
    """10 group-aware, class-stratified folds -> test / calibration / validation / train."""
    sgkf = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=seed)
    fold = np.full(len(y), -1)
    for i, (_, idx) in enumerate(sgkf.split(np.zeros(len(y)), y, groups)):
        fold[idx] = i
    split = np.full(len(y), "train", dtype=object)
    for name, f in SPLIT_FOLDS.items():
        split[fold == f] = name
    # Hard guarantees: no group may appear in two splits.
    seen: Dict[int, str] = {}
    for g, s in zip(groups, split):
        if seen.setdefault(g, s) != s:
            raise AssertionError("LEAK: a group appears in two splits")
    return split


# ==========================================================================
# Metrics
# ==========================================================================
def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    """Average gap between predicted probability and observed phishing rate."""
    y, p = np.asarray(y), np.asarray(p)
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(ece)


def recall_at_precision(y: np.ndarray, p: np.ndarray, min_precision: float = 0.95) -> float:
    prec, rec, _ = precision_recall_curve(y, p)
    ok = prec >= min_precision
    return float(rec[ok].max()) if ok.any() else 0.0


def best_f1_threshold(y: np.ndarray, p: np.ndarray) -> Tuple[float, float, float, float]:
    prec, rec, thr = precision_recall_curve(y, p)
    f1 = 2 * prec[:-1] * rec[:-1] / np.maximum(prec[:-1] + rec[:-1], 1e-12)
    i = int(np.argmax(f1))
    return float(thr[i]), float(f1[i]), float(prec[i]), float(rec[i])


def safe_auc(fn, y, p) -> Optional[float]:
    return float(fn(y, p)) if len(np.unique(y)) == 2 else None


def threshold_metrics(y: np.ndarray, p: np.ndarray, thr: float) -> Dict[str, float]:
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "threshold": float(thr),
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def suggest_thresholds(y: np.ndarray, p: np.ndarray, max_miss_rate: float = 0.02,
                       min_precision: float = 0.95) -> Dict[str, float]:
    """Pick the uncertain zone from data (not by hand).
      p <= t_safe   : at most `max_miss_rate` of these URLs were phishing
      p >= t_phish  : at least `min_precision` of these URLs were phishing
      in between    : UNKNOWN."""
    y, p = np.asarray(y), np.asarray(p)
    order = np.argsort(p, kind="stable")
    ps, ys = p[order], y[order]
    k = np.arange(1, len(ys) + 1)
    ok = np.where(np.cumsum(ys) / k <= max_miss_rate)[0]
    t_safe = float(ps[ok.max()]) if len(ok) else 0.0

    desc = np.argsort(-p, kind="stable")
    pd_, yd = p[desc], y[desc]
    ok2 = np.where(np.cumsum(yd) / k >= min_precision)[0]
    t_phish = float(pd_[ok2.max()]) if len(ok2) else 1.0

    if t_safe >= t_phish:  # no clear gap: collapse to one cut-off
        t_safe = t_phish = (t_safe + t_phish) / 2
    return {"t_safe": t_safe, "t_phish": t_phish,
            "max_miss_rate": max_miss_rate, "min_precision": min_precision}


def selective_report(y: np.ndarray, p: np.ndarray, t_safe: float, t_phish: float) -> Dict[str, float]:
    y, p = np.asarray(y), np.asarray(p)
    safe, phish = p <= t_safe, p >= t_phish
    unk = ~safe & ~phish
    return {
        "share_called_legitimate": float(safe.mean()),
        "share_called_phishing": float(phish.mean()),
        "share_unknown": float(unk.mean()),
        "phishing_rate_among_called_legitimate": float(y[safe].mean()) if safe.any() else None,
        "precision_among_called_phishing": float(y[phish].mean()) if phish.any() else None,
        "phishing_share_inside_unknown_zone": float(y[unk].mean()) if unk.any() else None,
    }


# ==========================================================================
# 5. Models
# ==========================================================================
def build_models(fast: bool, pos_weight: float) -> Dict[str, object]:
    models: Dict[str, object] = {
        "logistic_regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=3000, class_weight="balanced", random_state=SEED)),
        "decision_tree": DecisionTreeClassifier(
            max_depth=12, min_samples_leaf=20, class_weight="balanced", random_state=SEED),
        # min_samples_leaf keeps the saved file small enough for GitHub/Render.
        "random_forest": RandomForestClassifier(
            n_estimators=60 if fast else 200, min_samples_leaf=20, max_depth=24,
            class_weight="balanced_subsample", n_jobs=-1, random_state=SEED),
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=60 if fast else 200, learning_rate=0.1, max_depth=3,
            subsample=0.8, random_state=SEED),
    }
    if XGBClassifier is not None:
        models["xgboost"] = XGBClassifier(
            n_estimators=100 if fast else 300, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8, scale_pos_weight=pos_weight,
            eval_metric="logloss", tree_method="hist", n_jobs=-1, random_state=SEED)
    return models


def fit_estimator(name: str, est, X: pd.DataFrame, y: np.ndarray):
    """Fit with the right class-imbalance handling (never by oversampling)."""
    if name == "gradient_boosting":  # has no class_weight option -> sample weights
        est.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        est.fit(X, y)
    return est


def serialized_size_mb(obj) -> float:
    buf = io.BytesIO()
    joblib.dump(obj, buf, compress=3)
    return buf.tell() / 1e6


def cross_validate_pr_auc(name: str, est, X: pd.DataFrame, y: np.ndarray,
                          groups: np.ndarray, folds: int) -> Tuple[Optional[float], Optional[float]]:
    """Group-aware CV on the TRAIN set only; returns mean/std of PR-AUC."""
    if folds < 2:
        return None, None
    scores = []
    sgkf = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=SEED)
    for tr, te in sgkf.split(X, y, groups):
        m = fit_estimator(name, clone(est), X.iloc[tr], y[tr])
        scores.append(average_precision_score(y[te], m.predict_proba(X.iloc[te])[:, 1]))
    return float(np.mean(scores)), float(np.std(scores))


# ==========================================================================
# Plots (skipped quietly if matplotlib is unavailable)
# ==========================================================================
def plot_all(y_test, p_test, thr, val_y, val_raw, val_cal, importance: pd.DataFrame) -> List[str]:
    if plt is None:
        log("matplotlib not installed - plots skipped.")
        return []
    REPORTS_DIR.mkdir(exist_ok=True)
    made = []

    pred = (p_test >= thr).astype(int)
    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(4.5, 4))
    ax.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, f"{v:,}", ha="center", va="center",
                color="white" if v > cm.max() / 2 else "black")
    ax.set_xticks([0, 1], ["pred legit", "pred phish"])
    ax.set_yticks([0, 1], ["true legit", "true phish"])
    ax.set_title(f"Test confusion matrix (threshold {thr:.2f})")
    fig.tight_layout(); fig.savefig(REPORTS_DIR / "confusion_matrix.png", dpi=130); plt.close(fig)
    made.append("confusion_matrix.png")

    fig, axs = plt.subplots(1, 2, figsize=(9, 4))
    fpr, tpr, _ = roc_curve(y_test, p_test)
    axs[0].plot(fpr, tpr); axs[0].plot([0, 1], [0, 1], "--", color="gray")
    axs[0].set(xlabel="False positive rate", ylabel="True positive rate",
               title=f"ROC (AUC {roc_auc_score(y_test, p_test):.3f})")
    pr, rc, _ = precision_recall_curve(y_test, p_test)
    axs[1].plot(rc, pr)
    axs[1].set(xlabel="Recall", ylabel="Precision",
               title=f"PR (AP {average_precision_score(y_test, p_test):.3f})")
    fig.tight_layout(); fig.savefig(REPORTS_DIR / "roc_pr_curves.png", dpi=130); plt.close(fig)
    made.append("roc_pr_curves.png")

    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], "--", color="gray", label="perfect")
    for lbl, pp in (("raw score", val_raw), ("calibrated", val_cal)):
        edges = np.linspace(0, 1, 11)
        idx = np.clip(np.digitize(pp, edges[1:-1]), 0, 9)
        xs = [pp[idx == b].mean() for b in range(10) if (idx == b).sum() >= 20]
        ys = [val_y[idx == b].mean() for b in range(10) if (idx == b).sum() >= 20]
        ax.plot(xs, ys, marker="o", label=lbl)
    ax.set(xlabel="Predicted probability", ylabel="Observed phishing rate",
           title="Reliability curve (validation set)")
    ax.legend(); fig.tight_layout()
    fig.savefig(REPORTS_DIR / "calibration_curve.png", dpi=130); plt.close(fig)
    made.append("calibration_curve.png")

    top = importance.head(15).iloc[::-1]
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.barh(top["feature"], top["importance_mean"], xerr=top["importance_std"])
    ax.set(xlabel="Drop in PR-AUC when shuffled", title="Permutation importance (validation)")
    fig.tight_layout(); fig.savefig(REPORTS_DIR / "feature_importance.png", dpi=130); plt.close(fig)
    made.append("feature_importance.png")
    return made


# ==========================================================================
# Main
# ==========================================================================
def jsonable(o):
    if isinstance(o, dict):
        return {str(k): jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [jsonable(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    return o


def main() -> None:
    global REPORTS_DIR
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=DATA_PATH)
    ap.add_argument("--fast", action="store_true", help="smoke test: subsample + smaller models")
    ap.add_argument("--cv-folds", type=int, default=3, help="0 disables cross-validation")
    ap.add_argument("--max-model-mb", type=float, default=80.0,
                    help="models bigger than this (compressed) are ineligible (GitHub/Render limits)")
    ap.add_argument("--out-models", type=Path, default=MODELS_DIR)
    ap.add_argument("--out-reports", type=Path, default=REPORTS_DIR)
    args = ap.parse_args()

    REPORTS_DIR = args.out_reports
    args.out_models.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    t_start = time.time()
    np.random.seed(SEED)

    log("=" * 70)
    log("SafeWeb model training")
    log("=" * 70)
    df = load_dataset(args.data)
    log("Extracting features ...")
    X, df = build_feature_matrix(df)
    y = df["label"].to_numpy()
    groups = make_groups(df)
    split = assign_splits(y, groups)

    comp = {s: {"rows": int((split == s).sum()), "phishing": int(y[split == s].sum()),
                "phishing_share": float(y[split == s].mean())}
            for s in ("train", "validation", "calibration", "test")}
    log("\nDataset composition (after cleaning):")
    log(f"  total {len(df):,} URLs | legitimate {int((y == 0).sum()):,} | phishing {int((y == 1).sum()):,}")
    for s, c in comp.items():
        log(f"  {s:<12}{c['rows']:>9,} rows   phishing {c['phishing_share']:.1%}")

    tr, va, ca, te = (split == s for s in ("train", "validation", "calibration", "test"))
    Xtr, ytr, gtr = X[tr].reset_index(drop=True), y[tr], groups[tr]
    if args.fast and len(Xtr) > 40_000:
        sub = np.random.RandomState(SEED).choice(len(Xtr), 40_000, replace=False)
        Xtr, ytr, gtr = Xtr.iloc[sub].reset_index(drop=True), ytr[sub], gtr[sub]
        log(f"[fast mode] training subsample: {len(Xtr):,} rows")
    Xva, yva = X[va].reset_index(drop=True), y[va]
    Xca, yca = X[ca].reset_index(drop=True), y[ca]
    Xte, yte = X[te].reset_index(drop=True), y[te]
    if min(len(np.unique(a)) for a in (ytr, yva, yca, yte)) < 2:
        sys.exit("A split has only one class - the dataset is too small.")

    # ---- 5. compare models ------------------------------------------------
    pos_weight = float((ytr == 0).sum() / max((ytr == 1).sum(), 1))
    models = build_models(args.fast, pos_weight)
    log(f"\nComparing {len(models)} models: {', '.join(models)}")
    if XGBClassifier is None:
        log("(xgboost not installed - skipped. `pip install xgboost` to include it.)")
    rows, fitted = [], {}
    for name, est in models.items():
        t0 = time.time()
        try:  # one broken model (e.g. a library version clash) must not stop the whole run
            cv_m, cv_s = cross_validate_pr_auc(name, est, Xtr, ytr, gtr, 0 if args.fast else args.cv_folds)
            m = fit_estimator(name, clone(est), Xtr, ytr)
            p = m.predict_proba(Xva)[:, 1]
            size = serialized_size_mb(m)
        except Exception as exc:
            log(f"  {name:<20} FAILED ({type(exc).__name__}: {exc}) - skipped")
            continue
        fit_s = time.time() - t0
        thr, f1, pr_, rc_ = best_f1_threshold(yva, p)
        pr_auc = float(average_precision_score(yva, p))
        r95 = recall_at_precision(yva, p, 0.95)
        rows.append({
            "model": name, "val_roc_auc": float(roc_auc_score(yva, p)), "val_pr_auc": pr_auc,
            "val_recall_at_precision95": r95, "val_best_f1": f1, "f1_precision": pr_, "f1_recall": rc_,
            "cv_pr_auc_mean": cv_m, "cv_pr_auc_std": cv_s,
            "cv_vs_val_gap": None if cv_m is None else abs(cv_m - pr_auc),
            "size_mb": size, "eligible": size <= args.max_model_mb,
            "selection_score": 0.5 * pr_auc + 0.5 * r95, "fit_seconds": fit_s,
        })
        fitted[name] = m
        log(f"  {name:<20} PR-AUC {pr_auc:.4f}  recall@P95 {r95:.3f}  size {size:.1f} MB  ({fit_s:.0f}s)")
    if not rows:
        sys.exit("Every model failed to train - see the messages above.")

    comp_df = pd.DataFrame(rows).sort_values("selection_score", ascending=False)
    comp_df.to_csv(REPORTS_DIR / "model_comparison.csv", index=False)
    log("\nValidation comparison (selection score = mean of PR-AUC and recall at 95% precision):")
    show = comp_df[["model", "val_roc_auc", "val_pr_auc", "val_recall_at_precision95",
                    "val_best_f1", "cv_pr_auc_mean", "cv_pr_auc_std", "size_mb", "eligible"]]
    log(show.round(4).to_string(index=False))

    eligible = comp_df[comp_df["eligible"]]
    if eligible.empty:
        sys.exit("No model is under --max-model-mb. Raise it or regularise the models.")
    best_name = str(eligible.iloc[0]["model"])
    best_row = eligible.iloc[0]
    log(f"\nSELECTED MODEL: {best_name}")
    if best_row["cv_vs_val_gap"] is not None and best_row["cv_vs_val_gap"] > 0.03:
        log(f"  WARNING: cross-validation and validation PR-AUC differ by {best_row['cv_vs_val_gap']:.3f} "
            "- the estimate is unstable; treat results with caution.")
    best = fitted[best_name]

    # ---- 6. calibration ---------------------------------------------------
    raw_ca = best.predict_proba(Xca)[:, 1]
    raw_va = best.predict_proba(Xva)[:, 1]
    cal_results = {"none": {"brier": float(brier_score_loss(yva, np.clip(raw_va, 0, 1))),
                            "ece": expected_calibration_error(yva, raw_va)}}
    calibrators = {}
    for method in CALIBRATION_METHODS:
        calibrators[method] = fit_calibrator(method, raw_ca, yca)
        pv = apply_calibrator(method, calibrators[method], raw_va)
        cal_results[method] = {"brier": float(brier_score_loss(yva, pv)),
                               "ece": expected_calibration_error(yva, pv)}
    chosen = min(CALIBRATION_METHODS, key=lambda m: (cal_results[m]["ece"], cal_results[m]["brier"]))
    log("\nCalibration (fit on calibration split, scored on validation split; lower = better):")
    for m, r in cal_results.items():
        log(f"  {m:<9} ECE {r['ece']:.4f}   Brier {r['brier']:.4f}" + ("   <- chosen" if m == chosen else ""))

    final = CalibratedPhishingModel(best, chosen, calibrators[chosen], FEATURE_NAMES, best_name)
    pva = final.calibrate(raw_va)

    # ---- thresholds for the UNKNOWN zone (from validation, never from test) --
    th = suggest_thresholds(yva, pva)
    log(f"\nSuggested decision zones from validation data:")
    log(f"  p <= {th['t_safe']:.3f}  -> likely legitimate   (<= {th['max_miss_rate']:.0%} phishing among them)")
    log(f"  p >= {th['t_phish']:.3f}  -> likely phishing     (>= {th['min_precision']:.0%} precision)")
    log("  in between -> UNKNOWN / insufficient evidence")

    # ---- permutation importance ------------------------------------------
    n_imp = min(20_000, len(Xva))
    ix = np.random.RandomState(SEED).choice(len(Xva), n_imp, replace=False)
    pi = permutation_importance(best, Xva.iloc[ix], yva[ix], scoring="average_precision",
                                n_repeats=3, random_state=SEED, n_jobs=1)
    importance = (pd.DataFrame({"feature": FEATURE_NAMES, "importance_mean": pi.importances_mean,
                                "importance_std": pi.importances_std})
                  .sort_values("importance_mean", ascending=False).reset_index(drop=True))
    importance.to_csv(REPORTS_DIR / "feature_importance.csv", index=False)

    # ---- 7. FINAL TEST EVALUATION (first and only use of the test set) -----
    pte = final.predict_phishing_proba(Xte)
    test = {
        "n": int(len(yte)), "phishing_share": float(yte.mean()),
        "roc_auc": float(roc_auc_score(yte, pte)), "pr_auc": float(average_precision_score(yte, pte)),
        "brier": float(brier_score_loss(yte, pte)), "ece": expected_calibration_error(yte, pte),
        "at_threshold_0.5": threshold_metrics(yte, pte, 0.5),
        "at_t_phish": threshold_metrics(yte, pte, th["t_phish"]),
        "selective": selective_report(yte, pte, th["t_safe"], th["t_phish"]),
    }
    log("\n" + "=" * 70)
    log("FINAL TEST RESULTS (held-out domains; touched once)")
    log("=" * 70)
    log(f"Test URLs: {test['n']:,}  (phishing {test['phishing_share']:.1%})")
    log(f"ROC-AUC {test['roc_auc']:.4f} | PR-AUC {test['pr_auc']:.4f} | Brier {test['brier']:.4f} | ECE {test['ece']:.4f}")
    m5 = test["at_threshold_0.5"]
    log(f"At threshold 0.50: accuracy {m5['accuracy']:.4f}, precision {m5['precision']:.4f}, "
        f"recall {m5['recall']:.4f}, F1 {m5['f1']:.4f}, false-positive rate {m5['false_positive_rate']:.4f}")
    log(f"Confusion matrix [tn fp / fn tp]: {m5['tn']:,} {m5['fp']:,} / {m5['fn']:,} {m5['tp']:,}")
    s = test["selective"]
    def pct(v): return "n/a" if v is None else f"{v:.1%}"
    log(f"With the UNKNOWN zone: {pct(s['share_called_legitimate'])} called legitimate "
        f"(phishing among them: {pct(s['phishing_rate_among_called_legitimate'])}), "
        f"{pct(s['share_called_phishing'])} called phishing (precision {pct(s['precision_among_called_phishing'])}), "
        f"{pct(s['share_unknown'])} UNKNOWN.")

    # ---- slices: does it still work when the URL structure hint is removed? --
    masks = {
        "bare domain (no path/query)": ((Xte["path_length"] == 0) & (Xte["query_length"] == 0)).to_numpy(),
        "has a path": (Xte["path_length"] > 0).to_numpy(),
        "has a query string": (Xte["query_length"] > 0).to_numpy(),
    }
    slices = {}
    log("\nPerformance by URL structure (test set):")
    for nm, mk in masks.items():
        ys_, ps_ = yte[mk], pte[mk]
        r = {"n": int(mk.sum()), "phishing_share": float(ys_.mean()) if mk.any() else None}
        if mk.sum() >= 50 and len(np.unique(ys_)) == 2:
            r.update(roc_auc=float(roc_auc_score(ys_, ps_)), pr_auc=float(average_precision_score(ys_, ps_)),
                     recall_at_0_5=float(recall_score(ys_, ps_ >= 0.5, zero_division=0)),
                     false_positive_rate_at_0_5=threshold_metrics(ys_, ps_, 0.5)["false_positive_rate"])
        slices[nm] = r
        log(f"  {nm:<30} n={r['n']:>7,} phishing {pct(r['phishing_share'])}  " +
            (f"ROC-AUC {r['roc_auc']:.3f}  recall {r['recall_at_0_5']:.3f}  FPR {r['false_positive_rate_at_0_5']:.3f}"
             if "roc_auc" in r else "(too few of one class)"))

    # ---- ablations: how much comes from URL-shape shortcuts? ---------------
    ablation = {"all_features": {"roc_auc": test["roc_auc"], "pr_auc": test["pr_auc"]}}
    log("\nAblation on the test set (same algorithm, fewer features):")
    for nm, cols in (("host_only", HOST_FEATURES), ("path_and_length_only", STRUCTURE_FEATURES)):
        m = fit_estimator(best_name, clone(models[best_name]), Xtr[cols], ytr)
        pp = m.predict_proba(Xte[cols])[:, 1]
        ablation[nm] = {"roc_auc": float(roc_auc_score(yte, pp)), "pr_auc": float(average_precision_score(yte, pp)),
                        "features": cols}
    for nm, r in ablation.items():
        log(f"  {nm:<22} ROC-AUC {r['roc_auc']:.3f}   PR-AUC {r['pr_auc']:.3f}")
    log("  -> If 'path_and_length_only' is high, much of the skill comes from URL length/path\n"
        "     differences between the dataset's classes (a shortcut), not from phishing behaviour.")

    log("\nTop features by permutation importance (association, NOT causation):")
    for _, r in importance.head(8).iterrows():
        log(f"  {r['feature']:<24} {r['importance_mean']:.4f} +/- {r['importance_std']:.4f}")

    plots = plot_all(yte, pte, 0.5, yva, raw_va, pva, importance)

    # ---- 8. save artifacts -------------------------------------------------
    model_path = args.out_models / "website_safety_model.joblib"
    joblib.dump(final, model_path, compress=3)
    ranges = {c: {"min": float(Xtr[c].min()), "p0_5": float(Xtr[c].quantile(0.005)),
                  "p99_5": float(Xtr[c].quantile(0.995)), "max": float(Xtr[c].max())} for c in FEATURE_NAMES}
    schema = {"feature_version": FEATURE_VERSION, "feature_names": FEATURE_NAMES,
              "normalization_steps": NORMALIZATION_STEPS, "n_features": len(FEATURE_NAMES),
              "training_feature_ranges": ranges}
    (args.out_models / "feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")

    meta = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "random_seed": SEED, "fast_mode": args.fast,
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                     "numpy": np.__version__, "pandas": pd.__version__},
        "dataset": {"file": str(args.data.name), "rows": int(len(df)), "domains": int(df["domain"].nunique()),
                    "phishing_rows": int(y.sum()), "legitimate_rows": int((y == 0).sum()),
                    "splits": comp, "grouping": "registered domain + shared phishing-kit templates"},
        "model": {"selected": best_name, "estimator": str(best)[:500], "file_size_mb": model_path.stat().st_size / 1e6,
                  "calibration_method": chosen, "calibration_scores_on_validation": cal_results,
                  "imbalance_handling": "class weights / sample weights (no oversampling)"},
        "model_comparison": comp_df.to_dict(orient="records"),
        "decision_zones": th,
        "test_metrics": test, "test_slices": slices, "ablation": ablation,
        "top_features_permutation": importance.head(10).to_dict(orient="records"),
        "limitations": [
            "Trained on URL text only; page content, DNS, certificates and reputation are separate evidence layers.",
            "Class balance in the data (~20% phishing) is not the real-world rate, so precision on live traffic will differ.",
            "Labels come from a public compilation and contain noise; results are estimates, not guarantees.",
            "Feature importance shows association, not causation.",
        ],
        "plots": plots, "training_seconds": time.time() - t_start,
    }
    (args.out_models / "model_metadata.json").write_text(json.dumps(jsonable(meta), indent=2), encoding="utf-8")
    log(f"\nSaved: {model_path.name} ({meta['model']['file_size_mb']:.1f} MB), feature_schema.json, "
        f"model_metadata.json, plus reports in {REPORTS_DIR.name}/")
    log(f"Total time: {(time.time() - t_start) / 60:.1f} min")
    (REPORTS_DIR / "metrics_report.txt").write_text(_LOG.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    main()
