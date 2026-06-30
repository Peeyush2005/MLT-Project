"""
Inference module for the malware detection model.

Loads all PKL artifacts on module import and exposes predict_malware()
and predict_batch() for use by API routes.

PKL files are located two levels above this file's parent:
  MLT Project/backend/app/  →  MLT Project/
"""

import json
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Path(__file__)             = MLT Project/backend/app/inference.py
# Path(__file__).parent      = MLT Project/backend/app/
# ...parent.parent           = MLT Project/backend/
# ...parent.parent.parent    = MLT Project/    <-- PKL files live here
_APP_DIR = Path(__file__).parent  # MLT Project/backend/app/
_ARTIFACTS_DIR = (
    _APP_DIR.parent.parent
)  # MLT Project/  (2 hops: app -> backend -> project root)

_MODEL_PATH = _ARTIFACTS_DIR / "malware_detector_model.pkl"
_ENCODERS_PATH = _ARTIFACTS_DIR / "malware_detector_encoders.pkl"
_FEATURES_PATH = _ARTIFACTS_DIR / "malware_detector_features.pkl"
_CAT_COLS_PATH = _ARTIFACTS_DIR / "malware_detector_cat_cols.pkl"
_METRICS_PATH = _ARTIFACTS_DIR / "metrics.json"

# Target class labels (index → name)
TARGET_CLASSES = ["benign", "malware"]


# ---------------------------------------------------------------------------
# Artifact loading (fail-fast)
# ---------------------------------------------------------------------------
def _load_artifacts() -> tuple:
    missing = []
    for p in [_MODEL_PATH, _ENCODERS_PATH, _FEATURES_PATH, _CAT_COLS_PATH]:
        if not p.exists():
            missing.append(str(p))

    if missing:
        print("=" * 60, file=sys.stderr)
        print("ERROR: Required ML artifact files not found:", file=sys.stderr)
        for m in missing:
            print(f"  MISSING → {m}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Expected artifact files:", file=sys.stderr)
        print(f"  {_MODEL_PATH}", file=sys.stderr)
        print(f"  {_ENCODERS_PATH}", file=sys.stderr)
        print(f"  {_FEATURES_PATH}", file=sys.stderr)
        print(f"  {_CAT_COLS_PATH}", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        raise FileNotFoundError(
            f"Missing ML artifact(s): {missing}. "
            "Ensure PKL files are placed in the MLT Project/ root directory."
        )

    model = joblib.load(_MODEL_PATH)
    encoders = joblib.load(_ENCODERS_PATH)
    features = joblib.load(_FEATURES_PATH)
    cat_cols = joblib.load(_CAT_COLS_PATH)
    return model, encoders, features, cat_cols


def _load_metrics() -> dict:
    if not _METRICS_PATH.exists():
        print(f"WARNING: metrics.json not found at {_METRICS_PATH}", file=sys.stderr)
        return {}
    with open(_METRICS_PATH, "r") as fh:
        return json.load(fh)


loaded_model, loaded_encoders, loaded_features, loaded_cat_cols = _load_artifacts()
loaded_metrics: dict = _load_metrics()

# ---------------------------------------------------------------------------
# Single-record inference
# ---------------------------------------------------------------------------


def predict_malware(raw_record: dict) -> dict:
    """
    Predict whether a single IOC record is benign or malware.

    Parameters
    ----------
    raw_record : dict
        Feature names as keys with raw human-readable values.
        e.g. {"ioc_type": "domain", "src_country": "RU", "dst_port": 4444, ...}

    Returns
    -------
    dict with keys: prediction, class_index, confidence, all_probabilities
    """
    df_input = pd.DataFrame([raw_record])
    df_input = df_input.reindex(columns=loaded_features, fill_value=0)

    for col in loaded_cat_cols:
        enc = loaded_encoders[col]
        val = str(df_input.at[0, col])
        safe_val = val if val in set(enc.classes_) else enc.classes_[0]
        df_input[col] = enc.transform([safe_val])

    pred_idx = int(loaded_model.predict(df_input)[0])
    pred_proba = loaded_model.predict_proba(df_input)[0]
    pred_label = TARGET_CLASSES[pred_idx]
    confidence = float(pred_proba.max())

    return {
        "prediction": pred_label,
        "class_index": pred_idx,
        "confidence": confidence,
        "all_probabilities": {
            cls: float(p) for cls, p in zip(TARGET_CLASSES, pred_proba)
        },
    }


# ---------------------------------------------------------------------------
# Batch inference (vectorized)
# ---------------------------------------------------------------------------


def predict_batch(records: list[dict]) -> list[dict]:
    """
    Predict a batch of IOC records using vectorized DataFrame operations.

    Parameters
    ----------
    records : list[dict]
        Each dict has feature names as keys with raw human-readable values.

    Returns
    -------
    list[dict] in the same order, each with prediction / class_index /
    confidence / all_probabilities keys.
    """
    df = pd.DataFrame(records)
    df = df.reindex(columns=loaded_features, fill_value=0)

    for col in loaded_cat_cols:
        enc = loaded_encoders[col]
        known_set = set(enc.classes_)
        fallback = enc.classes_[0]
        safe_vals = (
            df[col].astype(str).apply(lambda v: v if v in known_set else fallback)
        )
        df[col] = enc.transform(safe_vals)

    pred_indices = loaded_model.predict(df).astype(int)
    pred_probas = loaded_model.predict_proba(df)

    results = []
    for idx, proba in zip(pred_indices, pred_probas):
        label = TARGET_CLASSES[idx]
        results.append(
            {
                "prediction": label,
                "class_index": int(idx),
                "confidence": float(proba.max()),
                "all_probabilities": {
                    cls: float(p) for cls, p in zip(TARGET_CLASSES, proba)
                },
            }
        )
    return results


# ---------------------------------------------------------------------------
# Helpers exposed to routes
# ---------------------------------------------------------------------------


def get_feature_importances(top_n: int = 20) -> list[dict]:
    """Return sorted feature importances from the loaded model."""
    importances = loaded_model.feature_importances_
    pairs = sorted(
        zip(loaded_features, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    return [{"feature": feat, "importance": float(imp)} for feat, imp in pairs[:top_n]]


def get_categorical_vocabularies() -> dict[str, list[str]]:
    """Return encoder classes for each categorical column."""
    return {col: list(loaded_encoders[col].classes_) for col in loaded_cat_cols}


def get_model_hyperparameters() -> dict[str, Any]:
    """Return XGBoost model hyperparameters."""
    return {k: v for k, v in loaded_model.get_params().items()}
