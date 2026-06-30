"""
generate_artifacts.py
---------------------
Standalone script that replicates the MLT_Project notebook's preprocessing
and XGBoost training logic, then saves the four .pkl model artifacts plus
metrics.json to the same directory as this script.

Usage:
    python generate_artifacts.py
"""

import json
import os

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from imblearn.over_sampling import SMOTE
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    train_test_split,
)
from sklearn.preprocessing import LabelEncoder

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(SCRIPT_DIR, "cybersecurity_threat_dataset.csv")
MODEL_PATH = os.path.join(SCRIPT_DIR, "malware_detector_model.pkl")
ENCODERS_PATH = os.path.join(SCRIPT_DIR, "malware_detector_encoders.pkl")
FEATURES_PATH = os.path.join(SCRIPT_DIR, "malware_detector_features.pkl")
CAT_COLS_PATH = os.path.join(SCRIPT_DIR, "malware_detector_cat_cols.pkl")
METRICS_PATH = os.path.join(SCRIPT_DIR, "metrics.json")


def load_and_inject_noise(csv_path: str) -> pd.DataFrame:
    """Load the raw CSV and inject realistic noise into categorical columns."""
    np.random.seed(42)

    df = pd.read_csv(csv_path)

    mal_idx = df["label"] == 1
    ben_idx = df["label"] == 0
    idx_mal = df.index[mal_idx]
    idx_ben = df.index[ben_idx]
    n_mal, n_ben = mal_idx.sum(), ben_idx.sum()

    # -- threat_type --
    threat_types = ["botnet_cc", "phishing", "trojan", "ransomware", "spyware"]
    df.loc[idx_mal, "threat_type"] = np.random.choice(threat_types, size=n_mal)
    df.loc[idx_ben, "threat_type"] = "benign"
    flip_ben = np.random.rand(n_ben) < 0.25
    df.loc[idx_ben[flip_ben], "threat_type"] = np.random.choice(
        threat_types, size=flip_ben.sum()
    )
    flip_mal = np.random.rand(n_mal) < 0.15
    df.loc[idx_mal[flip_mal], "threat_type"] = "benign"

    # -- malware_family --
    malware_families = [
        "emotet",
        "trickbot",
        "qakbot",
        "cobalt_strike",
        "redline_stealer",
        "lockbit",
    ]
    fam_probs = np.array([0.22, 0.20, 0.15, 0.15, 0.14, 0.14])
    fam_probs /= fam_probs.sum()
    df.loc[idx_mal, "malware_family"] = np.random.choice(
        malware_families, size=n_mal, p=fam_probs
    )
    flip_unknown = np.random.rand(n_mal) < 0.20
    df.loc[idx_mal[flip_unknown], "malware_family"] = "none"
    df.loc[idx_ben, "malware_family"] = "none"
    flip_fp = np.random.rand(n_ben) < 0.10
    df.loc[idx_ben[flip_fp], "malware_family"] = np.random.choice(
        malware_families, size=flip_fp.sum()
    )

    # -- confidence_level --
    df.loc[idx_mal, "confidence_level"] = (
        np.clip(np.random.normal(58, 22, n_mal), 0, 100).round().astype(int)
    )
    df.loc[idx_ben, "confidence_level"] = (
        np.clip(np.random.normal(40, 22, n_ben), 0, 100).round().astype(int)
    )

    # -- dst_port --
    common_mal_ports = [443, 8080, 4444, 6667, 80, 53, 8443, 1337, 9001]
    common_ben_ports = [80, 443, 22, 25, 53, 3306, 8080, 21]
    mp = np.array([0.18, 0.18, 0.10, 0.07, 0.18, 0.10, 0.07, 0.06, 0.06])
    mp /= mp.sum()
    bp = np.array([0.22, 0.20, 0.13, 0.08, 0.15, 0.08, 0.08, 0.06])
    bp /= bp.sum()
    df.loc[idx_mal, "dst_port"] = np.random.choice(common_mal_ports, size=n_mal, p=mp)
    df.loc[idx_ben, "dst_port"] = np.random.choice(common_ben_ports, size=n_ben, p=bp)

    # -- days_active --
    df.loc[idx_mal, "days_active"] = (
        np.clip(np.random.exponential(9, n_mal), 0, 90).round().astype(int)
    )
    df.loc[idx_ben, "days_active"] = (
        np.clip(np.random.exponential(6, n_ben), 0, 90).round().astype(int)
    )

    # -- src_country --
    countries = ["US", "RU", "CN", "NL", "DE", "BR", "IN", "VN", "FR", "GB", "UA", "KR"]
    mal_probs = np.array(
        [0.13, 0.14, 0.12, 0.08, 0.07, 0.07, 0.08, 0.08, 0.06, 0.06, 0.07, 0.04]
    )
    mal_probs /= mal_probs.sum()
    ben_probs = np.array(
        [0.18, 0.06, 0.06, 0.10, 0.11, 0.06, 0.10, 0.05, 0.09, 0.10, 0.04, 0.05]
    )
    ben_probs /= ben_probs.sum()
    df.loc[idx_mal, "src_country"] = np.random.choice(
        countries, size=n_mal, p=mal_probs
    )
    df.loc[idx_ben, "src_country"] = np.random.choice(
        countries, size=n_ben, p=ben_probs
    )

    # -- ioc_type --
    ioc_types = ["ip", "domain", "url", "hash"]
    df.loc[idx_mal, "ioc_type"] = np.random.choice(
        ioc_types, size=n_mal, p=[0.32, 0.33, 0.20, 0.15]
    )
    df.loc[idx_ben, "ioc_type"] = np.random.choice(
        ioc_types, size=n_ben, p=[0.35, 0.30, 0.22, 0.13]
    )

    # -- tags --
    tag_pool_mal = [
        "c2",
        "exfil",
        "suspicious",
        "recon",
        "lateral_movement",
        "persistence",
        "none",
    ]
    tag_pool_ben = ["scanner", "research", "cdn", "known_good", "monitoring", "none"]
    df.loc[idx_mal, "tags"] = np.random.choice(
        tag_pool_mal, size=n_mal, p=[0.16, 0.13, 0.15, 0.10, 0.10, 0.10, 0.26]
    )
    df.loc[idx_ben, "tags"] = np.random.choice(
        tag_pool_ben, size=n_ben, p=[0.13, 0.13, 0.13, 0.13, 0.10, 0.38]
    )

    # -- reporter --
    reporters = [
        "analyst_team_a",
        "analyst_team_b",
        "automated_feed_1",
        "automated_feed_2",
        "partner_org",
        "honeypot_net",
    ]
    df.loc[idx_mal, "reporter"] = np.random.choice(
        reporters, size=n_mal, p=[0.17, 0.17, 0.22, 0.18, 0.12, 0.14]
    )
    df.loc[idx_ben, "reporter"] = np.random.choice(
        reporters, size=n_ben, p=[0.18, 0.18, 0.17, 0.13, 0.18, 0.16]
    )

    return df


def preprocess(df: pd.DataFrame):
    """Split, label-encode categoricals (fit on train only), return split data + encoders."""
    df_model = df.copy()
    df_model["tags"] = df_model["tags"].fillna("none")

    target_col = "label"
    cat_cols = [
        "ioc_type",
        "threat_type",
        "malware_family",
        "src_country",
        "tags",
        "reporter",
    ]

    y = df_model[target_col]
    X = df_model.drop(columns=[target_col, "timestamp", "ioc_value"])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    encoders = {}
    X_train = X_train.copy()
    X_test = X_test.copy()
    for col in cat_cols:
        enc = LabelEncoder()
        X_train[col] = enc.fit_transform(X_train[col].astype(str))
        known = set(enc.classes_)
        X_test[col] = (
            X_test[col]
            .astype(str)
            .apply(lambda v: v if v in known else enc.classes_[0])
        )
        X_test[col] = enc.transform(X_test[col])
        encoders[col] = enc

    return X, X_train, X_test, y_train, y_test, encoders, cat_cols


def apply_smote(X_train, y_train):
    """Apply SMOTE when class imbalance ratio > 2, otherwise pass through."""
    class_counts = pd.Series(y_train).value_counts()
    imbalance_ratio = y_train.value_counts().max() / y_train.value_counts().min()
    if imbalance_ratio > 2:
        smote = SMOTE(random_state=42, k_neighbors=min(5, class_counts.min() - 1))
        X_res, y_res = smote.fit_resample(X_train, y_train)
    else:
        X_res, y_res = X_train, y_train
    return X_res, y_res


def train_xgboost(X_train_res, y_train_res):
    """Run RandomizedSearchCV over XGBoost and return the search object + best estimator."""
    pos_weight = (y_train_res == 0).sum() / max((y_train_res == 1).sum(), 1)

    base_xgb = xgb.XGBClassifier(
        random_state=42,
        n_jobs=-1,
        eval_metric="logloss",
        verbosity=0,
    )

    param_dist = {
        "n_estimators": [200, 300, 500, 800],
        "max_depth": [3, 4, 5, 6, 8],
        "learning_rate": [0.01, 0.03, 0.05, 0.1],
        "subsample": [0.7, 0.8, 0.9, 1.0],
        "colsample_bytree": [0.6, 0.8, 1.0],
        "min_child_weight": [1, 3, 5],
        "reg_alpha": [0, 0.1, 0.5],
        "reg_lambda": [0.5, 1, 2],
        "scale_pos_weight": [1, pos_weight],
    }

    cv_search = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    search = RandomizedSearchCV(
        base_xgb,
        param_distributions=param_dist,
        n_iter=30,
        scoring="roc_auc",
        cv=cv_search,
        random_state=42,
        n_jobs=-1,
        verbose=0,
    )

    search.fit(X_train_res, y_train_res)
    return search, search.best_estimator_


def build_metrics(
    xgb_model,
    search,
    X,
    X_train,
    X_test,
    y_train,
    y_train_res,
    y_test,
) -> dict:
    """Compute all evaluation metrics and return as a dict."""
    y_pred = xgb_model.predict(X_test)
    y_prob = xgb_model.predict_proba(X_test)[:, 1]
    cm = confusion_matrix(y_test, y_pred).tolist()

    fi = dict(zip(list(X.columns), xgb_model.feature_importances_.tolist()))
    fi_top20 = dict(sorted(fi.items(), key=lambda x: x[1], reverse=True)[:20])

    metrics = {
        "model": "XGBoost",
        "task": "binary_classification",
        "classes": ["benign", "malware"],
        "train_size": int(X_train.shape[0]),
        "test_size": int(X_test.shape[0]),
        "features": list(X.columns),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro")),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro")),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro")),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
        "confusion_matrix": cm,
        "best_params": search.best_params_,
        "best_cv_roc_auc": float(search.best_score_),
        "hyperparameter_search": {
            "method": "RandomizedSearchCV",
            "n_iter": 30,
            "cv_folds": 5,
            "scoring": "roc_auc",
        },
        "class_balance": {
            "method": "SMOTE",
            "train_before_smote": {
                "benign": int((y_train == 0).sum()),
                "malware": int((y_train == 1).sum()),
            },
            "train_after_smote": {
                "benign": int((y_train_res == 0).sum()),
                "malware": int((y_train_res == 1).sum()),
            },
        },
        "feature_importance_top20": fi_top20,
    }
    return metrics


def main():
    print("=" * 60)
    print("  Malware Detector — Artifact Generation")
    print("=" * 60)

    # 1. Load + noise injection
    print("\n[1/5] Loading dataset and injecting noise...")
    df = load_and_inject_noise(CSV_PATH)
    print(f"      Dataset shape: {df.shape}")

    # 2. Preprocessing
    print("[2/5] Preprocessing (split + label-encode)...")
    X, X_train, X_test, y_train, y_test, encoders, cat_cols = preprocess(df)
    print(f"      Train: {X_train.shape[0]} rows | Test: {X_test.shape[0]} rows")

    # 3. SMOTE
    print("[3/5] Applying SMOTE (if needed)...")
    X_train_res, y_train_res = apply_smote(X_train, y_train)
    print(
        f"      After SMOTE — benign: {(y_train_res == 0).sum()} | malware: {(y_train_res == 1).sum()}"
    )

    # 4. Train
    print("[4/5] Training XGBoost with RandomizedSearchCV (n_iter=30, cv=5)...")
    print("      (This may take a few minutes...)")
    search, xgb_model = train_xgboost(X_train_res, y_train_res)
    print(f"      Best CV ROC-AUC: {search.best_score_:.4f}")
    print(f"      Best params:     {search.best_params_}")

    # 5. Evaluate + save
    print("[5/5] Evaluating and saving artifacts...")
    metrics = build_metrics(
        xgb_model, search, X, X_train, X_test, y_train, y_train_res, y_test
    )

    joblib.dump(xgb_model, MODEL_PATH)
    joblib.dump(encoders, ENCODERS_PATH)
    joblib.dump(list(X.columns), FEATURES_PATH)
    joblib.dump(cat_cols, CAT_COLS_PATH)

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print("\n  Artifacts saved:")
    for path in [MODEL_PATH, ENCODERS_PATH, FEATURES_PATH, CAT_COLS_PATH, METRICS_PATH]:
        print(f"    {os.path.relpath(path, SCRIPT_DIR)}")

    print("\n" + "=" * 60)
    print("  METRICS SUMMARY")
    print("=" * 60)
    print(f"  Accuracy:          {metrics['accuracy']:.4f}")
    print(f"  F1 (macro):        {metrics['f1_macro']:.4f}")
    print(f"  Precision (macro): {metrics['precision_macro']:.4f}")
    print(f"  Recall (macro):    {metrics['recall_macro']:.4f}")
    print(f"  ROC-AUC:           {metrics['roc_auc']:.4f}")
    print(f"  Best CV ROC-AUC:   {metrics['best_cv_roc_auc']:.4f}")
    print(f"  Confusion matrix:  {metrics['confusion_matrix']}")
    print("=" * 60)
    print("\nDone.")


if __name__ == "__main__":
    main()
