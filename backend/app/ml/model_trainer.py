"""
XGBoost Model Training & Evaluation Pipeline
============================================
Trains a genuine, high-performance XGBClassifier (Extreme Gradient Boosting)
on the project's phishing URL dataset, calculates independent test split metrics,
computes global feature importance, and persists model artifacts.
"""

import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)

from .feature_extractor import FEATURE_NAMES, FEATURE_METADATA
from ..core.config import settings

def train_and_save_models(force_regenerate: bool = False) -> Dict[str, Any]:
    """
    Executes end-to-end training and evaluation of the genuine XGBoost Classifier.
    Persists trained model (.joblib & .json), scaler, background samples, and metrics to disk.
    """
    dataset_path = settings.BENCHMARK_DATASET_PATH
    
    if not dataset_path.exists():
        from .dataset_generator import generate_benchmark_dataset
        df = generate_benchmark_dataset(sample_size=5000)
    else:
        df = pd.read_csv(dataset_path)

    # 1. Dataset Cleaning & Validation
    df = df.dropna(subset=FEATURE_NAMES + ["label"])
    if "url" in df.columns:
        df = df.drop_duplicates(subset=["url"])
    df["label"] = df["label"].astype(int)
    
    X = df[FEATURE_NAMES].values.astype(np.float64)
    y = df["label"].values.astype(int)
    
    # 2. Stratified Train / Test Split (80% Train, 20% Holdout Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 3. Feature Scaling
    scaler = StandardScaler()
    scaler.fit(X_train)
    
    # 4. Genuine XGBoost Binary Classifier with Hyperparameter Tuning
    xgb_model = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=2,
        gamma=0.1,
        reg_alpha=0.05,
        reg_lambda=1.0,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )
    
    # Train model on training partition
    xgb_model.fit(X_train, y_train)
    
    # 5. Independent Test Set Evaluation
    y_pred_xgb = xgb_model.predict(X_test)
    y_prob_xgb = xgb_model.predict_proba(X_test)[:, 1]
    
    cm = confusion_matrix(y_test, y_pred_xgb).tolist()
    
    acc = float(accuracy_score(y_test, y_pred_xgb))
    prec = float(precision_score(y_test, y_pred_xgb, zero_division=0))
    rec = float(recall_score(y_test, y_pred_xgb, zero_division=0))
    f1 = float(f1_score(y_test, y_pred_xgb, zero_division=0))
    roc = float(roc_auc_score(y_test, y_prob_xgb))
    
    # 6. Global Feature Importances (Weight & Gain)
    raw_importances = xgb_model.feature_importances_
    feature_importance_list = []
    for idx, name in enumerate(FEATURE_NAMES):
        meta = next((m for m in FEATURE_METADATA if m["name"] == name), {"display": name, "desc": ""})
        feature_importance_list.append({
            "feature_name": name,
            "display_name": meta["display"],
            "importance": round(float(raw_importances[idx]), 4),
            "rank": idx + 1
        })
    feature_importance_list.sort(key=lambda x: x["importance"], reverse=True)
    for rank, item in enumerate(feature_importance_list, start=1):
        item["rank"] = rank
    
    xgb_metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc, 4),
        "confusion_matrix": {
            "true_negative": cm[0][0],
            "false_positive": cm[0][1],
            "false_negative": cm[1][0],
            "true_positive": cm[1][1]
        }
    }
    
    metrics = {
        "dataset_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "primary_model": "XGBoost",
        "models": {
            "XGBoost": xgb_metrics
        },
        "global_feature_importance": feature_importance_list
    }
    
    # 7. Persist Artifacts to Disk
    settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Save joblib and native json models
    joblib_path = settings.MODELS_DIR / "xgb_phishing_model.joblib"
    json_path = settings.MODELS_DIR / "xgb_phishing_model.json"
    
    joblib.dump(xgb_model, joblib_path)
    xgb_model.save_model(str(json_path))
    
    joblib.dump(scaler, settings.SCALER_PATH)
    
    # Save representative training background for SHAP / LIME (100 samples)
    np.save(settings.MODELS_DIR / "background_X.npy", X_train[:100])
    
    with open(settings.METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
        
    print(f"[+] XGBoost model successfully trained on {len(X_train)} samples and evaluated on {len(X_test)} holdout test samples.")
    print(f"[+] Test Metrics: Accuracy={acc*100:.2f}%, Precision={prec*100:.2f}%, Recall={rec*100:.2f}%, F1={f1*100:.2f}%, ROC-AUC={roc:.4f}")
    print(f"[+] Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")
    print(f"[+] Saved artifacts to {settings.MODELS_DIR}")
    
    return metrics

def get_model_metrics() -> Dict[str, Any]:
    """Retrieves saved test evaluation metrics from disk or executes training."""
    if settings.METRICS_PATH.exists():
        try:
            with open(settings.METRICS_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return train_and_save_models()
