"""
MODULE 5: Phishing URL Classification Module
============================================
Responsible for:
- State-of-the-art XGBoost (Extreme Gradient Boosting) machine learning model training, evaluation, and inference.
- Model implementation:
    1. XGBoost Classifier (Primary gradient boosted decision trees with 150 estimators, logloss optimization, subsample/colsample regularization)
- Comprehensive performance evaluation:
    - Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrix.
- Model artifact persistence (`xgb_phishing_model.joblib` and `xgb_phishing_model.json`) and dynamic in-memory hot-reloading.
- Real-time single URL and batch feature classification with genuine `predict_proba()`.
"""

import json
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from xgboost import XGBClassifier

from .feature_extraction import FEATURE_NAMES
from .feature_preprocessing import FeaturePreprocessor, default_preprocessor
from ..ml.model_trainer import train_and_save_models
from ..core.config import settings

class PhishingClassifier:
    """
    Module 5 Core Class: Handles training, caching, and real-time inference for the XGBoost phishing classifier.
    """

    def __init__(self, models_dir: Optional[Path] = None):
        self.models_dir = models_dir or settings.MODELS_DIR
        self.models: Dict[str, Any] = {}
        self.preprocessor = default_preprocessor
        self.metrics: Dict[str, Any] = {}
        self._ensure_models_loaded()

    def _ensure_models_loaded(self, force_retrain: bool = False):
        """Loads cached XGBoost model from disk or initiates training."""
        xgb_joblib_path = self.models_dir / "xgb_phishing_model.joblib"
        xgb_json_path = self.models_dir / "xgb_phishing_model.json"

        if force_retrain or (not xgb_joblib_path.exists() and not xgb_json_path.exists()):
            self.train_all_models()
        else:
            try:
                if xgb_joblib_path.exists():
                    self.models["XGBoost"] = joblib.load(xgb_joblib_path)
                elif xgb_json_path.exists():
                    model = XGBClassifier()
                    model.load_model(str(xgb_json_path))
                    self.models["XGBoost"] = model
                self._load_metrics()
            except Exception as e:
                print(f"[-] Error loading XGBoost model artifact ({e}), retraining...")
                self.train_all_models()

    def _load_metrics(self):
        """Loads saved evaluation metrics from JSON file."""
        if settings.METRICS_PATH.exists():
            try:
                with open(settings.METRICS_PATH, "r") as f:
                    self.metrics = json.load(f)
            except Exception:
                pass

    def train_all_models(self, sample_size: int = 5000) -> Dict[str, Any]:
        """
        Executes full training pipeline on benchmark dataset and computes test metrics for XGBoost.
        """
        self.metrics = train_and_save_models(force_regenerate=False)
        
        xgb_path = self.models_dir / "xgb_phishing_model.joblib"
        if xgb_path.exists():
            self.models["XGBoost"] = joblib.load(xgb_path)
            
        return self.metrics

    def predict_features(
        self, 
        features_vector: List[float], 
        model_name: str = "XGBoost"
    ) -> Tuple[str, float, float, Any]:
        """
        Classifies a single feature vector using the genuine XGBoost engine.
        Returns:
            - prediction ("Phishing" or "Legitimate")
            - phishing_probability (0.0 to 100.0)
            - confidence_score (0.0 to 100.0)
            - active_model_instance
        """
        self._ensure_models_loaded()
        x_input = np.array(features_vector, dtype=np.float64).reshape(1, -1)

        # Retrieve XGBoost model
        model = self.models.get("XGBoost") or list(self.models.values())[0]
        proba = model.predict_proba(x_input)[0]

        phishing_probability = round(float(proba[1]) * 100.0, 2)
        prediction = "Phishing" if phishing_probability >= 50.0 else "Legitimate"
        confidence_score = phishing_probability if prediction == "Phishing" else round(100.0 - phishing_probability, 2)

        return prediction, phishing_probability, confidence_score, model

    def compare_all_models(self, features_vector: List[float]) -> Dict[str, Any]:
        """
        Returns prediction telemetry from the XGBoost classification engine.
        """
        pred, prob, conf, _ = self.predict_features(features_vector, model_name="XGBoost")
        return {
            "XGBoost": {
                "prediction": pred,
                "phishing_probability": prob,
                "confidence_score": conf,
                "engine": "Extreme Gradient Boosting"
            }
        }

# Global singleton
default_classifier = PhishingClassifier()
