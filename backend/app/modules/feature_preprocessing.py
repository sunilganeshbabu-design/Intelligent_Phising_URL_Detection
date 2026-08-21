"""
MODULE 4: Feature Preprocessing Module
======================================
Responsible for:
- Scaling and standardizing raw feature vectors using Scikit-Learn `StandardScaler` / `MinMaxScaler`.
- Aligning feature vectors to match exact model training schemas.
- Handling missing, NaN, infinite, or out-of-range numerical values.
- Persisting and loading feature scalers (`feature_scaler.joblib`).
- Transforming single inference inputs or high-throughput batch vectors.
"""

import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from sklearn.preprocessing import StandardScaler

from .feature_extraction import FEATURE_NAMES
from ..core.config import settings

class FeaturePreprocessor:
    """
    Module 4 Core Class: Manages transformation, scaling, and validation
    of extracted feature matrices.
    """

    def __init__(self, scaler_path: Optional[Path] = None):
        self.scaler_path = scaler_path or settings.SCALER_PATH
        self.scaler: Optional[StandardScaler] = None
        self._load_or_create_scaler()

    def _load_or_create_scaler(self):
        """Loads saved scaler from disk if available."""
        if self.scaler_path.exists():
            try:
                self.scaler = joblib.load(self.scaler_path)
            except Exception as e:
                print(f"[-] Error loading scaler from {self.scaler_path}: {e}")
                self.scaler = StandardScaler()
        else:
            self.scaler = StandardScaler()

    def fit(self, X: np.ndarray) -> "FeaturePreprocessor":
        """Fits the StandardScaler on training data matrix."""
        self.scaler.fit(X)
        return self

    def save(self, path: Optional[Path] = None):
        """Saves fitted scaler to disk."""
        target_path = path or self.scaler_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.scaler, target_path)

    def transform(self, X: Union[np.ndarray, List[List[float]]]) -> np.ndarray:
        """Applies scaling transformation to feature array."""
        arr = np.array(X, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        
        # Replace NaN / Inf values with 0.0
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e6, neginf=-1e6)

        if self.scaler is not None and hasattr(self.scaler, "mean_") and self.scaler.mean_ is not None:
            return self.scaler.transform(arr)
        return arr

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fits and transforms training data."""
        self.fit(X)
        self.save()
        return self.transform(X)

    @classmethod
    def align_feature_dict(cls, features_dict: Dict[str, Any]) -> List[float]:
        """
        Takes an arbitrary feature dictionary and extracts values in canonical FEATURE_NAMES order,
        safely casting types and imputing missing keys.
        """
        vector = []
        for name in FEATURE_NAMES:
            raw_val = features_dict.get(name, 0.0)
            try:
                val = float(raw_val)
                if np.isnan(val) or np.isinf(val):
                    val = 0.0
            except (ValueError, TypeError):
                val = 0.0
            vector.append(val)
        return vector

    @classmethod
    def get_feature_bounds(cls) -> Dict[str, Dict[str, float]]:
        """
        Returns reference bounds and default ranges for each feature.
        """
        return {
            "url_length": {"min": 5, "max": 500, "default": 25},
            "domain_length": {"min": 3, "max": 100, "default": 12},
            "path_length": {"min": 0, "max": 300, "default": 10},
            "subdomain_count": {"min": 0, "max": 10, "default": 0},
            "count_dots": {"min": 0, "max": 20, "default": 1},
            "count_hyphens": {"min": 0, "max": 20, "default": 0},
            "count_underscores": {"min": 0, "max": 20, "default": 0},
            "count_slashes": {"min": 0, "max": 30, "default": 2},
            "count_question_marks": {"min": 0, "max": 10, "default": 0},
            "count_equals": {"min": 0, "max": 20, "default": 0},
            "count_percent": {"min": 0, "max": 50, "default": 0},
            "count_digits": {"min": 0, "max": 100, "default": 0},
            "https_status": {"min": 0, "max": 1, "default": 1},
            "ip_address": {"min": 0, "max": 1, "default": 0},
            "has_at_symbol": {"min": 0, "max": 1, "default": 0},
            "has_double_slash_redirect": {"min": 0, "max": 1, "default": 0},
            "has_prefix_suffix": {"min": 0, "max": 1, "default": 0},
            "is_shortened_url": {"min": 0, "max": 1, "default": 0},
            "suspicious_keywords": {"min": 0, "max": 10, "default": 0},
            "entropy": {"min": 0.0, "max": 6.0, "default": 3.5},
            "tld_risk_score": {"min": 0.0, "max": 1.0, "default": 0.1}
        }

# Global singleton instance
default_preprocessor = FeaturePreprocessor()
