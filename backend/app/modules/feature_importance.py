"""
MODULE 8: Feature Importance Analysis Module
============================================
Responsible for:
- Computing Global Model Feature Importance using XGBoost feature importance metrics (Gain & Weight).
- Ranking global feature importances across the 21 extracted lexical, structural, and protocol features.
- Computing Local Instance Feature Importance rankings (positive risk drivers vs. negative legitimacy mitigators).
- Categorizing feature impacts by analytical domain (Lexical, Structural, Protocol, Content, Registry).
- Providing serialized visual data structures for radar, bar, and waterfall charts in the frontend.
"""

import numpy as np
from typing import Dict, Any, List, Optional

from .feature_extraction import FEATURE_METADATA, FEATURE_NAMES
from .classification import default_classifier

class FeatureImportanceAnalyzer:
    """
    Module 8 Core Class: Computes and analyzes global and localized feature importance for XGBoost.
    """

    @classmethod
    def get_global_importance(cls, model_name: str = "XGBoost") -> Dict[str, Any]:
        """
        Extracts and normalizes global feature importances from the XGBoost model.
        """
        model = default_classifier.models.get("XGBoost")
        if model is None:
            default_classifier._ensure_models_loaded()
            model = default_classifier.models.get("XGBoost")

        if model is not None and hasattr(model, "feature_importances_"):
            raw_importances = model.feature_importances_
            # Normalize to sum to 1.0
            sum_imp = float(np.sum(raw_importances))
            if sum_imp > 0:
                raw_importances = raw_importances / sum_imp
        else:
            raw_importances = np.ones(len(FEATURE_NAMES)) / len(FEATURE_NAMES)

        meta_map = {f["name"]: f for f in FEATURE_METADATA}
        importances = []
        for i, name in enumerate(FEATURE_NAMES):
            weight = float(raw_importances[i])
            meta = meta_map.get(name, {"display": name, "category": "General", "desc": ""})
            importances.append({
                "feature_name": name,
                "display_name": meta["display"],
                "category": meta.get("category", "General"),
                "importance_score": round(weight * 100.0, 2),
                "raw_weight": round(weight, 5),
                "description": meta["desc"]
            })

        importances.sort(key=lambda x: x["importance_score"], reverse=True)

        # Aggregate category-level importance
        category_scores = {}
        for item in importances:
            cat = item["category"]
            category_scores[cat] = round(category_scores.get(cat, 0.0) + item["importance_score"], 2)

        return {
            "model_name": "XGBoost",
            "total_features": len(FEATURE_NAMES),
            "feature_rankings": importances,
            "category_breakdown": category_scores,
            "top_feature": importances[0] if importances else None
        }

    @classmethod
    def get_local_importance(cls, shap_contributions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes and categorizes local prediction feature contributions for a specific custom URL.
        """
        positive_drivers = []
        negative_mitigators = []
        neutral_factors = []

        total_magnitude = sum(abs(item.get("contribution", 0.0)) for item in shap_contributions)
        if total_magnitude == 0:
            total_magnitude = 1.0

        ranked_local = []
        sorted_items = sorted(shap_contributions, key=lambda x: abs(x.get("contribution", 0.0)), reverse=True)

        for item in sorted_items:
            contrib = float(item.get("contribution", 0.0))
            weight_pct = round((abs(contrib) / total_magnitude) * 100.0, 1)
            
            enhanced_item = {
                "feature_name": item.get("feature_name"),
                "display_name": item.get("display_name", item.get("feature_name")),
                "value": item.get("value"),
                "contribution": contrib,
                "direction": item.get("direction", "Phishing Indicator" if contrib > 0 else ("Legitimacy Indicator" if contrib < 0 else "Neutral")),
                "local_weight_pct": weight_pct,
                "description": item.get("description", "")
            }
            ranked_local.append(enhanced_item)

            if contrib > 0.02:
                positive_drivers.append(enhanced_item)
            elif contrib < -0.02:
                negative_mitigators.append(enhanced_item)
            else:
                neutral_factors.append(enhanced_item)

        return {
            "total_evaluated": len(shap_contributions),
            "phishing_drivers_count": len(positive_drivers),
            "legitimacy_mitigators_count": len(negative_mitigators),
            "neutral_count": len(neutral_factors),
            "ranked_local_features": ranked_local,
            "top_phishing_drivers": positive_drivers[:5],
            "top_legitimacy_mitigators": negative_mitigators[:5]
        }
