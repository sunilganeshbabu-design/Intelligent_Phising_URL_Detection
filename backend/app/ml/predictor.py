import joblib
import numpy as np
import datetime
import time
from urllib.parse import urlparse

from ..modules.url_validation import URLValidator
from ..modules.feature_extraction import URLFeatureExtractor, extract_features, clean_url, FEATURE_NAMES
from ..modules.classification import PhishingClassifier, default_classifier
from ..modules.risk_analysis import RiskConfidenceAnalyzer
from ..modules.xai_engine import ExplainableAIEngine, explain_prediction_shap, explain_prediction_lime
from ..modules.security_recommendations import SecurityRecommendationEngine
from .threat_intel import analyze_threat_intelligence
from ..models.schemas import PredictResponse, ExtractedFeaturesSchema, XAIExplanation
from ..core.config import settings

def load_models(force_reload: bool = False):
    """Ensures ML models are loaded and initialized."""
    default_classifier._ensure_models_loaded(force_retrain=force_reload)

def get_risk_level(prob: float) -> str:
    tier, _, _ = RiskConfidenceAnalyzer.calculate_risk_tier(prob)
    return tier

def predict_url(
    raw_url: str, 
    model_name: str = "XGBoost", 
    include_xai: bool = True
) -> PredictResponse:
    """
    Performs end-to-end real-time live network probing, feature extraction,
    ML classification, risk calibration, and XAI explainability for ANY URL provided by the user.
    """
    start_time = time.perf_counter()
    load_models()
    
    # 1. URL Input & Validation (Module 2) + Feature Extraction (Module 3)
    val_res = URLValidator.validate_url(raw_url)
    features_dict, features_vector, detected_words, detected_tld = URLFeatureExtractor.extract(raw_url)
    domain = val_res.get("hostname") or raw_url.lower().split("/")[0]
    
    # 2. Phishing URL Classification (Module 5)
    pred_class, raw_ml_prob, conf, chosen_model = default_classifier.predict_features(
        features_vector, model_name=model_name
    )
    
    # 3. Real-Time Live Network Probing & Dynamic Risk Calibration (Module 6)
    threat_intel, ai_insights, ai_recommendations = analyze_threat_intelligence(
        raw_url, features_dict, raw_ml_prob
    )
    
    risk_analysis = RiskConfidenceAnalyzer.calibrate_risk(
        raw_ml_prob=raw_ml_prob,
        features_dict=features_dict,
        threat_intel=threat_intel,
        domain=domain
    )
    
    phishing_probability = risk_analysis["risk_score"]
    prediction = risk_analysis["prediction"]
    confidence_score = risk_analysis["confidence_score"]
    risk_level = risk_analysis["risk_level"]
        
    # 4. Explainable AI (SHAP & LIME) (Module 7)
    shap_exp = None
    lime_exp = None
    
    if include_xai:
        shap_res = ExplainableAIEngine.explain_shap(chosen_model, features_vector, features_dict, phishing_probability)
        lime_res = ExplainableAIEngine.explain_lime(chosen_model, features_vector, features_dict, phishing_probability)
        shap_exp = XAIExplanation(**shap_res)
        lime_exp = XAIExplanation(**lime_res)
        
    # 5. Security Recommendations (Module 10)
    module10_recs = SecurityRecommendationEngine.generate_recommendations(
        risk_level=risk_level,
        features_dict=features_dict,
        domain=domain,
        threat_intel=threat_intel,
        detected_words=detected_words
    )
    # Merge recommendations if existing empty or supplement
    final_recommendations = module10_recs if module10_recs else ai_recommendations

    features_schema = ExtractedFeaturesSchema(
        url_length=features_dict["url_length"],
        domain_length=features_dict["domain_length"],
        path_length=features_dict["path_length"],
        subdomain_count=features_dict["subdomain_count"],
        count_dots=features_dict["count_dots"],
        count_hyphens=features_dict["count_hyphens"],
        count_underscores=features_dict["count_underscores"],
        count_slashes=features_dict["count_slashes"],
        count_question_marks=features_dict["count_question_marks"],
        count_equals=features_dict["count_equals"],
        count_percent=features_dict["count_percent"],
        count_digits=features_dict["count_digits"],
        https_status=bool(features_dict["https_status"]),
        ip_address=bool(features_dict["ip_address"]),
        has_at_symbol=bool(features_dict["has_at_symbol"]),
        has_double_slash_redirect=bool(features_dict["has_double_slash_redirect"]),
        has_prefix_suffix=bool(features_dict["has_prefix_suffix"]),
        is_shortened_url=bool(features_dict["is_shortened_url"]),
        suspicious_keywords=features_dict["suspicious_keywords"],
        entropy=features_dict["entropy"],
        tld_risk_score=features_dict["tld_risk_score"],
        detected_suspicious_words=detected_words,
        detected_tld=detected_tld
    )
    
    execution_time_ms = round((time.perf_counter() - start_time) * 1000, 1)
    
    return PredictResponse(
        url=raw_url,
        domain=domain,
        prediction=prediction,
        phishing_probability=phishing_probability,
        confidence_score=confidence_score,
        risk_level=risk_level,
        model_name=model_name,
        execution_time_ms=execution_time_ms,
        features=features_schema,
        shap_explanation=shap_exp,
        lime_explanation=lime_exp,
        threat_intel=threat_intel,
        ai_security_insights=ai_insights,
        ai_recommendations=final_recommendations,
        created_at=datetime.datetime.now()
    )

def simulate_whatif(features_dict: dict, model_name: str = "XGBoost") -> dict:
    """
    Performs lightning-fast counterfactual prediction and recalculates SHAP feature
    attributions based on user-modified feature sliders/toggles in real time using XGBoost.
    """
    load_models()
    chosen_model = default_classifier.models.get("XGBoost")
    return ExplainableAIEngine.simulate_whatif(chosen_model, features_dict, model_name="XGBoost")

