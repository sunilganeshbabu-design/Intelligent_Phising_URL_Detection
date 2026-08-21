"""
INTELLIGENT PHISHING URL DETECTION - 10 CORE MODULES PACKAGE
============================================================
This package encapsulates all 10 modular components of the AI system:

Module 1: Dataset Collection & Preprocessing Module
Module 2: URL Input & Validation Module
Module 3: URL Feature Extraction Module
Module 4: Feature Preprocessing Module
Module 5: Phishing URL Classification Module
Module 6: Risk & Confidence Analysis Module
Module 7: Explainable AI (XAI) Module
Module 8: Feature Importance Analysis Module
Module 9: Detection History & Database Module
Module 10: Security Recommendation Module
"""

from .dataset_preprocessing import DatasetCollector, DatasetPreprocessor, get_or_create_benchmark_dataset
from .url_validation import URLValidator
from .feature_extraction import URLFeatureExtractor, FEATURE_NAMES, FEATURE_METADATA
from .feature_preprocessing import FeaturePreprocessor, default_preprocessor
from .classification import PhishingClassifier, default_classifier
from .risk_analysis import RiskConfidenceAnalyzer
from .xai_engine import ExplainableAIEngine
from .feature_importance import FeatureImportanceAnalyzer
from .detection_history import DetectionHistoryDB
from .security_recommendations import SecurityRecommendationEngine

MODULES_REGISTRY = [
    {
        "id": 1,
        "name": "Dataset Collection & Preprocessing Module",
        "key": "dataset_preprocessing",
        "description": "Generates, ingests, cleans, deduplicates, and splits balanced benchmark phishing and legitimate URL datasets.",
        "icon": "Database",
        "status": "ONLINE"
    },
    {
        "id": 2,
        "name": "URL Input & Validation Module",
        "key": "url_validation",
        "description": "Validates RFC 3986 URL syntax, normalizes protocol schemes, parses hostnames, and detects pre-classification evasion flags.",
        "icon": "CheckCircle",
        "status": "ONLINE"
    },
    {
        "id": 3,
        "name": "URL Feature Extraction Module",
        "key": "feature_extraction",
        "description": "Extracts 21+ numerical, statistical, lexical, and structural features including Shannon entropy and brand typosquatting.",
        "icon": "Cpu",
        "status": "ONLINE"
    },
    {
        "id": 4,
        "name": "Feature Preprocessing Module",
        "key": "feature_preprocessing",
        "description": "Scales, normalizes, and validates feature matrices to match exact machine learning model schemas.",
        "icon": "Sliders",
        "status": "ONLINE"
    },
    {
        "id": 5,
        "name": "Phishing URL Classification Module",
        "key": "classification",
        "description": "Trains and executes single high-performance XGBoost model (Extreme Gradient Boosting) inference with evaluation metrics.",
        "icon": "Network",
        "status": "ONLINE"
    },
    {
        "id": 6,
        "name": "Risk & Confidence Analysis Module",
        "key": "risk_analysis",
        "description": "Synthesizes ML probabilities with live network telemetry into a 0-100 Risk Score across 5 standardized risk tiers.",
        "icon": "ShieldAlert",
        "status": "ONLINE"
    },
    {
        "id": 7,
        "name": "Explainable AI (XAI) Module",
        "key": "xai_engine",
        "description": "Generates game-theoretic SHAP and local surrogate LIME feature attribution waterfall charts and natural language insights.",
        "icon": "Sparkles",
        "status": "ONLINE"
    },
    {
        "id": 8,
        "name": "Feature Importance Analysis Module",
        "key": "feature_importance",
        "description": "Computes global Gini feature importance across models and per-prediction local feature importance rankings.",
        "icon": "BarChart3",
        "status": "ONLINE"
    },
    {
        "id": 9,
        "name": "Detection History & Database Module",
        "key": "detection_history",
        "description": "Manages persistent SQLite storage (WAL mode, foreign keys) for scan telemetry, full feature sets, and execution audit logs.",
        "icon": "HardDrive",
        "status": "ONLINE"
    },
    {
        "id": 10,
        "name": "Security Recommendation Module",
        "key": "security_recommendations",
        "description": "Produces prioritized, actionable remediation playbooks for end-users, SOC analysts, and firewall containment.",
        "icon": "ShieldCheck",
        "status": "ONLINE"
    }
]

__all__ = [
    "DatasetCollector",
    "DatasetPreprocessor",
    "get_or_create_benchmark_dataset",
    "URLValidator",
    "URLFeatureExtractor",
    "FEATURE_NAMES",
    "FEATURE_METADATA",
    "FeaturePreprocessor",
    "default_preprocessor",
    "PhishingClassifier",
    "default_classifier",
    "RiskConfidenceAnalyzer",
    "ExplainableAIEngine",
    "FeatureImportanceAnalyzer",
    "DetectionHistoryDB",
    "SecurityRecommendationEngine",
    "MODULES_REGISTRY"
]
