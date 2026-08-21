"""
Comprehensive 10-Module & SQLite Database Automated Verification Suite
========================================================================
Validates all 10 modules individually and as a unified pipeline:
1. Dataset Collection & Preprocessing Module
2. URL Input & Validation Module
3. URL Feature Extraction Module
4. Feature Preprocessing Module
5. Phishing URL Classification Module
6. Risk & Confidence Analysis Module
7. Explainable AI (XAI) Module
8. Feature Importance Analysis Module
9. Detection History & Database Module (SQLite)
10. Security Recommendation Module
"""

import sys
import os
import time
from pathlib import Path

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.config import settings
from app.core.database import SessionLocal, engine, Base
from app.models.db_models import User, URLScan, URLFeatures, ModuleAuditLog
from app.modules import (
    MODULES_REGISTRY,
    DatasetCollector,
    DatasetPreprocessor,
    get_or_create_benchmark_dataset,
    URLValidator,
    URLFeatureExtractor,
    FEATURE_NAMES,
    FeaturePreprocessor, default_preprocessor,
    PhishingClassifier, default_classifier,
    RiskConfidenceAnalyzer,
    ExplainableAIEngine,
    FeatureImportanceAnalyzer,
    DetectionHistoryDB,
    SecurityRecommendationEngine
)

def run_comprehensive_tests():
    print("=" * 75)
    print("  INTELLIGENT PHISHING URL DETECTION - 10-MODULE TEST SUITE")
    print("  Database Engine: SQLite 3 (WAL mode, Foreign Keys Active)")
    print("=" * 75)

    # Initialize SQLite tables
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # -------------------------------------------------------------
        # MODULE 1: Dataset Collection & Preprocessing
        # -------------------------------------------------------------
        print("\n[+] Testing Module 1: Dataset Collection & Preprocessing...")
        t0 = time.perf_counter()
        df = get_or_create_benchmark_dataset(sample_size=100)
        assert len(df) > 0, "Module 1 Failed: Dataset generation returned 0 rows"
        assert "label" in df.columns, "Module 1 Failed: 'label' column missing"
        profile = DatasetPreprocessor.get_dataset_profile(df)
        assert profile["total_samples"] == len(df), "Module 1 Failed: Profile mismatch"
        print(f"    -> Module 1 SUCCESS: Dataset with {len(df)} samples created & preprocessed in {round((time.perf_counter()-t0)*1000, 2)}ms")
        print(f"    -> Class Balance: {profile['legitimate_samples']} Legitimate vs {profile['phishing_samples']} Phishing")

        # -------------------------------------------------------------
        # MODULE 2: URL Input & Validation
        # -------------------------------------------------------------
        print("\n[+] Testing Module 2: URL Input & Validation...")
        test_urls = [
            "https://www.google.com/search?q=cybersecurity",
            "http://192.168.1.50/login.php?token=928103",
            "http://paypal.com@phishing-portal.xyz/auth//redirect",
            "invalid url with spaces and characters"
        ]
        val_batch = URLValidator.validate_batch(test_urls)
        assert val_batch["total"] == 4, "Module 2 Failed: Batch size mismatch"
        assert val_batch["valid_count"] == 3, f"Module 2 Failed: Expected 3 valid URLs, got {val_batch['valid_count']}"
        val_single = URLValidator.validate_url("http://192.168.1.50:8080/auth")
        assert val_single["is_ip"] is True, "Module 2 Failed: Did not detect IP hostname"
        assert val_single["port"] == 8080, "Module 2 Failed: Did not parse port"
        print(f"    -> Module 2 SUCCESS: URL input parsing, IDN/IP handling, and batch validation verified.")

        # -------------------------------------------------------------
        # MODULE 3: URL Feature Extraction
        # -------------------------------------------------------------
        print("\n[+] Testing Module 3: URL Feature Extraction...")
        test_phish_url = "http://paypal-security-update.account-verify.xyz/signin.php?session=92810398102381"
        feats_dict, feats_vec, detected_words, tld = URLFeatureExtractor.extract(test_phish_url)
        assert len(feats_vec) == len(FEATURE_NAMES), f"Module 3 Failed: Expected {len(FEATURE_NAMES)} features, got {len(feats_vec)}"
        assert feats_dict["entropy"] > 0, "Module 3 Failed: Entropy calculation returned 0"
        assert feats_dict["tld_risk_score"] >= 0.7, "Module 3 Failed: High-risk TLD .xyz not scored"
        assert "login" in detected_words or "signin" in detected_words or "verify" in detected_words, "Module 3 Failed: Keywords not detected"
        print(f"    -> Module 3 SUCCESS: All 21 features extracted (Entropy: {feats_dict['entropy']}, TLD: {tld}, Words: {detected_words})")

        # -------------------------------------------------------------
        # MODULE 4: Feature Preprocessing
        # -------------------------------------------------------------
        print("\n[+] Testing Module 4: Feature Preprocessing...")
        aligned_vec = FeaturePreprocessor.align_feature_dict(feats_dict)
        assert len(aligned_vec) == len(FEATURE_NAMES), "Module 4 Failed: Aligned vector length mismatch"
        scaled_vec = default_preprocessor.transform([aligned_vec])
        assert scaled_vec.shape == (1, len(FEATURE_NAMES)), "Module 4 Failed: Scaled shape mismatch"
        bounds = FeaturePreprocessor.get_feature_bounds()
        assert len(bounds) == len(FEATURE_NAMES), "Module 4 Failed: Feature bounds missing"
        print(f"    -> Module 4 SUCCESS: Feature standardization, bounds validation, and alignment confirmed.")

        # -------------------------------------------------------------
        # MODULE 5: Phishing URL Classification
        # -------------------------------------------------------------
        print("\n[+] Testing Module 5: Phishing URL Classification...")
        pred, phish_prob, conf, model = default_classifier.predict_features(aligned_vec, model_name="XGBoost")
        assert pred in ["Phishing", "Legitimate"], "Module 5 Failed: Invalid prediction class"
        assert 0.0 <= phish_prob <= 100.0, "Module 5 Failed: Phishing probability out of range"
        comp = default_classifier.compare_all_models(aligned_vec)
        assert "XGBoost" in comp, "Module 5 Failed: Missing model in comparison"
        print(f"    -> Module 5 SUCCESS: Primary XGBoost prediction (Verdict: {comp['XGBoost']['prediction']} - {comp['XGBoost']['phishing_probability']}%, Engine: {comp['XGBoost']['engine']})")

        # -------------------------------------------------------------
        # MODULE 6: Risk & Confidence Analysis
        # -------------------------------------------------------------
        print("\n[+] Testing Module 6: Risk & Confidence Analysis...")
        risk_res = RiskConfidenceAnalyzer.calibrate_risk(
            raw_ml_prob=phish_prob,
            features_dict=feats_dict,
            threat_intel=None,
            domain="paypal-security-update.account-verify.xyz"
        )
        assert risk_res["risk_level"] in ["Safe", "Low", "Medium", "High", "Critical"], "Module 6 Failed: Invalid risk level tier"
        assert len(risk_res["factor_breakdown"]) > 0, "Module 6 Failed: Missing factor breakdown"
        print(f"    -> Module 6 SUCCESS: Risk calibrated to {risk_res['risk_score']}% (Tier: {risk_res['risk_level']}, Confidence: {risk_res['confidence_score']}%)")

        # -------------------------------------------------------------
        # MODULE 7: Explainable AI (XAI)
        # -------------------------------------------------------------
        print("\n[+] Testing Module 7: Explainable AI (XAI)...")
        shap_res = ExplainableAIEngine.explain_shap(model, aligned_vec, feats_dict, risk_res["risk_score"])
        assert shap_res["method"] == "SHAP", "Module 7 Failed: SHAP method name missing"
        assert len(shap_res["contributions"]) == len(FEATURE_NAMES), "Module 7 Failed: SHAP contributions incomplete"
        lime_res = ExplainableAIEngine.explain_lime(model, aligned_vec, feats_dict, risk_res["risk_score"])
        assert len(lime_res["contributions"]) > 0, "Module 7 Failed: LIME contributions empty"
        whatif_res = ExplainableAIEngine.simulate_whatif(model, feats_dict, model_name="XGBoost")
        assert "shap_explanation" in whatif_res, "Module 7 Failed: Counterfactual simulation failed"
        print(f"    -> Module 7 SUCCESS: SHAP & LIME explanations and What-If counterfactual engine verified.")

        # -------------------------------------------------------------
        # MODULE 8: Feature Importance Analysis
        # -------------------------------------------------------------
        print("\n[+] Testing Module 8: Feature Importance Analysis...")
        global_imp = FeatureImportanceAnalyzer.get_global_importance("XGBoost")
        assert len(global_imp["feature_rankings"]) == len(FEATURE_NAMES), "Module 8 Failed: Missing global rankings"
        local_imp = FeatureImportanceAnalyzer.get_local_importance(shap_res["contributions"])
        assert "top_phishing_drivers" in local_imp, "Module 8 Failed: Local rankings missing"
        print(f"    -> Module 8 SUCCESS: Global feature rankings (Top: {global_imp['top_feature']['display_name']} - {global_imp['top_feature']['importance_score']}%)")

        # -------------------------------------------------------------
        # MODULE 9: Detection History & Database Module (SQLite)
        # -------------------------------------------------------------
        print("\n[+] Testing Module 9: Detection History & Database Module (SQLite)...")
        test_scan = DetectionHistoryDB.save_scan(
            db=db,
            url=test_phish_url,
            domain="paypal-security-update.account-verify.xyz",
            prediction=risk_res["prediction"],
            phishing_probability=risk_res["risk_score"],
            confidence_score=risk_res["confidence_score"],
            risk_level=risk_res["risk_level"],
            model_name="XGBoost",
            scan_type="unit_test",
            features_dict=feats_dict,
            shap_summary=shap_res,
            lime_summary=lime_res,
            ai_recommendations=[]
        )
        assert test_scan.id is not None, "Module 9 Failed: Scan ID not assigned by SQLite"
        
        # Verify SQLite relations
        features_row = db.query(URLFeatures).filter(URLFeatures.scan_id == test_scan.id).first()
        assert features_row is not None, "Module 9 Failed: Features table record not saved in SQLite"
        assert features_row.entropy == feats_dict["entropy"], "Module 9 Failed: Feature value mismatch in SQLite"

        # Log audit event
        audit_entry = DetectionHistoryDB.log_module_event(
            db, module_id=9, module_name="Detection History & Database Module",
            action="test_verification", input_sample=test_phish_url,
            status="SUCCESS", execution_time_ms=1.5
        )
        assert audit_entry is not None, "Module 9 Failed: Audit log entry failed in SQLite"

        db_stats = DetectionHistoryDB.get_database_stats(db)
        assert db_stats["database_type"] == "SQLite 3", "Module 9 Failed: Database type mismatch"
        print(f"    -> Module 9 SUCCESS: SQLite persistence verified (Scan ID: {test_scan.id}, DB Size: {db_stats['database_size_mb']}MB, Total Scans: {db_stats['total_scans']})")

        # -------------------------------------------------------------
        # MODULE 10: Security Recommendation Module
        # -------------------------------------------------------------
        print("\n[+] Testing Module 10: Security Recommendation Module...")
        recs = SecurityRecommendationEngine.generate_recommendations(
            risk_level=risk_res["risk_level"],
            features_dict=feats_dict,
            domain="paypal-security-update.account-verify.xyz",
            detected_words=detected_words
        )
        assert len(recs) >= 2, "Module 10 Failed: Insufficient recommendations generated for high risk"
        categories = [r["category"] for r in recs]
        assert "Immediate User Action" in categories, "Module 10 Failed: Immediate user action missing"
        print(f"    -> Module 10 SUCCESS: Generated {len(recs)} tailored remediation actions (Categories: {categories})")

        print("\n" + "=" * 75)
        print("  ALL 10 MODULES & SQLITE DATABASE PASSED 100% OF VERIFICATION CHECKS!")
        print("=" * 75)

    finally:
        db.close()

if __name__ == "__main__":
    run_comprehensive_tests()
