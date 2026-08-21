import requests
import json

def inspect_url(u):
    print("\n" + "=" * 75)
    print(f"TESTING CURRENT URL: {u}")
    print("=" * 75)
    r = requests.post("http://127.0.0.1:8000/api/modules/pipeline-run", json={"url": u, "model_name": "XGBooster"})
    data = r.json()
    print("PIPELINE STATUS:", data.get("pipeline_status"))
    print("FINAL VERDICT:", data.get("final_prediction"), "| RISK SCORE:", data.get("final_risk_score"), "% | TIER:", data.get("final_risk_level"), "| SCAN ID:", data.get("persisted_scan_id"))
    
    flow = {step["module_id"]: step for step in data.get("module_execution_flow", [])}
    
    print("\n[Module 1 - Dataset Preprocessing]")
    print("  Target URL:", flow[1]["output"]["target_url"])
    print("  Corpus Samples:", flow[1]["output"]["corpus_telemetry"]["total_samples"])
    legit_sim = flow[1]["output"]["nearest_neighbors"]["closest_legitimate"]["similarity_score"]
    phish_sim = flow[1]["output"]["nearest_neighbors"]["closest_phishing"]["similarity_score"]
    print("  Closest Legit:", flow[1]["output"]["nearest_neighbors"]["closest_legitimate"]["url"], f"({legit_sim}%)")
    print("  Closest Phish:", flow[1]["output"]["nearest_neighbors"]["closest_phishing"]["url"], f"({phish_sim}%)")
    
    print("\n[Module 2 - URL Validation]")
    print("  Valid RFC-3986:", flow[2]["output"]["is_valid"], "| Scheme:", flow[2]["output"]["scheme"], "| Host:", flow[2]["output"]["hostname"])
    print("  Security Flags:", flow[2]["output"]["security_flags"])
    
    print("\n[Module 3 - Feature Extraction]")
    print("  Total Extracted:", flow[3]["output"]["total_extracted"])
    print("  Entropy:", flow[3]["output"]["features_dict"]["entropy"], "| HTTPS:", flow[3]["output"]["features_dict"]["https_status"], "| Keywords:", flow[3]["output"]["detected_words"])
    print("  Dots:", flow[3]["output"]["features_dict"]["count_dots"], "| Subdomains:", flow[3]["output"]["features_dict"]["subdomain_count"], "| TLD Risk:", flow[3]["output"]["features_dict"]["tld_risk_score"])
    
    print("\n[Module 4 - Feature Preprocessing]")
    print("  Tensor Dim:", flow[4]["output"]["vector_dimension"], "| Raw sample (first 4):", flow[4]["output"]["raw_vector"][:4])
    
    print("\n[Module 5 - ML Classification]")
    print("  Primary Prediction:", flow[5]["output"]["primary_prediction"], "| Raw Prob:", flow[5]["output"]["raw_phishing_probability"], "% | Conf:", flow[5]["output"]["confidence_score"], "%")
    models_summary = {k: v["prediction"] + f" ({v['phishing_probability']}%)" for k, v in flow[5]["output"]["multi_model_comparison"].items()}
    print("  Multi-Model Comparison:", models_summary)
    
    print("\n[Module 6 - Risk & Confidence]")
    print("  Calibrated Risk Score:", flow[6]["output"]["risk_score"], "% | Tier:", flow[6]["output"]["risk_level"], "| Conf:", flow[6]["output"]["confidence_score"], "%")
    
    print("\n[Module 7 - SHAP & LIME XAI]")
    print("  SHAP Base Value:", flow[7]["output"]["shap_base_value"])
    top_shap = [(c["feature_name"], c["contribution"]) for c in flow[7]["output"]["top_shap_contributions"][:3]]
    print("  Top SHAP Contributions:", top_shap)
    
    print("\n[Module 8 - Feature Importance]")
    top_local = [(f["display_name"], f"{f['local_weight_pct']}%") for f in flow[8]["output"]["local_importance"]["ranked_local_features"][:3]]
    print("  Top Local Drivers:", top_local)
    top_global = [(f["display_name"], f"{f['importance_score']}%") for f in flow[8]["output"]["global_top_5"][:3]]
    print("  Global Top Predictors:", top_global)
    
    print("\n[Module 9 - SQLite Persistence]")
    print("  DB Engine:", flow[9]["output"]["database"], "| Persisted Scan ID:", flow[9]["output"]["persisted_scan_id"], "| DB Size:", flow[9]["output"]["database_size_mb"], "MB | Total Scans:", flow[9]["output"]["total_scans"])
    
    print("\n[Module 10 - Security Recommendations]")
    print("  Total Recommendations:", flow[10]["output"]["total_recommendations"])
    print("  Remediation Actions:", flow[10]["output"]["recommendations"])

if __name__ == "__main__":
    inspect_url("https://www.google.com")
    inspect_url("http://google-login-security.example/verify")
