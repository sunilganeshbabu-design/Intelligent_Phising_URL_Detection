from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from pydantic import BaseModel

from ..core.database import get_db
from ..core.security import get_current_user_optional
from ..models.db_models import User, URLScan, URLFeatures
from ..models.schemas import (
    PredictRequest, PredictResponse, BulkPredictRequest, 
    BulkPredictResponse, BulkItemResult
)
from ..ml.predictor import predict_url, simulate_whatif

router = APIRouter(prefix="/predict", tags=["Prediction & XAI"])

class WhatIfRequest(BaseModel):
    features: Dict[str, Any]
    model_name: Optional[str] = "XGBoost"

@router.post("/simulate-whatif")
def run_whatif_simulation(request: WhatIfRequest):
    try:
        return simulate_whatif(request.features, model_name=request.model_name or "XGBoost")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation error: {str(e)}")

@router.post("", response_model=PredictResponse)
def run_prediction(
    request: PredictRequest, 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
        
    try:
        # 1. Run ML Prediction & XAI
        result = predict_url(
            raw_url=url,
            model_name=request.model_name or "XGBoost",
            include_xai=request.include_xai
        )
        
        # 2. Persist to Database if desired
        scan_type = request.scan_type or "url"
        scan_record = URLScan(
            user_id=current_user.id if current_user else None,
            url=result.url,
            domain=result.domain,
            prediction=result.prediction,
            phishing_probability=result.phishing_probability,
            confidence_score=result.confidence_score,
            risk_level=result.risk_level,
            model_name=result.model_name,
            scan_type=scan_type,
            shap_summary=result.shap_explanation.model_dump() if result.shap_explanation else None,
            lime_summary=result.lime_explanation.model_dump() if result.lime_explanation else None,
            ai_recommendations=result.ai_recommendations
        )
        db.add(scan_record)
        db.flush() # get scan_record.id
        
        feats = result.features
        features_record = URLFeatures(
            scan_id=scan_record.id,
            url_length=feats.url_length,
            domain_length=feats.domain_length,
            path_length=feats.path_length,
            subdomain_count=feats.subdomain_count,
            count_dots=feats.count_dots,
            count_hyphens=feats.count_hyphens,
            count_underscores=feats.count_underscores,
            count_slashes=feats.count_slashes,
            count_question_marks=feats.count_question_marks,
            count_equals=feats.count_equals,
            count_percent=feats.count_percent,
            count_digits=feats.count_digits,
            https_status=feats.https_status,
            ip_address=feats.ip_address,
            has_at_symbol=feats.has_at_symbol,
            has_double_slash_redirect=feats.has_double_slash_redirect,
            has_prefix_suffix=feats.has_prefix_suffix,
            is_shortened_url=feats.is_shortened_url,
            suspicious_keywords=feats.suspicious_keywords,
            entropy=feats.entropy,
            tld_risk_score=feats.tld_risk_score,
            raw_features=feats.model_dump()
        )
        db.add(features_record)
        db.commit()
        db.refresh(scan_record)
        
        result.id = scan_record.id
        result.scan_type = scan_type
        return result
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Prediction error occurred: {str(e)}"
        )

@router.post("/bulk", response_model=BulkPredictResponse)
def run_bulk_prediction(
    request: BulkPredictRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    urls = [u.strip() for u in request.urls if u.strip()]
    if not urls:
        raise HTTPException(status_code=400, detail="No valid URLs provided")
    if len(urls) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 URLs per bulk scan batch")
        
    items = []
    phish_count = 0
    legit_count = 0
    total_prob = 0.0
    
    for url in urls:
        try:
            res = predict_url(raw_url=url, model_name=request.model_name or "XGBoost", include_xai=False)
            
            if res.prediction == "Phishing":
                phish_count += 1
            else:
                legit_count += 1
            total_prob += res.phishing_probability
            
            # Save lightweight scan record
            scan = URLScan(
                user_id=current_user.id if current_user else None,
                url=res.url,
                domain=res.domain,
                prediction=res.prediction,
                phishing_probability=res.phishing_probability,
                confidence_score=res.confidence_score,
                risk_level=res.risk_level,
                model_name=res.model_name
            )
            db.add(scan)
            
            # Top key risk factors
            key_factors = []
            if res.features.ip_address:
                key_factors.append("IP Address Host")
            if res.features.suspicious_keywords > 0:
                key_factors.append(f"{res.features.suspicious_keywords} Suspicious Keywords")
            if not res.features.https_status:
                key_factors.append("No HTTPS")
            if res.features.tld_risk_score > 0.5:
                key_factors.append(f"High-risk TLD ({res.features.detected_tld})")
            if not key_factors:
                key_factors.append("Standard Lexical Pattern")
                
            items.append(BulkItemResult(
                url=res.url,
                domain=res.domain,
                prediction=res.prediction,
                phishing_probability=res.phishing_probability,
                risk_level=res.risk_level,
                key_factors=key_factors
            ))
        except Exception as e:
            items.append(BulkItemResult(
                url=url,
                domain="Error",
                prediction="Unknown",
                phishing_probability=50.0,
                risk_level="Medium",
                key_factors=[f"Scan error: {str(e)}"]
            ))
            
    db.commit()
    
    avg_risk = round(total_prob / len(urls), 2) if urls else 0.0
    return BulkPredictResponse(
        total_processed=len(urls),
        phishing_count=phish_count,
        legitimate_count=legit_count,
        average_risk=avg_risk,
        results=items
    )
