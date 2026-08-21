from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from ..core.database import get_db
from ..core.security import get_current_user_optional
from ..models.db_models import User, URLScan, URLFeatures
from ..models.schemas import HistoryResponse, PredictResponse, ExtractedFeaturesSchema, XAIExplanation, ThreatIntelResult

router = APIRouter(prefix="/history", tags=["Scan History"])

@router.get("", response_model=HistoryResponse)
def get_scan_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    search: Optional[str] = None,
    filter_type: Optional[str] = None,  # "all", "Phishing", "Legitimate"
    scan_type: Optional[str] = None,    # "all", "url", "email", "qr", "threat_ioc"
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    query = db.query(URLScan)
    
    # Enforce user data isolation (admin sees all, user sees only own)
    if current_user and current_user.role != "admin":
        query = query.filter(URLScan.user_id == current_user.id)
    elif not current_user:
        # For public/demo queries if unauthenticated, show public/seed items
        query = query.filter(URLScan.user_id.is_(None))
        
    if scan_type and scan_type.lower() != "all":
        query = query.filter(URLScan.scan_type == scan_type.lower())
        
    if search:
        search_pattern = f"%{search}%"
        query = query.filter((URLScan.url.like(search_pattern)) | (URLScan.domain.like(search_pattern)))
        
    if filter_type and filter_type.lower() != "all":
        query = query.filter(URLScan.prediction == filter_type)
        
    total = query.count()
    items = (
        query.order_by(URLScan.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    
    return HistoryResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=items
    )

@router.get("/{scan_id}", response_model=PredictResponse)
def get_scan_detail(
    scan_id: int, 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    scan = db.query(URLScan).filter(URLScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    # Enforce data isolation: verify user ownership
    if current_user and current_user.role != "admin" and scan.user_id is not None and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied: You do not have permission to access another user's scan.")
        
    features = db.query(URLFeatures).filter(URLFeatures.scan_id == scan_id).first()
    
    # Reconstruct schemas
    feats_schema = None
    if features and features.raw_features:
        feats_schema = ExtractedFeaturesSchema(**features.raw_features)
    else:
        feats_schema = ExtractedFeaturesSchema(
            url_length=len(scan.url),
            domain_length=len(scan.domain or ""),
            path_length=10,
            subdomain_count=0,
            count_dots=2,
            count_hyphens=0,
            count_underscores=0,
            count_slashes=1,
            count_question_marks=0,
            count_equals=0,
            count_percent=0,
            count_digits=0,
            https_status=scan.url.startswith("https"),
            ip_address=False,
            has_at_symbol=False,
            has_double_slash_redirect=False,
            has_prefix_suffix=False,
            is_shortened_url=False,
            suspicious_keywords=0,
            entropy=3.5,
            tld_risk_score=0.1
        )
        
    shap_exp = XAIExplanation(**scan.shap_summary) if scan.shap_summary else None
    lime_exp = XAIExplanation(**scan.lime_summary) if scan.lime_summary else None
    
    threat_intel = ThreatIntelResult(
        is_blacklisted=(scan.prediction == "Phishing" and scan.phishing_probability > 90),
        threat_category="Identified Phishing Threat" if scan.prediction == "Phishing" else None,
        ssl_valid=scan.url.startswith("https"),
        ssl_issuer="Verified Certificate" if scan.url.startswith("https") else "None",
        reputation_score=round(100.0 - scan.phishing_probability, 1),
        threat_notes=["Historical record loaded from PhishGuard database."]
    )
    
    return PredictResponse(
        id=scan.id,
        url=scan.url,
        domain=scan.domain or scan.url,
        prediction=scan.prediction,
        phishing_probability=scan.phishing_probability,
        confidence_score=scan.confidence_score,
        risk_level=scan.risk_level,
        model_name=scan.model_name,
        features=feats_schema,
        shap_explanation=shap_exp,
        lime_explanation=lime_exp,
        threat_intel=threat_intel,
        ai_security_insights=[f"Historical prediction classified with {scan.confidence_score}% model confidence."],
        ai_recommendations=scan.ai_recommendations or ["Exercise standard cybersecurity vigilance."],
        created_at=scan.created_at
    )

@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    query = db.query(URLScan).filter(URLScan.id == scan_id)
    if current_user and current_user.role != "admin":
        query = query.filter(URLScan.user_id == current_user.id)
        
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found or unauthorized")
        
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}

@router.delete("")
def clear_all_history(
    scan_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    query = db.query(URLScan)
    if current_user and current_user.role != "admin":
        query = query.filter(URLScan.user_id == current_user.id)
    if scan_type and scan_type.lower() != "all":
        query = query.filter(URLScan.scan_type == scan_type.lower())
    query.delete(synchronize_session=False)
    db.commit()
    return {"message": "Scan history cleared successfully"}
