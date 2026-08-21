import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional

from ..core.database import get_db
from ..core.security import get_current_user_optional
from ..models.db_models import User, URLScan
from ..models.schemas import DashboardStats
from ..ml.model_trainer import get_model_metrics

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("", response_model=DashboardStats)
def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    base_query = db.query(URLScan)
    
    # If user is logged in as regular user, prioritize user's scans
    if current_user and current_user.role != "admin":
        user_scan_count = db.query(URLScan).filter(URLScan.user_id == current_user.id).count()
        if user_scan_count > 0:
            base_query = base_query.filter(URLScan.user_id == current_user.id)
    
    total_scans = base_query.count()
    phishing_count = base_query.filter(URLScan.prediction == "Phishing").count()
    legitimate_count = base_query.filter(URLScan.prediction == "Legitimate").count()
    
    # Defaults for fresh database
    if total_scans == 0:
        phish_pct = 0.0
        safe_pct = 0.0
    else:
        phish_pct = round((phishing_count / total_scans) * 100.0, 1)
        safe_pct = round((legitimate_count / total_scans) * 100.0, 1)
        
    # Risk Distribution
    risk_counts = {
        "Safe": base_query.filter(URLScan.risk_level == "Safe").count(),
        "Low": base_query.filter(URLScan.risk_level == "Low").count(),
        "Medium": base_query.filter(URLScan.risk_level == "Medium").count(),
        "High": base_query.filter(URLScan.risk_level == "High").count(),
        "Critical": base_query.filter(URLScan.risk_level == "Critical").count()
    }
    
    # Weekly Activity (past 7 days)
    today = datetime.date.today()
    weekly_trend = []
    for i in range(6, -1, -1):
        day = today - datetime.timedelta(days=i)
        day_str = day.strftime("%b %d")
        
        day_q = base_query.filter(func.date(URLScan.created_at) == day.isoformat())
        day_total = day_q.count()
        day_phish = day_q.filter(URLScan.prediction == "Phishing").count()
        day_legit = day_total - day_phish
        
        weekly_trend.append({
            "date": day_str,
            "total": day_total,
            "phishing": day_phish,
            "legitimate": day_legit
        })
        
    # Top threat domains
    top_threats_raw = (
        base_query.filter(URLScan.prediction == "Phishing")
        .with_entities(URLScan.domain, func.count(URLScan.id).label("count"))
        .group_by(URLScan.domain)
        .order_by(func.count(URLScan.id).desc())
        .limit(5)
        .all()
    )
    top_threat_domains = [
        {"domain": d, "count": c, "risk": "High"} for d, c in top_threats_raw if d
    ]
    
    # Recent scans
    recent_scans = (
        base_query.order_by(URLScan.created_at.desc())
        .limit(8)
        .all()
    )
    
    # ML model metrics
    metrics = get_model_metrics()
    
    return DashboardStats(
        total_scans=total_scans,
        phishing_detected=phishing_count,
        legitimate_detected=legitimate_count,
        phishing_percentage=phish_pct,
        safe_percentage=safe_pct,
        weekly_scans_trend=weekly_trend,
        risk_distribution=risk_counts,
        top_threat_domains=top_threat_domains,
        recent_scans=recent_scans,
        model_accuracy_metrics=metrics
    )
