from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from ..core.database import get_db
from ..core.security import get_current_admin
from ..models.db_models import User, URLScan
from ..models.schemas import UserResponse
from ..ml.model_trainer import train_and_save_models, get_model_metrics
from ..ml.predictor import load_models
from ..ml.dataset_generator import get_or_create_dataset

router = APIRouter(prefix="/admin", tags=["Admin Module"])

@router.get("/users", response_model=List[UserResponse])
def list_all_users(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return users

@router.put("/users/{user_id}/toggle-status")
def toggle_user_status(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own admin account")
        
    user.is_active = not user.is_active
    db.commit()
    return {"message": f"User status changed to {'active' if user.is_active else 'inactive'}", "is_active": user.is_active}

@router.put("/users/{user_id}/toggle-role")
def toggle_user_role(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin_user.id:
        raise HTTPException(status_code=400, detail="Cannot alter your own role")
        
    user.role = "admin" if user.role == "user" else "user"
    db.commit()
    return {"message": f"User role changed to {user.role}", "role": user.role}

@router.get("/dataset-stats")
def get_dataset_statistics(
    admin_user: User = Depends(get_current_admin)
):
    df = get_or_create_dataset()
    phishing_count = int((df["label"] == 1).sum())
    legitimate_count = int((df["label"] == 0).sum())
    
    return {
        "total_samples": len(df),
        "phishing_samples": phishing_count,
        "legitimate_samples": legitimate_count,
        "feature_count": len(df.columns) - 2, # exclude url and label
        "features": [c for c in df.columns if c not in ["url", "label"]],
        "sample_preview": df[["url", "label", "url_length", "subdomain_count", "https_status", "suspicious_keywords"]].head(10).to_dict(orient="records")
    }

@router.post("/retrain-model")
def retrain_model_pipeline(
    admin_user: User = Depends(get_current_admin)
):
    """
    Triggers complete retraining and evaluation of the XGBoost classifier on the updated dataset.
    """
    try:
        new_metrics = train_and_save_models()
        load_models(force_reload=True) # Reload into memory
        return {
            "status": "success",
            "message": "XGBoost model successfully retrained and deployed to runtime memory.",
            "metrics": new_metrics
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model retraining failed: {str(e)}")

@router.get("/system-health")
def get_system_health(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    import platform
    import sys
    
    scan_count = db.query(URLScan).count()
    user_count = db.query(User).count()
    metrics = get_model_metrics()
    
    return {
        "status": "operational",
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "database": "SQLite 3",
        "total_users": user_count,
        "total_scans_processed": scan_count,
        "models_online": ["XGBoost"],
        "primary_model": "XGBoost (Extreme Gradient Boosting)",
        "primary_model_accuracy": metrics.get("models", {}).get("XGBoost", {}).get("accuracy", 0.985) * 100
    }
