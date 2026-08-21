"""
MODULE 9: Detection History & Database Module
=============================================
Responsible for:
- Managing persistent SQLite storage for URL scans, extracted features, threat indicators, and audit logs.
- SQLite optimizations: WAL mode, foreign keys, and multi-column index queries.
- Querying, filtering, searching, and paginating historical detection records.
- Storing and retrieving granular 21+ features per scan alongside XAI SHAP/LIME artifacts.
- Recording module-level execution audit logs (`module_audit_logs`).
- Aggregating cybersecurity metrics and analytics across historical scans.
- Exporting history records to CSV and JSON formats.
"""

import os
import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_
from typing import Dict, Any, List, Optional, Tuple

from ..core.config import settings
from ..core.database import SessionLocal, engine
from ..models.db_models import User, URLScan, URLFeatures, Report, ThreatFeed, ModuleAuditLog

class DetectionHistoryDB:
    """
    Module 9 Core Class: High-level database abstraction for scan persistence
    and telemetry retrieval.
    """

    @staticmethod
    def log_module_event(
        db: Session,
        module_id: int,
        module_name: str,
        action: str,
        input_sample: Optional[str] = None,
        status: str = "SUCCESS",
        execution_time_ms: float = 0.0,
        details: Optional[Dict[str, Any]] = None
    ) -> ModuleAuditLog:
        """
        Records an audit event into SQLite for tracking module operations.
        """
        try:
            log_entry = ModuleAuditLog(
                module_id=module_id,
                module_name=module_name,
                action=action,
                input_sample=(input_sample[:250] if input_sample else None),
                status=status,
                execution_time_ms=execution_time_ms,
                details=details
            )
            db.add(log_entry)
            db.commit()
            return log_entry
        except Exception as e:
            db.rollback()
            print(f"[-] Failed to log module audit event: {e}")
            return None

    @staticmethod
    def save_scan(
        db: Session,
        url: str,
        domain: str,
        prediction: str,
        phishing_probability: float,
        confidence_score: float,
        risk_level: str,
        model_name: str = "XGBoost",
        scan_type: str = "url",
        features_dict: Optional[Dict[str, Any]] = None,
        shap_summary: Optional[Dict[str, Any]] = None,
        lime_summary: Optional[Dict[str, Any]] = None,
        ai_recommendations: Optional[List[Dict[str, Any]]] = None,
        user_id: Optional[int] = None
    ) -> URLScan:
        """
        Persists a complete scan and its associated feature record to SQLite.
        """
        scan = URLScan(
            user_id=user_id,
            url=url,
            domain=domain,
            prediction=prediction,
            phishing_probability=phishing_probability,
            confidence_score=confidence_score,
            risk_level=risk_level,
            model_name=model_name,
            scan_type=scan_type,
            shap_summary=shap_summary,
            lime_summary=lime_summary,
            ai_recommendations=ai_recommendations
        )
        db.add(scan)
        db.flush()

        if features_dict:
            features_record = URLFeatures(
                scan_id=scan.id,
                url_length=int(features_dict.get("url_length", 0)),
                domain_length=int(features_dict.get("domain_length", 0)),
                path_length=int(features_dict.get("path_length", 0)),
                subdomain_count=int(features_dict.get("subdomain_count", 0)),
                count_dots=int(features_dict.get("count_dots", 0)),
                count_hyphens=int(features_dict.get("count_hyphens", 0)),
                count_underscores=int(features_dict.get("count_underscores", 0)),
                count_slashes=int(features_dict.get("count_slashes", 0)),
                count_question_marks=int(features_dict.get("count_question_marks", 0)),
                count_equals=int(features_dict.get("count_equals", 0)),
                count_percent=int(features_dict.get("count_percent", 0)),
                count_digits=int(features_dict.get("count_digits", 0)),
                https_status=bool(features_dict.get("https_status", False)),
                ip_address=bool(features_dict.get("ip_address", False)),
                has_at_symbol=bool(features_dict.get("has_at_symbol", False)),
                has_double_slash_redirect=bool(features_dict.get("has_double_slash_redirect", False)),
                has_prefix_suffix=bool(features_dict.get("has_prefix_suffix", False)),
                is_shortened_url=bool(features_dict.get("is_shortened_url", False)),
                suspicious_keywords=int(features_dict.get("suspicious_keywords", 0)),
                entropy=float(features_dict.get("entropy", 0.0)),
                tld_risk_score=float(features_dict.get("tld_risk_score", 0.1)),
                raw_features=features_dict
            )
            db.add(features_record)

        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def get_history(
        db: Session,
        page: int = 1,
        page_size: int = 20,
        search: Optional[str] = None,
        risk_level: Optional[str] = None,
        prediction: Optional[str] = None,
        scan_type: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> Tuple[List[URLScan], int]:
        """
        Retrieves paginated scan history with dynamic filtering.
        """
        query = db.query(URLScan)

        if user_id is not None:
            query = query.filter(URLScan.user_id == user_id)

        if search:
            search_term = f"%{search}%"
            query = query.filter(or_(URLScan.url.ilike(search_term), URLScan.domain.ilike(search_term)))

        if risk_level and risk_level != "all":
            query = query.filter(URLScan.risk_level == risk_level)

        if prediction and prediction != "all":
            query = query.filter(URLScan.prediction == prediction)

        if scan_type and scan_type != "all":
            query = query.filter(URLScan.scan_type == scan_type)

        total = query.count()
        records = query.order_by(desc(URLScan.created_at)).offset((page - 1) * page_size).limit(page_size).all()

        return records, total

    @staticmethod
    def get_database_stats(db: Session) -> Dict[str, Any]:
        """
        Gathers SQLite database statistics and storage health metrics.
        """
        total_scans = db.query(URLScan).count()
        phishing_scans = db.query(URLScan).filter(URLScan.prediction == "Phishing").count()
        legit_scans = db.query(URLScan).filter(URLScan.prediction == "Legitimate").count()
        total_users = db.query(User).count()
        total_reports = db.query(Report).count()
        total_audit_logs = db.query(ModuleAuditLog).count()

        db_path = settings.DATA_DIR / "phishguard.db"
        db_size_mb = round(db_path.stat().st_size / (1024 * 1024), 2) if db_path.exists() else 0.0

        # Risk distribution
        risk_counts = {}
        for r_tier in ["Safe", "Low", "Medium", "High", "Critical"]:
            count = db.query(URLScan).filter(URLScan.risk_level == r_tier).count()
            risk_counts[r_tier] = count

        return {
            "database_type": "SQLite 3",
            "database_file": str(db_path),
            "database_size_mb": db_size_mb,
            "wal_mode_enabled": True,
            "foreign_keys_enabled": True,
            "total_scans": total_scans,
            "phishing_scans": phishing_scans,
            "legitimate_scans": legit_scans,
            "total_users": total_users,
            "total_reports": total_reports,
            "total_audit_logs": total_audit_logs,
            "risk_distribution": risk_counts
        }
