import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from ..core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    password_hash = Column(String(255), nullable=True)
    auth_provider = Column(String(20), default="email")  # "email", "google"
    google_subject_id = Column(String(100), unique=True, index=True, nullable=True)
    email_verified = Column(Boolean, default=False)
    role = Column(String(20), default="user")  # "user" or "admin"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now)
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    last_login_at = Column(DateTime, nullable=True)

    scans = relationship("URLScan", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    verification_tokens = relationship("EmailVerificationToken", back_populates="user", cascade="all, delete-orphan")
    reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")

class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    code = Column(String(10), nullable=True, index=True)
    verification_code = Column(String(10), nullable=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.now)

    user = relationship("User", back_populates="verification_tokens")

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    code = Column(String(10), nullable=True, index=True)
    reset_code = Column(String(10), nullable=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.now)

    user = relationship("User", back_populates="reset_tokens")

class URLScan(Base):
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    url = Column(Text, nullable=False, index=True)
    domain = Column(String(255), index=True)
    prediction = Column(String(50), nullable=False)  # "Phishing" or "Legitimate"
    phishing_probability = Column(Float, nullable=False)  # 0.0 to 100.0%
    confidence_score = Column(Float, nullable=False)     # 0.0 to 100.0%
    risk_level = Column(String(20), nullable=False)       # "Safe", "Low", "Medium", "High", "Critical"
    model_name = Column(String(50), default="XGBoost")
    scan_type = Column(String(50), default="url", index=True) # "url", "email", "qr", "threat_ioc"
    shap_summary = Column(JSON, nullable=True)
    lime_summary = Column(JSON, nullable=True)
    ai_recommendations = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now, index=True)

    user = relationship("User", back_populates="scans")
    features = relationship("URLFeatures", back_populates="scan", uselist=False, cascade="all, delete-orphan")

class URLFeatures(Base):
    __tablename__ = "url_features"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    url_length = Column(Integer)
    domain_length = Column(Integer)
    path_length = Column(Integer)
    subdomain_count = Column(Integer)
    count_dots = Column(Integer)
    count_hyphens = Column(Integer)
    count_underscores = Column(Integer)
    count_slashes = Column(Integer)
    count_question_marks = Column(Integer)
    count_equals = Column(Integer)
    count_percent = Column(Integer)
    count_digits = Column(Integer)
    https_status = Column(Boolean)
    ip_address = Column(Boolean)
    has_at_symbol = Column(Boolean)
    has_double_slash_redirect = Column(Boolean)
    has_prefix_suffix = Column(Boolean)
    is_shortened_url = Column(Boolean)
    suspicious_keywords = Column(Integer)
    entropy = Column(Float)
    tld_risk_score = Column(Float)
    raw_features = Column(JSON)

    scan = relationship("URLScan", back_populates="features")

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="SET NULL"), nullable=True)
    report_name = Column(String(255), nullable=False)
    report_path = Column(String(500), nullable=False)
    format = Column(String(20), default="PDF")  # "PDF", "CSV"
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now)

    user = relationship("User", back_populates="reports")

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    indicator_type = Column(String(50), default="phishing_domain")  # "phishing_domain", "malicious_ip", "typosquat"
    risk_score = Column(Float, default=95.0)
    source = Column(String(100), default="PhishGuard Threat Intelligence")
    updated_at = Column(DateTime, default=datetime.datetime.now)

class ModuleAuditLog(Base):
    __tablename__ = "module_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    module_id = Column(Integer, index=True, nullable=False)  # 1 to 10
    module_name = Column(String(100), index=True, nullable=False)
    action = Column(String(100), nullable=False)  # e.g., "validate", "extract", "classify", "explain"
    input_sample = Column(Text, nullable=True)
    status = Column(String(20), default="SUCCESS")  # "SUCCESS", "WARNING", "ERROR"
    execution_time_ms = Column(Float, default=0.0)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now, index=True)



