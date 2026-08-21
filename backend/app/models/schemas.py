import datetime
import re
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, field_validator

def validate_email_format(email: Optional[str]) -> Optional[str]:
    if email is not None:
        email = email.strip()
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            raise ValueError("Invalid email address format.")
    return email

# ----------------- User Schemas -----------------
class UserBase(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    auth_provider: Optional[str] = "email"
    email_verified: Optional[bool] = False

    @field_validator("email", mode="before")
    @classmethod
    def check_email(cls, v):
        return validate_email_format(v)

class UserCreate(BaseModel):
    full_name: Optional[str] = None
    username: Optional[str] = None
    email: str
    password: str
    confirm_password: Optional[str] = None

    @field_validator("email", mode="before")
    @classmethod
    def check_email(cls, v):
        return validate_email_format(v)

class UserLogin(BaseModel):
    username_or_email: str
    password: str
    remember_me: Optional[bool] = True

class UserResponse(UserBase):
    id: int
    role: str
    is_active: bool
    created_at: datetime.datetime
    updated_at: Optional[datetime.datetime] = None
    last_login_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    user: UserResponse

class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: Optional[str] = None

class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email", mode="before")
    @classmethod
    def check_email(cls, v):
        return validate_email_format(v)

class ForgotPasswordResponse(BaseModel):
    success: bool
    message: str
    reset_code: Optional[str] = None

class ResetPasswordRequest(BaseModel):
    email: str
    reset_code: str
    new_password: str
    confirm_password: Optional[str] = None

    @field_validator("email", mode="before")
    @classmethod
    def check_email(cls, v):
        return validate_email_format(v)

class VerifyEmailRequest(BaseModel):
    token: Optional[str] = None
    code: Optional[str] = None
    email: Optional[str] = None

class ResendVerificationRequest(BaseModel):
    email: str

    @field_validator("email", mode="before")
    @classmethod
    def check_email(cls, v):
        return validate_email_format(v)

# ----------------- Feature Schemas -----------------
class ExtractedFeaturesSchema(BaseModel):
    url_length: int
    domain_length: int
    path_length: int
    subdomain_count: int
    count_dots: int
    count_hyphens: int
    count_underscores: int
    count_slashes: int
    count_question_marks: int
    count_equals: int
    count_percent: int
    count_digits: int
    https_status: bool
    ip_address: bool
    has_at_symbol: bool
    has_double_slash_redirect: bool
    has_prefix_suffix: bool
    is_shortened_url: bool
    suspicious_keywords: int
    entropy: float
    tld_risk_score: float
    detected_suspicious_words: List[str] = []
    detected_tld: str = ""

# ----------------- XAI Schemas -----------------
class FeatureContribution(BaseModel):
    feature_name: str
    display_name: str
    value: Any
    contribution: float  # Positive = pushes towards phishing, Negative = pushes towards safe
    direction: str       # "Phishing Indicator" or "Legitimacy Indicator"
    description: str

class XAIExplanation(BaseModel):
    method: str  # "SHAP" or "LIME"
    base_value: float
    prediction_score: float
    contributions: List[FeatureContribution]
    summary_text: str

# ----------------- Predict Schemas -----------------
class PredictRequest(BaseModel):
    url: str
    model_name: Optional[str] = "XGBoost"  # "XGBoost"
    include_xai: Optional[bool] = True
    scan_type: Optional[str] = "url"

class ThreatIntelResult(BaseModel):
    is_blacklisted: bool
    threat_category: Optional[str] = None
    ssl_valid: bool
    ssl_issuer: Optional[str] = None
    ssl_protocol: Optional[str] = None
    ssl_valid_to: Optional[str] = None
    ip_hostname: Optional[str] = None
    dns_resolved_ip: Optional[str] = None
    dns_status: Optional[str] = None
    domain_age: Optional[str] = None
    registrar: Optional[str] = None
    reputation_score: float
    live_inspection: bool = True
    realtime_dataset_source: Optional[str] = None
    is_authentic_authority: bool = False
    http_status: Optional[int] = None
    unshortened_url: Optional[str] = None
    threat_notes: List[str] = []

class PredictResponse(BaseModel):
    id: Optional[int] = None
    url: str
    domain: str
    prediction: str  # "Phishing" or "Legitimate"
    phishing_probability: float
    confidence_score: float
    risk_level: str  # "Safe", "Low", "Medium", "High", "Critical"
    model_name: str
    scan_type: Optional[str] = "url"
    execution_time_ms: float = 0.0
    features: ExtractedFeaturesSchema
    shap_explanation: Optional[XAIExplanation] = None
    lime_explanation: Optional[XAIExplanation] = None
    threat_intel: ThreatIntelResult
    ai_security_insights: List[Any] = []
    ai_recommendations: List[Any] = []
    created_at: datetime.datetime

# ----------------- Bulk Predict Schemas -----------------
class BulkPredictRequest(BaseModel):
    urls: List[str]
    model_name: Optional[str] = "XGBoost"

class BulkItemResult(BaseModel):
    url: str
    domain: str
    prediction: str
    phishing_probability: float
    risk_level: str
    key_factors: List[str]

class BulkPredictResponse(BaseModel):
    total_processed: int
    phishing_count: int
    legitimate_count: int
    average_risk: float
    results: List[BulkItemResult]

# ----------------- History Schemas -----------------
class ScanHistoryItem(BaseModel):
    id: int
    url: str
    domain: str
    prediction: str
    phishing_probability: float
    confidence_score: float
    risk_level: str
    model_name: str
    scan_type: Optional[str] = "url"
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class HistoryResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[ScanHistoryItem]

# ----------------- Dashboard Schemas -----------------
class DashboardStats(BaseModel):
    total_scans: int
    phishing_detected: int
    legitimate_detected: int
    phishing_percentage: float
    safe_percentage: float
    weekly_scans_trend: List[Dict[str, Any]]
    risk_distribution: Dict[str, int]
    top_threat_domains: List[Dict[str, Any]]
    recent_scans: List[ScanHistoryItem]
    model_accuracy_metrics: Dict[str, Any]

# ----------------- Chatbot Schemas -----------------
class ChatbotQuery(BaseModel):
    message: str
    scanned_url_context: Optional[str] = None
    prediction_context: Optional[Dict[str, Any]] = None
    history: Optional[List[Dict[str, Any]]] = None

class ChatbotResponse(BaseModel):
    reply: str
    suggested_actions: List[str]
    related_security_topics: List[str]

# ----------------- Report Schemas -----------------
class ReportResponse(BaseModel):
    id: int
    report_name: str
    report_path: str
    format: str
    summary: Optional[str]
    created_at: datetime.datetime

    class Config:
        from_attributes = True
