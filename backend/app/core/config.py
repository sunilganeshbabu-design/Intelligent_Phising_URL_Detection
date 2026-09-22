import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
REPORTS_DIR = STATIC_DIR / "reports"
MODELS_DIR = BASE_DIR / "ml_models"

DATA_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

class Settings:
    PROJECT_NAME: str = "Intelligent Phishing URL Detection Using Explainable AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-cyber-key-for-phishguard-xai-2026-secure-jwt")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR
    STATIC_DIR: Path = STATIC_DIR
    REPORTS_DIR: Path = REPORTS_DIR
    MODELS_DIR: Path = MODELS_DIR
    
    # Database Configuration (PostgreSQL / SQLite)
    _DEFAULT_SQLITE_URL: str = f"sqlite:///{DATA_DIR / 'phishguard.db'}"
    DATABASE_URL: str = os.getenv("DATABASE_URL", _DEFAULT_SQLITE_URL).strip()
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DATABASE_URL.startswith("postgresql://") and "+psycopg2" not in DATABASE_URL:
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
    
    # ML & XAI paths
    MODEL_PATH: Path = MODELS_DIR / "rf_phishing_model.joblib"
    SCALER_PATH: Path = MODELS_DIR / "feature_scaler.joblib"
    METRICS_PATH: Path = MODELS_DIR / "model_metrics.json"
    BENCHMARK_DATASET_PATH: Path = DATA_DIR / "phishing_benchmark_dataset.csv"
    
    # Default Admin
    ADMIN_EMAIL: str = "admin@phishguard.ai"
    ADMIN_USERNAME: str = "Admin"
    ADMIN_PASSWORD: str = "Admin@123"

    # Google OAuth 2.0
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "1082490219482-phishguard-oauth-google-client.apps.googleusercontent.com")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")

settings = Settings()
