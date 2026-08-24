import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .core.config import settings
from .core.database import engine, Base, SessionLocal
from .core.security import get_password_hash
from .models.db_models import User, URLScan, URLFeatures
from .ml.predictor import load_models, predict_url
from .ml.realtime_threat_engine import global_threat_engine

# Import API Routers
from .api.auth import router as auth_router
from .api.predict import router as predict_router
from .api.history import router as history_router
from .api.reports import router as reports_router
from .api.dashboard import router as dashboard_router
from .api.chatbot import router as chatbot_router
from .api.admin import router as admin_router
from .api.email_scanner import router as email_router
from .api.threat_lookup import router as threat_router
from .api.modules_api import router as modules_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Intelligent Phishing URL Detection System using Machine Learning and Explainable AI (SHAP & LIME)."
)

# Allowed Origins for CORS
ALLOWED_ORIGINS = [
    "https://intelligent-phising-url-detection.vercel.app",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Mount static reports directory
app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR)), name="static")

# Mount API Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(modules_router, prefix=settings.API_V1_STR)
app.include_router(predict_router, prefix=settings.API_V1_STR)
app.include_router(email_router, prefix=settings.API_V1_STR)
app.include_router(threat_router, prefix=settings.API_V1_STR)
app.include_router(history_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(chatbot_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
def on_startup():
    print("[*] Initializing Database tables...")
    Base.metadata.create_all(bind=engine)
    
    # Auto-migrate SQLite url_scans table if scan_type column is missing
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(url_scans)"))
            columns = [row[1] for row in result.fetchall()]
            if "scan_type" not in columns:
                conn.execute(text("ALTER TABLE url_scans ADD COLUMN scan_type VARCHAR(50) DEFAULT 'url'"))
                conn.commit()
                print("[+] Migrated url_scans: added scan_type column")

            user_res = conn.execute(text("PRAGMA table_info(users)"))
            user_cols = [row[1] for row in user_res.fetchall()]
            if "full_name" not in user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN full_name VARCHAR(255)"))
            if "avatar_url" not in user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500)"))
            if "auth_provider" not in user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN auth_provider VARCHAR(20) DEFAULT 'email'"))
            if "google_subject_id" not in user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN google_subject_id VARCHAR(100)"))
            if "email_verified" not in user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0"))
            if "updated_at" not in user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN updated_at DATETIME"))
            if "last_login_at" not in user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN last_login_at DATETIME"))
            conn.commit()
    except Exception as e:
        print(f"[-] Migration check: {e}")

    db: Session = SessionLocal()
    try:
        # 1. Create Default Admin if not exists
        admin = db.query(User).filter(User.email == settings.ADMIN_EMAIL).first()
        if not admin:
            admin = User(
                username=settings.ADMIN_USERNAME,
                email=settings.ADMIN_EMAIL,
                full_name="Administrator Officer",
                password_hash=get_password_hash(settings.ADMIN_PASSWORD),
                auth_provider="email",
                email_verified=True,
                role="admin",
                is_active=True,
                created_at=datetime.datetime.now(),
                last_login_at=datetime.datetime.now()
            )
            db.add(admin)
            print(f"[+] Created default Admin account: {settings.ADMIN_EMAIL}")
        else:
            if not admin.email_verified:
                admin.email_verified = True
            
        # 2. Create Demo User
        demo_user = db.query(User).filter(User.email == "demo@phishguard.ai").first()
        if not demo_user:
            demo_user = User(
                username="DemoAnalyst",
                email="demo@phishguard.ai",
                full_name="Demo Security Analyst",
                password_hash=get_password_hash("Demo@123"),
                auth_provider="email",
                email_verified=True,
                role="user",
                is_active=True,
                created_at=datetime.datetime.now(),
                last_login_at=datetime.datetime.now()
            )
            db.add(demo_user)
            print("[+] Created default Demo Analyst user: demo@phishguard.ai")
        else:
            if not demo_user.email_verified:
                demo_user.email_verified = True
            
        db.commit()
        
        # 3. Train & Load ML Models & Real-Time Threat Feeds
        print("[*] Preparing ML Models and XAI Engine...")
        load_models()
        print(f"[+] Real-Time Threat Engine active: {len(global_threat_engine.malicious_urls) + len(global_threat_engine.malicious_domains)} threat signatures & live OpenPhish/URLhaus syncer active.")
        
        # 4. Seed initial scans if table is empty to make dashboard look fantastic on initial load
        if db.query(URLScan).count() == 0:
            print("[*] Seeding sample security scans for dashboard...")
            db.query(URLFeatures).delete()
            seed_urls = [
                ("https://www.google.com", "Legitimate"),
                ("http://192.168.1.100/login/bankofamerica-auth.php?token=928103", "Phishing"),
                ("https://github.com/torvalds/linux", "Legitimate"),
                ("http://paypal-security-update.account-verify.xyz/signin.php", "Phishing"),
                ("https://www.microsoft.com/en-us/security", "Legitimate"),
                ("http://appleid-support-validation.login-portal.top/recover", "Phishing"),
                ("https://en.wikipedia.org/wiki/Phishing", "Legitimate"),
                ("http://netflix-billing-resolve-account.buzz/verify", "Phishing"),
                ("https://aws.amazon.com/console", "Legitimate"),
                ("http://google.com@chase-urgent-alert.tk/auth", "Phishing")
            ]
            for url, label in seed_urls:
                try:
                    res = predict_url(url, model_name="XGBoost", include_xai=True)
                    scan = URLScan(
                        user_id=admin.id,
                        url=res.url,
                        domain=res.domain,
                        prediction=res.prediction,
                        phishing_probability=res.phishing_probability,
                        confidence_score=res.confidence_score,
                        risk_level=res.risk_level,
                        model_name=res.model_name,
                        shap_summary=res.shap_explanation.model_dump() if res.shap_explanation else None,
                        lime_summary=res.lime_explanation.model_dump() if res.lime_explanation else None,
                        ai_recommendations=res.ai_recommendations,
                        created_at=datetime.datetime.now() - datetime.timedelta(hours=seed_urls.index((url, label))*3)
                    )
                    db.add(scan)
                    db.flush()
                    feats = res.features
                    features_record = URLFeatures(
                        scan_id=scan.id,
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
                except Exception as e:
                    db.rollback()
                    print(f"[-] Seed error for {url}: {e}")
            print("[+] Initial security scans seeded successfully.")
    finally:
        db.close()

@app.get("/")
def root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs_url": "/docs"
    }
