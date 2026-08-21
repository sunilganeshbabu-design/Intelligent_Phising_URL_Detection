import sqlite3
from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings

# Configure SQLite engine with thread safety and timeout settings
engine = create_engine(
    settings.DATABASE_URL, 
    connect_args={"check_same_thread": False, "timeout": 30}
)

# Enable foreign keys and WAL mode for SQLite performance and data integrity
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def init_db_and_migrate():
    """
    Creates tables if not existing and automatically migrates any missing columns
    for SQLite backwards-compatibility.
    """
    from sqlalchemy import text
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            # Check url_scans columns
            url_res = conn.execute(text("PRAGMA table_info(url_scans)"))
            url_cols = [row[1] for row in url_res.fetchall()]
            if "scan_type" not in url_cols:
                conn.execute(text("ALTER TABLE url_scans ADD COLUMN scan_type VARCHAR(50) DEFAULT 'url'"))
                conn.commit()

            # Check users columns
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

            # Check email_verification_tokens columns
            ev_res = conn.execute(text("PRAGMA table_info(email_verification_tokens)"))
            ev_cols = [row[1] for row in ev_res.fetchall()]
            if "code" not in ev_cols and len(ev_cols) > 0:
                conn.execute(text("ALTER TABLE email_verification_tokens ADD COLUMN code VARCHAR(10)"))
            if "verification_code" not in ev_cols and len(ev_cols) > 0:
                conn.execute(text("ALTER TABLE email_verification_tokens ADD COLUMN verification_code VARCHAR(10)"))

            # Check password_reset_tokens columns
            pr_res = conn.execute(text("PRAGMA table_info(password_reset_tokens)"))
            pr_cols = [row[1] for row in pr_res.fetchall()]
            if "code" not in pr_cols and len(pr_cols) > 0:
                conn.execute(text("ALTER TABLE password_reset_tokens ADD COLUMN code VARCHAR(10)"))
            if "reset_code" not in pr_cols and len(pr_cols) > 0:
                conn.execute(text("ALTER TABLE password_reset_tokens ADD COLUMN reset_code VARCHAR(10)"))

            conn.commit()
    except Exception as e:
        print(f"[-] Migration note: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

