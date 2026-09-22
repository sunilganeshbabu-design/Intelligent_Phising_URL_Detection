import os
import sqlite3
import logging
from sqlalchemy import create_engine, event, text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings

logger = logging.getLogger("phishguard.database")

def create_configured_engine(url: str):
    """
    Creates an optimized SQLAlchemy engine based on the database dialect (PostgreSQL or SQLite).
    """
    url_lower = url.lower()
    if "sqlite" in url_lower:
        eng = create_engine(
            url,
            connect_args={"check_same_thread": False, "timeout": 30}
        )
        @event.listens_for(eng, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            if isinstance(dbapi_connection, sqlite3.Connection):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON;")
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
                cursor.close()
        return eng, True
    else:
        # PostgreSQL / other SQL engines
        eng = create_engine(
            url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20
        )
        return eng, False

# Try initializing with configured DATABASE_URL
primary_url = settings.DATABASE_URL
engine, is_sqlite_mode = create_configured_engine(primary_url)

# If PostgreSQL was configured, test connection; if unreachable, fallback gracefully to SQLite
if not is_sqlite_mode:
    try:
        with engine.connect() as test_conn:
            test_conn.execute(text("SELECT 1"))
        logger.info(f"[+] Successfully connected to PostgreSQL database at {primary_url.split('@')[-1] if '@' in primary_url else primary_url}")
    except Exception as pg_err:
        logger.warning(
            f"[!] Could not connect to PostgreSQL ({pg_err}). "
            f"Falling back to local SQLite database to prevent downtime."
        )
        engine, is_sqlite_mode = create_configured_engine(settings._DEFAULT_SQLITE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db_and_migrate():
    """
    Creates tables if not existing and automatically migrates any missing columns
    in a database-agnostic way for both PostgreSQL and SQLite.
    """
    Base.metadata.create_all(bind=engine)
    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()

        with engine.connect() as conn:
            # 1. Check url_scans columns
            if "url_scans" in existing_tables:
                url_cols = [col["name"] for col in inspector.get_columns("url_scans")]
                if "scan_type" not in url_cols:
                    conn.execute(text("ALTER TABLE url_scans ADD COLUMN scan_type VARCHAR(50) DEFAULT 'url'"))
                    conn.commit()

            # 2. Check users columns
            if "users" in existing_tables:
                user_cols = [col["name"] for col in inspector.get_columns("users")]
                if "full_name" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN full_name VARCHAR(255)"))
                if "avatar_url" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500)"))
                if "auth_provider" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN auth_provider VARCHAR(20) DEFAULT 'email'"))
                if "google_subject_id" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN google_subject_id VARCHAR(100)"))
                if "email_verified" not in user_cols:
                    default_val = "0" if is_sqlite_mode else "FALSE"
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT {default_val}"))
                if "updated_at" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP"))
                if "last_login_at" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP"))
                conn.commit()

            # 3. Check email_verification_tokens columns
            if "email_verification_tokens" in existing_tables:
                ev_cols = [col["name"] for col in inspector.get_columns("email_verification_tokens")]
                if "code" not in ev_cols and len(ev_cols) > 0:
                    conn.execute(text("ALTER TABLE email_verification_tokens ADD COLUMN code VARCHAR(10)"))
                if "verification_code" not in ev_cols and len(ev_cols) > 0:
                    conn.execute(text("ALTER TABLE email_verification_tokens ADD COLUMN verification_code VARCHAR(10)"))
                conn.commit()

            # 4. Check password_reset_tokens columns
            if "password_reset_tokens" in existing_tables:
                pr_cols = [col["name"] for col in inspector.get_columns("password_reset_tokens")]
                if "code" not in pr_cols and len(pr_cols) > 0:
                    conn.execute(text("ALTER TABLE password_reset_tokens ADD COLUMN code VARCHAR(10)"))
                if "reset_code" not in pr_cols and len(pr_cols) > 0:
                    conn.execute(text("ALTER TABLE password_reset_tokens ADD COLUMN reset_code VARCHAR(10)"))
                conn.commit()

        logger.info("[+] Database schema verified and up-to-date.")
    except Exception as e:
        logger.warning(f"[-] Database schema migration note: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

