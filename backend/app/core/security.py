import time
import secrets
import string
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Any, Dict, List, Tuple
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .config import settings
from .database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login", auto_error=False)

# ----------------- Rate Limiter / Brute-Force Protection -----------------
# Maps key (e.g. "login:127.0.0.1" or "forgot:email@example.com") -> list of timestamps
_RATE_LIMIT_STORE: Dict[str, List[float]] = defaultdict(list)

def check_rate_limit(key: str, max_requests: int, window_seconds: int = 60) -> bool:
    """
    Sliding-window rate limiter. Returns True if allowed, False if limit exceeded.
    """
    now = time.time()
    timestamps = _RATE_LIMIT_STORE[key]
    
    # Remove timestamps older than window
    cutoff = now - window_seconds
    _RATE_LIMIT_STORE[key] = [t for t in timestamps if t > cutoff]
    
    if len(_RATE_LIMIT_STORE[key]) >= max_requests:
        return False
        
    _RATE_LIMIT_STORE[key].append(now)
    return True

def enforce_rate_limit(key: str, max_requests: int, window_seconds: int = 60, action_desc: str = "requests"):
    """
    Enforces rate limit by raising 429 Too Many Requests if limit exceeded.
    """
    if not check_rate_limit(key, max_requests, window_seconds):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many {action_desc}. Please wait a moment before trying again."
        )

# ----------------- Cryptographic Token Helpers -----------------
def generate_secure_token(nbytes: int = 32) -> str:
    """
    Generates a cryptographically secure URL-safe random string.
    """
    return secrets.token_urlsafe(nbytes)

def generate_verification_code(length: int = 6) -> str:
    """
    Generates a cryptographically secure numeric string of specified length (e.g. '849201').
    """
    return "".join(secrets.choice(string.digits) for _ in range(length))

# ----------------- Password Security & Validation -----------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validates that password meets industry cybersecurity complexity standards:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one numeric digit."
    if not any(c in string.punctuation for c in password):
        return False, "Password must contain at least one special character (e.g. !@#$%^&*)."
    return True, ""

# ----------------- JWT Access Token Helpers -----------------
def create_access_token(
    subject: Union[str, Any], 
    expires_delta: Optional[timedelta] = None,
    remember_me: bool = True
) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # 30 days if remember_me, else 1 day
        minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES if remember_me else 60 * 24
        expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "iat": datetime.now(timezone.utc)
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None

# ----------------- User Authentication Dependencies -----------------
def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None
    
    from ..models.db_models import User
    user = db.query(User).filter(User.id == int(user_id)).first()
    return user if user and user.is_active else None

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session has expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    from ..models.db_models import User
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been deactivated. Please contact an administrator."
        )
    return user

def get_current_admin(
    current_user = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to access this resource."
        )
    return current_user
