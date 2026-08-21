import time
import datetime
from typing import Dict, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ..core.database import get_db
from ..core.config import settings
from ..core.security import (
    verify_password, get_password_hash, create_access_token, 
    get_current_user, validate_password_strength, enforce_rate_limit,
    generate_secure_token, generate_verification_code
)
from ..models.db_models import User, EmailVerificationToken, PasswordResetToken
from ..models.schemas import (
    UserCreate, UserLogin, UserResponse, Token,
    UserProfileUpdate, ChangePasswordRequest,
    ForgotPasswordRequest, ForgotPasswordResponse, ResetPasswordRequest,
    VerifyEmailRequest, ResendVerificationRequest
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ============================================================================
# 1. USER REGISTRATION (SIGN UP)
# ============================================================================
@router.post("/register", response_model=Token)
def register(user_in: UserCreate, request: Request, db: Session = Depends(get_db)):
    """
    Registers a new user account with real email + password credentials.
    Enforces strong password policy, checks duplicate emails, and securely hashes passwords.
    """
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(f"register:{client_ip}", max_requests=10, window_seconds=60, action_desc="registration requests")

    clean_email = user_in.email.lower().strip()
    
    # 1. Check duplicate email in database
    existing_user = db.query(User).filter(User.email == clean_email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please sign in."
        )

    # 2. Validate Password Policy
    is_valid_pwd, pwd_error_msg = validate_password_strength(user_in.password)
    if not is_valid_pwd:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=pwd_error_msg
        )

    # 3. Confirm Password Match Check
    if user_in.confirm_password and user_in.password != user_in.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match. Please verify your password confirmation."
        )

    # 4. Generate clean username from email / name
    raw_name = (user_in.full_name or "").strip()
    candidate_username = (user_in.username or "").strip()
    if not candidate_username:
        base_username = raw_name.lower().replace(" ", "_") if raw_name else clean_email.split("@")[0]
        base_username = "".join(c for c in base_username if c.isalnum() or c == "_") or "analyst"
        candidate_username = base_username
        suffix = 1
        while db.query(User).filter(User.username == candidate_username).first():
            candidate_username = f"{base_username}_{suffix}"
            suffix += 1

    # 5. Create new User with Bcrypt hashed password
    password_hash = get_password_hash(user_in.password)
    new_user = User(
        username=candidate_username,
        email=clean_email,
        full_name=raw_name or candidate_username,
        password_hash=password_hash,
        auth_provider="email",
        email_verified=False,
        role="user",
        is_active=True,
        created_at=datetime.datetime.now(),
        last_login_at=datetime.datetime.now()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # 6. Generate real email verification token
    verification_token = generate_secure_token(32)
    verification_code = generate_verification_code(6)
    token_record = EmailVerificationToken(
        user_id=new_user.id,
        token=verification_token,
        code=verification_code,
        verification_code=verification_code,
        expires_at=datetime.datetime.now() + datetime.timedelta(hours=24),
        is_used=False
    )
    db.add(token_record)
    db.commit()

    # 7. Issue session JWT Token
    token = create_access_token(new_user.id, remember_me=True)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": new_user
    }

# ============================================================================
# 2. USER LOGIN (SIGN IN)
# ============================================================================
@router.post("/login", response_model=Token)
def login(login_in: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Authenticates an existing user using Email + Password.
    Verifies stored Bcrypt hash, checks account status, and updates last_login_at timestamp.
    """
    client_ip = request.client.host if request.client else "unknown"
    login_target = login_in.username_or_email.lower().strip()
    
    enforce_rate_limit(f"login:{client_ip}:{login_target}", max_requests=10, window_seconds=60, action_desc="login attempts")

    user = db.query(User).filter(
        or_(User.username == login_target, User.email == login_target)
    ).first()

    # Generic security error message
    if not user or not user.password_hash or not verify_password(login_in.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated. Please contact your system administrator."
        )

    # Update last login timestamp
    user.last_login_at = datetime.datetime.now()
    db.commit()
    db.refresh(user)

    remember_me = bool(login_in.remember_me)
    token = create_access_token(user.id, remember_me=remember_me)
    expires_in_seconds = (settings.ACCESS_TOKEN_EXPIRE_MINUTES if remember_me else 60 * 24) * 60

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in_seconds,
        "user": user
    }

# ============================================================================
# 3. CURRENT USER PROFILE (/me & /profile)
# ============================================================================
@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated profile of the currently logged-in user."""
    return current_user

@router.put("/profile", response_model=UserResponse)
def update_user_profile(
    profile_in: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Updates user full name and avatar."""
    if profile_in.full_name is not None:
        name_clean = profile_in.full_name.strip()
        if len(name_clean) > 0:
            current_user.full_name = name_clean
            
    if profile_in.avatar_url is not None:
        current_user.avatar_url = profile_in.avatar_url.strip() or None

    current_user.updated_at = datetime.datetime.now()
    db.commit()
    db.refresh(current_user)
    return current_user

# ============================================================================
# 4. CHANGE PASSWORD
# ============================================================================
@router.post("/change-password")
def change_password(
    pwd_in: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Allows an authenticated user to change their password."""
    if not current_user.password_hash or not verify_password(pwd_in.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect. Please verify and try again."
        )

    if pwd_in.confirm_password and pwd_in.new_password != pwd_in.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation do not match."
        )

    is_valid, reason = validate_password_strength(pwd_in.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=reason
        )

    current_user.password_hash = get_password_hash(pwd_in.new_password)
    current_user.updated_at = datetime.datetime.now()
    db.commit()

    return {
        "success": True,
        "message": "Your password has been changed successfully."
    }

# ============================================================================
# 5. LOGOUT
# ============================================================================
@router.post("/logout")
def logout():
    """Terminates active session."""
    return {"success": True, "message": "Successfully logged out of session."}

# ============================================================================
# 6. FORGOT PASSWORD & PASSWORD RESET
# ============================================================================
@router.post("/forgot-password", response_model=ForgotPasswordResponse)
def forgot_password(req_in: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """
    Generates a secure 15-minute single-use password reset code.
    Returns a generic message to prevent email enumeration.
    """
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(f"forgot_password:{client_ip}", max_requests=6, window_seconds=60, action_desc="password reset requests")

    email_clean = req_in.email.lower().strip()
    user = db.query(User).filter(User.email == email_clean).first()
    
    reset_code_for_user = None

    if user and user.is_active:
        # Invalidate existing active tokens
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.is_used == False
        ).update({"is_used": True})
        
        secure_token = generate_secure_token(32)
        reset_code = generate_verification_code(6)
        reset_code_for_user = reset_code
        
        token_entry = PasswordResetToken(
            user_id=user.id,
            token=secure_token,
            code=reset_code,
            reset_code=reset_code,
            expires_at=datetime.datetime.now() + datetime.timedelta(minutes=15),
            is_used=False
        )
        db.add(token_entry)
        db.commit()

    return {
        "success": True,
        "message": "If an account exists for this email, password reset instructions have been sent.",
        "reset_code": reset_code_for_user
    }

@router.post("/reset-password")
def reset_password(reset_in: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """
    Resets the user's password using the 6-digit recovery code or token.
    Enforces password complexity and updates the Bcrypt hash.
    """
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(f"reset_password:{client_ip}", max_requests=8, window_seconds=60, action_desc="password reset confirmations")

    email_clean = reset_in.email.lower().strip()
    user = db.query(User).filter(User.email == email_clean).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset code. Please request a new recovery code."
        )

    code_clean = reset_in.reset_code.strip()
    token_entry = db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        or_(PasswordResetToken.code == code_clean, PasswordResetToken.token == code_clean),
        PasswordResetToken.is_used == False,
        PasswordResetToken.expires_at > datetime.datetime.now()
    ).first()

    if not token_entry:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or previously used recovery code. Please request a new code."
        )

    if reset_in.confirm_password and reset_in.new_password != reset_in.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation do not match."
        )

    is_valid, reason = validate_password_strength(reset_in.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=reason
        )

    user.password_hash = get_password_hash(reset_in.new_password)
    user.updated_at = datetime.datetime.now()
    token_entry.is_used = True
    db.commit()

    return {
        "success": True,
        "message": "Password reset successfully. You can now sign in with your new credentials."
    }

# ============================================================================
# 7. EMAIL VERIFICATION
# ============================================================================
@router.post("/verify-email")
def verify_email(verify_in: VerifyEmailRequest, db: Session = Depends(get_db)):
    """Verifies a user's email address using a single-use token or 6-digit code."""
    token_str = (verify_in.token or verify_in.code or "").strip()
    if not token_str:
        raise HTTPException(status_code=400, detail="Verification token or code is required.")

    query = db.query(EmailVerificationToken).filter(
        or_(EmailVerificationToken.token == token_str, EmailVerificationToken.code == token_str),
        EmailVerificationToken.is_used == False,
        EmailVerificationToken.expires_at > datetime.datetime.now()
    )

    if verify_in.email:
        user = db.query(User).filter(User.email == verify_in.email.lower().strip()).first()
        if user:
            query = query.filter(EmailVerificationToken.user_id == user.id)

    token_record = query.first()
    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid, expired, or used verification code.")

    user = db.query(User).filter(User.id == token_record.user_id).first()
    if user:
        user.email_verified = True
        token_record.is_used = True
        db.commit()

    return {"success": True, "message": "Email address verified successfully!"}

@router.post("/resend-verification")
def resend_verification(req_in: ResendVerificationRequest, request: Request, db: Session = Depends(get_db)):
    """Resends a new 6-digit email verification code."""
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(f"resend_verification:{client_ip}", max_requests=5, window_seconds=60, action_desc="resend requests")

    email_clean = req_in.email.lower().strip()
    user = db.query(User).filter(User.email == email_clean).first()
    
    if user and not user.email_verified:
        new_token = generate_secure_token(32)
        new_code = generate_verification_code(6)
        token_entry = EmailVerificationToken(
            user_id=user.id,
            token=new_token,
            code=new_code,
            verification_code=new_code,
            expires_at=datetime.datetime.now() + datetime.timedelta(hours=24),
            is_used=False
        )
        db.add(token_entry)
        db.commit()
        return {"success": True, "message": f"New verification code issued for {email_clean}."}

    return {"success": True, "message": "If an unverified account exists for this email, a verification code has been issued."}
