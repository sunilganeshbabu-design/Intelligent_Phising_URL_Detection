import sys
import os
import uuid
import datetime

# Ensure backend path is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from starlette.requests import Request
from app.core.database import SessionLocal, engine, Base, init_db_and_migrate
from app.models.db_models import User, URLScan, EmailVerificationToken, PasswordResetToken
from app.models.schemas import (
    UserLogin, UserCreate, UserProfileUpdate, ChangePasswordRequest,
    ForgotPasswordRequest, ResetPasswordRequest, PredictRequest
)
from app.core.security import get_password_hash, verify_password, create_access_token, decode_access_token
from app.api.auth import (
    login, register, get_current_user_profile, update_user_profile,
    change_password, forgot_password, reset_password, verify_email
)
from app.api.predict import run_prediction
from app.api.history import get_scan_history, get_scan_detail
from app.api.reports import download_scan_pdf
from fastapi import HTTPException

def mock_request(ip="127.0.0.1"):
    scope = {
        "type": "http",
        "client": (ip, 12345),
        "headers": []
    }
    return Request(scope)

def test_full_auth_suite():
    print("==================================================")
    print("[*] RUNNING PHISHGUARD AI DIRECT AUTHENTICATION SUITE")
    print("==================================================")

    # Initialize tables and schema migration
    init_db_and_migrate()
    db = SessionLocal()

    try:
        req = mock_request()

        # 1. Admin and Demo User Verification
        print("\n[1] Verifying Admin & Demo Analyst Accounts...")
        admin = db.query(User).filter(User.email == "admin@phishguard.ai").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@phishguard.ai",
                full_name="Administrator Officer",
                password_hash=get_password_hash("Admin@123"),
                role="admin",
                auth_provider="email",
                email_verified=True,
                is_active=True
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)

        assert verify_password("Admin@123", admin.password_hash)
        print("  [+] Admin credentials verified with Bcrypt.")

        # Test login endpoint
        login_req = UserLogin(username_or_email="admin@phishguard.ai", password="Admin@123", remember_me=True)
        login_res = login(login_req, req, db)
        assert login_res["access_token"] is not None
        assert login_res["user"].role == "admin"
        admin_token = login_res["access_token"]
        print("  [+] Admin login token issued successfully.")

        # 2. Test Password Complexity Validation
        print("\n[2] Testing Password Strength Validation...")
        try:
            weak_create = UserCreate(
                full_name="Weak User",
                email="weak@test.com",
                password="weak",
                confirm_password="weak"
            )
            register(weak_create, req, db)
            assert False, "Weak password was not rejected!"
        except HTTPException as e:
            assert e.status_code == 422 or e.status_code == 400
            print(f"  [+] Weak password correctly rejected: {e.detail}")

        # 3. Test Real User Registration
        unique_id = uuid.uuid4().hex[:6]
        test_email = f"analyst_{unique_id}@phishguard-cybersec.com"
        strong_pwd = "Secure@Password123!"

        print(f"\n[3] Testing Real User Registration for {test_email}...")
        user_create = UserCreate(
            full_name="Alex Mercer (SecOps)",
            email=test_email,
            password=strong_pwd,
            confirm_password=strong_pwd
        )
        reg_res = register(user_create, req, db)
        assert reg_res["access_token"] is not None
        assert reg_res["user"].email == test_email
        assert reg_res["user"].auth_provider == "email"
        assert reg_res["user"].email_verified is False
        user_a = db.query(User).filter(User.email == test_email).first()
        print(f"  [+] User A registered successfully. User ID: {user_a.id}")

        # 4. Test Duplicate Email Prevention
        print("\n[4] Testing Duplicate Email Prevention...")
        try:
            register(user_create, req, db)
            assert False, "Duplicate email was not rejected!"
        except HTTPException as e:
            assert e.status_code == 400
            print(f"  [+] Duplicate registration blocked: {e.detail}")

        # 5. Test Profile Update
        print("\n[5] Testing Profile Update...")
        profile_req = UserProfileUpdate(
            full_name="Alex Mercer (Lead Threat Hunter)",
            avatar_url="https://images.unsplash.com/photo-1535713875002-d1d0cf377fde"
        )
        updated_profile = update_user_profile(profile_req, user_a, db)
        assert updated_profile.full_name == "Alex Mercer (Lead Threat Hunter)"
        print("  [+] Profile updated successfully.")

        # 6. Test Password Change
        print("\n[6] Testing Change Password Flow...")
        new_pwd = "SuperSecret@NewPwd2026!"
        change_req = ChangePasswordRequest(
            current_password=strong_pwd,
            new_password=new_pwd,
            confirm_password=new_pwd
        )
        change_res = change_password(change_req, user_a, db)
        assert change_res["success"] is True
        # Verify new password
        db.refresh(user_a)
        assert verify_password(new_pwd, user_a.password_hash)
        print("  [+] Password changed and verified.")

        # 7. Test Forgot Password and Reset Code
        print("\n[7] Testing Forgot Password & Reset Code...")
        forgot_req = ForgotPasswordRequest(email=test_email)
        forgot_res = forgot_password(forgot_req, req, db)
        assert forgot_res.get("reset_code") is not None
        reset_code = forgot_res["reset_code"]
        print(f"  [+] Reset token generated with 6-digit code: {reset_code}")

        final_pwd = "Ultimate@ResetPwd789!"
        reset_req = ResetPasswordRequest(
            email=test_email,
            reset_code=reset_code,
            new_password=final_pwd,
            confirm_password=final_pwd
        )
        reset_res = reset_password(reset_req, req, db)
        assert reset_res["success"] is True
        db.refresh(user_a)
        assert verify_password(final_pwd, user_a.password_hash)
        print("  [+] Password reset completed successfully.")

        # 8. Test Multi-User Data Isolation
        print("\n[8] Testing Multi-User Data Isolation...")
        # Create second user
        user_b = User(
            username=f"analyst_b_{unique_id}",
            email=f"user_b_{unique_id}@test.com",
            full_name="User B (Analyst)",
            password_hash=get_password_hash("Demo@12345"),
            role="user",
            auth_provider="email",
            email_verified=True,
            is_active=True
        )
        db.add(user_b)
        db.commit()
        db.refresh(user_b)

        # User A performs a scan
        pred_req = PredictRequest(
            url="http://bank-verification-account-phish.suspicious.net/login",
            model_name="XGBoost",
            include_xai=True,
            scan_type="url"
        )
        scan_result = run_prediction(pred_req, db, current_user=user_a)
        scan_id = scan_result.id
        print(f"  [+] User A performed scan ID #{scan_id}")

        # User B attempts to access User A's scan
        try:
            get_scan_detail(scan_id, db, current_user=user_b)
            assert False, "Data Isolation Failed: User B accessed User A's scan!"
        except HTTPException as e:
            assert e.status_code == 403
            print(f"  [+] Data isolation confirmed: User B received 403 Forbidden ({e.detail})")

        # User B attempts to download User A's PDF report
        try:
            download_scan_pdf(scan_id, db, current_user=user_b)
            assert False, "Data Isolation Failed: User B downloaded User A's PDF!"
        except HTTPException as e:
            assert e.status_code == 403
            print(f"  [+] PDF report isolation confirmed: User B received 403 Forbidden ({e.detail})")

        # Admin CAN access User A's scan
        admin_scan = get_scan_detail(scan_id, db, current_user=admin)
        assert admin_scan.id == scan_id
        print("  [+] Admin role authorized to access scan successfully.")

        # 9. Verify XGBoost Model Accuracy & Explanations Intact
        print("\n[9] Testing ML Pipeline & SHAP Explanations...")
        assert scan_result.prediction in ["Phishing", "Legitimate"]
        assert scan_result.shap_explanation is not None
        assert len(scan_result.shap_explanation.contributions) > 0
        print(f"  [+] XGBoost Model Prediction: {scan_result.prediction} ({scan_result.phishing_probability}%)")
        print(f"  [+] SHAP Explanation Features: {len(scan_result.shap_explanation.contributions)} feature contributions analyzed.")

        print("\n==================================================")
        print("[+] ALL DIRECT AUTHENTICATION & SECURITY TESTS PASSED 100%!")
        print("==================================================")

    finally:
        db.close()

if __name__ == "__main__":
    test_full_auth_suite()
