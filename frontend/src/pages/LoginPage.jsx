import React, { useState } from 'react';
import { 
  Shield, Lock, Mail, Eye, EyeOff, 
  ArrowLeft, CheckCircle2, AlertCircle, Loader2,
  Check, X, KeyRound, ShieldCheck
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { 
  requestForgotPassword, submitResetPassword, 
  verifyEmailToken, resendEmailVerification 
} from '../services/api';

const LoginPage = ({ onLoginSuccess, onNavigateToRegister }) => {
  const { user, isAuthenticated, logout, login } = useAuth();
  
  // View states: 'signin', 'forgot_step1', 'forgot_step2', 'forgot_success', 'verify_email'
  const [viewMode, setViewMode] = useState('signin');
  
  // Sign In Form States
  const [emailOrUsername, setEmailOrUsername] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  
  // Forgot Password Form States
  const [forgotEmail, setForgotEmail] = useState('');
  const [resetCode, setResetCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [generatedCodeHint, setGeneratedCodeHint] = useState('');

  // Email Verification States
  const [verifyEmailAddr, setVerifyEmailAddr] = useState('');
  const [verifyCodeInput, setVerifyCodeInput] = useState('');

  // Status & Feedback
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const isForgot = viewMode.startsWith('forgot');

  // Password criteria evaluation for reset
  const hasMinLength = newPassword.length >= 8;
  const hasUppercase = /[A-Z]/.test(newPassword);
  const hasLowercase = /[a-z]/.test(newPassword);
  const hasNumber = /[0-9]/.test(newPassword);
  const hasSpecial = /[^A-Za-z0-9]/.test(newPassword);

  // Handle Standard Sign In
  const handleSignInSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!emailOrUsername.trim()) {
      setError('Please enter your email address.');
      return;
    }
    if (!password) {
      setError('Please enter your password.');
      return;
    }

    setLoading(true);
    try {
      await login(emailOrUsername.trim(), password, rememberMe);
      if (onLoginSuccess) onLoginSuccess();
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid email or password.');
    } finally {
      setLoading(false);
    }
  };

  // Forgot Password: Step 1 - Request 6-digit recovery code
  const handleRequestResetCode = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!forgotEmail.trim()) {
      setError('Please enter your registered email address.');
      return;
    }

    setLoading(true);
    try {
      const res = await requestForgotPassword(forgotEmail.trim());
      if (res.reset_code) {
        setResetCode(res.reset_code);
        setGeneratedCodeHint(res.reset_code);
      }
      setSuccessMsg(res.message || 'If an account exists for this email, password reset instructions have been sent.');
      setViewMode('forgot_step2');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to process password recovery.');
    } finally {
      setLoading(false);
    }
  };

  // Forgot Password: Step 2 - Submit New Password with Code
  const handleResetPasswordSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!resetCode.trim()) {
      setError('Please enter the 6-digit recovery code.');
      return;
    }
    if (!hasMinLength || !hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
      setError('New password must be at least 8 characters with uppercase, lowercase, numbers, and special symbols.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match. Please verify confirmation.');
      return;
    }

    setLoading(true);
    try {
      await submitResetPassword(forgotEmail.trim(), resetCode.trim(), newPassword, confirmPassword);
      setSuccessMsg('Your password has been successfully reset! You can now sign in.');
      setViewMode('forgot_success');
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid or expired recovery code.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Email Verification Submission
  const handleVerifyEmailSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!verifyCodeInput.trim()) {
      setError('Please enter your 6-digit verification code.');
      return;
    }

    setLoading(true);
    try {
      await verifyEmailToken(verifyCodeInput.trim(), verifyEmailAddr.trim() || null);
      setSuccessMsg('Email successfully verified! Redirecting to Sign In...');
      setTimeout(() => {
        setViewMode('signin');
        setEmailOrUsername(verifyEmailAddr);
        setSuccessMsg('');
      }, 1500);
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid or expired verification code.');
    } finally {
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    if (!verifyEmailAddr.trim()) {
      setError('Please provide your email address to resend the code.');
      return;
    }
    setLoading(true);
    try {
      const res = await resendEmailVerification(verifyEmailAddr.trim());
      setSuccessMsg(res.message || 'Verification code resent.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to resend code.');
    } finally {
      setLoading(false);
    }
  };

  // If already logged in, show active session banner
  if (isAuthenticated && user) {
    return (
      <div style={{
        minHeight: '75vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px'
      }}>
        <div className="glass-panel" style={{
          width: '100%',
          maxWidth: '460px',
          padding: '36px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center',
          gap: '20px',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6)',
          border: '1px solid rgba(16, 185, 129, 0.3)'
        }}>
          <div style={{
            background: 'rgba(16, 185, 129, 0.15)',
            padding: '16px',
            borderRadius: '50%',
            color: '#10B981'
          }}>
            <CheckCircle2 size={40} />
          </div>

          <div>
            <h2 style={{ fontSize: '1.3rem', fontWeight: '800', color: '#F8FAFC' }}>
              Active Session Detected
            </h2>
            <p style={{ fontSize: '0.86rem', color: '#94A3B8', marginTop: '6px' }}>
              You are currently signed in as <strong style={{ color: '#38BDF8' }}>{user.full_name || user.username}</strong> ({user.email}).
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%', marginTop: '8px' }}>
            <button
              onClick={onLoginSuccess}
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '11px' }}
            >
              Continue to Dashboard
            </button>

            <button
              onClick={logout}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                padding: '10px',
                borderRadius: '8px',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                background: 'rgba(239, 68, 68, 0.1)',
                color: '#EF4444',
                fontWeight: '700',
                fontSize: '0.86rem',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'}
            >
              Sign Out of Account
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '80vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px 16px'
    }}>
      <div className="glass-panel" style={{
        width: '100%',
        maxWidth: '460px',
        padding: '36px',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6)',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        position: 'relative'
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
          <div style={{
            background: 'linear-gradient(135deg, #0284C7 0%, #38BDF8 100%)',
            padding: '12px',
            borderRadius: '16px',
            boxShadow: '0 0 20px rgba(56, 189, 248, 0.4)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#FFF'
          }}>
            <Shield size={30} />
          </div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: '800', color: '#F8FAFC', margin: '4px 0 0' }}>
            {viewMode === 'signin' && 'Sign In to PhishGuard'}
            {viewMode === 'forgot_step1' && 'Recover Account Password'}
            {viewMode === 'forgot_step2' && 'Set New Password'}
            {viewMode === 'forgot_success' && 'Password Reset Complete'}
            {viewMode === 'verify_email' && 'Verify Email Address'}
          </h2>
          <p style={{ fontSize: '0.82rem', color: '#94A3B8', margin: 0 }}>
            {viewMode === 'signin' && 'Enter your email and password to access the cybersecurity workspace.'}
            {viewMode === 'forgot_step1' && 'Enter your email address to receive a 6-digit recovery code.'}
            {viewMode === 'forgot_step2' && 'Enter the 6-digit code and choose a new secure password.'}
            {viewMode === 'verify_email' && 'Enter your registered email and 6-digit verification code.'}
          </p>
        </div>

        {/* ================= VIEW 1: STANDARD SIGN IN ================= */}
        {viewMode === 'signin' && (
          <>
            <form onSubmit={handleSignInSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {/* Email Address */}
              <div>
                <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                  Email Address *
                </label>
                <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <Mail size={16} color="#64748B" style={{ position: 'absolute', left: '12px', pointerEvents: 'none' }} />
                  <input
                    type="email"
                    placeholder="analyst@domain.com"
                    value={emailOrUsername}
                    onChange={(e) => setEmailOrUsername(e.target.value)}
                    style={{
                      width: '100%',
                      background: 'rgba(7, 11, 20, 0.8)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                      padding: '9px 12px 9px 36px',
                      color: '#F8FAFC',
                      fontSize: '0.88rem',
                      outline: 'none'
                    }}
                    required
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <label style={{ fontSize: '0.78rem', color: '#CBD5E1', fontWeight: '600' }}>
                    Password *
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setViewMode('forgot_step1');
                      setForgotEmail(emailOrUsername);
                      setError('');
                      setSuccessMsg('');
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#38BDF8',
                      fontSize: '0.76rem',
                      cursor: 'pointer',
                      padding: 0,
                      fontWeight: '600'
                    }}
                  >
                    Forgot password?
                  </button>
                </div>
                <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <Lock size={16} color="#64748B" style={{ position: 'absolute', left: '12px', pointerEvents: 'none' }} />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    style={{
                      width: '100%',
                      background: 'rgba(7, 11, 20, 0.8)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                      padding: '9px 38px 9px 36px',
                      color: '#F8FAFC',
                      fontSize: '0.88rem',
                      outline: 'none'
                    }}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{
                      position: 'absolute',
                      right: '10px',
                      background: 'transparent',
                      border: 'none',
                      color: showPassword ? '#38BDF8' : '#64748B',
                      cursor: 'pointer',
                      padding: '4px',
                      display: 'flex',
                      alignItems: 'center'
                    }}
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              {/* Remember Me Checkbox */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                <input
                  type="checkbox"
                  id="rememberMe"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  style={{ cursor: 'pointer', accentColor: '#38BDF8' }}
                />
                <label htmlFor="rememberMe" style={{ fontSize: '0.78rem', color: '#CBD5E1', cursor: 'pointer' }}>
                  Remember me on this device (30 days)
                </label>
              </div>

              {/* Error Alert */}
              {error && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.35)',
                  color: '#EF4444',
                  padding: '9px 12px',
                  borderRadius: '8px',
                  fontSize: '0.82rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <AlertCircle size={16} /> {error}
                </div>
              )}

              {/* Success Alert */}
              {successMsg && (
                <div style={{
                  background: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.35)',
                  color: '#10B981',
                  padding: '9px 12px',
                  borderRadius: '8px',
                  fontSize: '0.82rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <ShieldCheck size={16} /> {successMsg}
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading}
                className="btn-primary"
                style={{ width: '100%', justifyContent: 'center', marginTop: '4px', padding: '11px' }}
              >
                {loading ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Loader2 size={16} className="animate-spin" /> Authenticating...
                  </div>
                ) : (
                  'Sign In'
                )}
              </button>
            </form>

            {/* Link to Register */}
            <div style={{ textAlign: 'center', borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '16px' }}>
              <span style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                Don't have an account?{' '}
              </span>
              <button
                type="button"
                onClick={onNavigateToRegister}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#38BDF8',
                  fontSize: '0.84rem',
                  fontWeight: '700',
                  cursor: 'pointer',
                  padding: 0
                }}
              >
                Register here
              </button>
            </div>

            {/* Link to Email Verification */}
            <div style={{ textAlign: 'center', marginTop: '-6px' }}>
              <button
                type="button"
                onClick={() => {
                  setViewMode('verify_email');
                  setVerifyEmailAddr(emailOrUsername);
                  setError('');
                  setSuccessMsg('');
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#64748B',
                  fontSize: '0.76rem',
                  cursor: 'pointer',
                  padding: 0
                }}
              >
                Have an unverified email? <span style={{ color: '#38BDF8', fontWeight: '600' }}>Enter code</span>
              </button>
            </div>
          </>
        )}

        {/* ================= VIEW 2: FORGOT PASSWORD STEP 1 ================= */}
        {viewMode === 'forgot_step1' && (
          <form onSubmit={handleRequestResetCode} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                Enter Your Registered Email Address:
              </label>
              <div style={{ position: 'relative' }}>
                <Mail size={16} color="#64748B" style={{ position: 'absolute', left: '12px', top: '12px' }} />
                <input
                  type="email"
                  placeholder="analyst@domain.com"
                  value={forgotEmail}
                  onChange={(e) => setForgotEmail(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(7, 11, 20, 0.8)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    padding: '9px 12px 9px 36px',
                    color: '#F8FAFC',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                  required
                />
              </div>
            </div>

            {error && (
              <div style={{ color: '#EF4444', fontSize: '0.82rem' }}>
                ⚠️ {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '11px' }}
            >
              {loading ? 'Sending Code...' : 'Send 6-Digit Recovery Code'}
            </button>

            <button
              type="button"
              onClick={() => { setViewMode('signin'); setError(''); }}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#94A3B8',
                fontSize: '0.82rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px'
              }}
            >
              <ArrowLeft size={15} /> Back to Sign In
            </button>
          </form>
        )}

        {/* ================= VIEW 3: FORGOT PASSWORD STEP 2 ================= */}
        {viewMode === 'forgot_step2' && (
          <form onSubmit={handleResetPasswordSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {generatedCodeHint && (
              <div style={{
                background: 'rgba(56, 189, 248, 0.15)',
                border: '1px solid rgba(56, 189, 248, 0.35)',
                borderRadius: '8px',
                padding: '10px 14px',
                fontSize: '0.82rem',
                color: '#38BDF8',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <span>Recovery Code: <strong style={{ letterSpacing: '0.15em', fontSize: '1rem' }}>{generatedCodeHint}</strong></span>
                <span style={{ fontSize: '0.72rem', color: '#94A3B8' }}>(15 min TTL)</span>
              </div>
            )}

            <div>
              <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                6-Digit Recovery Code *
              </label>
              <input
                type="text"
                maxLength={6}
                placeholder="123456"
                value={resetCode}
                onChange={(e) => setResetCode(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 20, 0.8)',
                  border: '1px solid rgba(56, 189, 248, 0.4)',
                  borderRadius: '8px',
                  padding: '9px 12px',
                  color: '#38BDF8',
                  fontSize: '1.1rem',
                  fontWeight: '700',
                  letterSpacing: '0.2em',
                  textAlign: 'center',
                  outline: 'none'
                }}
                required
              />
            </div>

            <div>
              <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                New Password *
              </label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <Lock size={16} color="#64748B" style={{ position: 'absolute', left: '12px', pointerEvents: 'none' }} />
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  placeholder="Min. 8 characters"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(7, 11, 20, 0.8)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    padding: '9px 38px 9px 36px',
                    color: '#F8FAFC',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  style={{
                    position: 'absolute',
                    right: '10px',
                    background: 'transparent',
                    border: 'none',
                    color: showNewPassword ? '#38BDF8' : '#64748B',
                    cursor: 'pointer'
                  }}
                >
                  {showNewPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div>
              <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                Confirm New Password *
              </label>
              <div style={{ position: 'relative' }}>
                <Lock size={16} color="#64748B" style={{ position: 'absolute', left: '12px', top: '12px' }} />
                <input
                  type="password"
                  placeholder="Re-enter new password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(7, 11, 20, 0.8)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    padding: '9px 12px 9px 36px',
                    color: '#F8FAFC',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                  required
                />
              </div>
            </div>

            {error && (
              <div style={{ color: '#EF4444', fontSize: '0.82rem' }}>
                ⚠️ {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '11px' }}
            >
              {loading ? 'Updating Password...' : 'Save New Password'}
            </button>

            <button
              type="button"
              onClick={() => { setViewMode('forgot_step1'); setError(''); }}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#94A3B8',
                fontSize: '0.82rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px'
              }}
            >
              <ArrowLeft size={15} /> Change Email
            </button>
          </form>
        )}

        {/* ================= VIEW 4: FORGOT PASSWORD SUCCESS ================= */}
        {viewMode === 'forgot_success' && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px', textAlign: 'center', padding: '12px 0' }}>
            <div style={{
              background: 'rgba(16, 185, 129, 0.15)',
              padding: '16px',
              borderRadius: '50%',
              color: '#10B981'
            }}>
              <CheckCircle2 size={44} />
            </div>

            <h3 style={{ fontSize: '1.15rem', color: '#F8FAFC', fontWeight: '700', margin: 0 }}>
              Password Reset Complete!
            </h3>

            <p style={{ fontSize: '0.85rem', color: '#94A3B8', margin: 0 }}>
              Your password has been updated successfully. You can now sign in using your new credentials.
            </p>

            <button
              type="button"
              onClick={() => {
                setViewMode('signin');
                setPassword('');
                setError('');
                setSuccessMsg('');
              }}
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '11px', marginTop: '8px' }}
            >
              Sign In with New Password
            </button>
          </div>
        )}

        {/* ================= VIEW 5: EMAIL VERIFICATION ================= */}
        {viewMode === 'verify_email' && (
          <form onSubmit={handleVerifyEmailSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ textAlign: 'center', marginBottom: '4px' }}>
              <p style={{ fontSize: '0.84rem', color: '#94A3B8' }}>
                Enter your registered email address and the 6-digit verification code you received.
              </p>
            </div>

            <div>
              <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                Registered Email Address *
              </label>
              <div style={{ position: 'relative' }}>
                <Mail size={16} color="#64748B" style={{ position: 'absolute', left: '12px', top: '12px' }} />
                <input
                  type="email"
                  placeholder="analyst@domain.com"
                  value={verifyEmailAddr}
                  onChange={(e) => setVerifyEmailAddr(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(7, 11, 20, 0.8)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    padding: '9px 12px 9px 36px',
                    color: '#F8FAFC',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                  required
                />
              </div>
            </div>

            <div>
              <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                6-Digit Verification Code *
              </label>
              <input
                type="text"
                maxLength={6}
                placeholder="123456"
                value={verifyCodeInput}
                onChange={(e) => setVerifyCodeInput(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 20, 0.8)',
                  border: '1px solid rgba(56, 189, 248, 0.4)',
                  borderRadius: '8px',
                  padding: '9px 12px',
                  color: '#38BDF8',
                  fontSize: '1.1rem',
                  fontWeight: '700',
                  letterSpacing: '0.2em',
                  textAlign: 'center',
                  outline: 'none'
                }}
                required
              />
            </div>

            {error && (
              <div style={{ color: '#EF4444', fontSize: '0.82rem' }}>
                ⚠️ {error}
              </div>
            )}

            {successMsg && (
              <div style={{ color: '#10B981', fontSize: '0.82rem' }}>
                ✅ {successMsg}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '11px' }}
            >
              {loading ? 'Verifying...' : 'Verify Email Address'}
            </button>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.78rem' }}>
              <button
                type="button"
                onClick={handleResendCode}
                disabled={loading}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#38BDF8',
                  fontWeight: '600',
                  cursor: 'pointer',
                  padding: 0
                }}
              >
                Resend verification code
              </button>

              <button
                type="button"
                onClick={() => { setViewMode('signin'); setError(''); setSuccessMsg(''); }}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94A3B8',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
              >
                <ArrowLeft size={14} /> Back to Sign In
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default LoginPage;
