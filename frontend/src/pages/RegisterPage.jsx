import React, { useState } from 'react';
import { 
  Shield, Lock, Mail, User, Eye, EyeOff, 
  Check, X, AlertCircle, Loader2, ArrowRight, ShieldCheck
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const RegisterPage = ({ onRegisterSuccess, onNavigateToSignIn }) => {
  const { register } = useAuth();
  
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [agreeTerms, setAgreeTerms] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Real-time email validation
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());

  // Password criteria evaluation
  const hasMinLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  const criteriaCount = [hasMinLength, hasUppercase, hasLowercase, hasNumber, hasSpecial].filter(Boolean).length;

  const getStrengthInfo = () => {
    if (!password) return { label: 'None', percent: 0, color: '#64748B' };
    if (criteriaCount <= 2) return { label: 'Weak', percent: 30, color: '#EF4444' };
    if (criteriaCount <= 4) return { label: 'Good', percent: 70, color: '#F59E0B' };
    return { label: 'Strong', percent: 100, color: '#10B981' };
  };

  const strength = getStrengthInfo();
  const passwordsMatch = password.length > 0 && confirmPassword.length > 0 && password === confirmPassword;

  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    // Field Validations
    if (!fullName.trim()) {
      setError('Please enter your full name.');
      return;
    }
    if (!email.trim() || !isValidEmail) {
      setError('Please enter a valid email address (e.g. analyst@domain.com).');
      return;
    }
    if (!hasMinLength) {
      setError('Password must be at least 8 characters long.');
      return;
    }
    if (!hasUppercase) {
      setError('Password must contain at least one uppercase letter (A-Z).');
      return;
    }
    if (!hasLowercase) {
      setError('Password must contain at least one lowercase letter (a-z).');
      return;
    }
    if (!hasNumber) {
      setError('Password must contain at least one numeric digit (0-9).');
      return;
    }
    if (!hasSpecial) {
      setError('Password must contain at least one special character (!@#$%^&*).');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match. Please verify your password confirmation.');
      return;
    }
    if (!agreeTerms) {
      setError('You must accept the Terms of Service and Privacy Policy to register.');
      return;
    }

    setLoading(true);
    try {
      await register(fullName.trim(), email.trim(), password, confirmPassword);
      setSuccessMsg('Account registered successfully! Redirecting to workspace...');
      setTimeout(() => {
        if (onRegisterSuccess) onRegisterSuccess();
      }, 1000);
    } catch (err) {
      const detailMsg = err.response?.data?.detail;
      if (detailMsg) {
        setError(detailMsg);
      } else if (err.message === 'Network Error' || err.code === 'ERR_NETWORK') {
        setError('Network Error: Unable to connect to backend server. If the server is spinning up, please retry in 10 seconds.');
      } else {
        setError(err.message || 'Registration failed. Please check your information.');
      }
    } finally {
      setLoading(false);
    }
  };

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
        maxWidth: '490px',
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
            Create PhishGuard Account
          </h2>
          <p style={{ fontSize: '0.82rem', color: '#94A3B8', margin: 0 }}>
            Sign up with your email to access AI-powered phishing defense & XAI models.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleRegisterSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* Full Name */}
          <div>
            <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
              Full Name *
            </label>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <User size={16} color="#64748B" style={{ position: 'absolute', left: '12px', pointerEvents: 'none' }} />
              <input
                type="text"
                placeholder="e.g. Suneel Kumar"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
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
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 20, 0.8)',
                  border: `1px solid ${email && !isValidEmail ? '#EF4444' : 'rgba(255, 255, 255, 0.1)'}`,
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
            <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
              Password *
            </label>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Lock size={16} color="#64748B" style={{ position: 'absolute', left: '12px', pointerEvents: 'none' }} />
              <input
                type={showPassword ? 'text' : 'password'}
                placeholder="Min. 8 characters"
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

            {/* Password Strength Indicator */}
            {password && (
              <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.72rem' }}>
                  <span style={{ color: '#94A3B8' }}>Strength:</span>
                  <strong style={{ color: strength.color }}>{strength.label}</strong>
                </div>
                <div style={{ width: '100%', height: '4px', background: 'rgba(255, 255, 255, 0.1)', borderRadius: '2px', overflow: 'hidden' }}>
                  <div style={{
                    width: `${strength.percent}%`,
                    height: '100%',
                    background: strength.color,
                    transition: 'all 0.3s ease'
                  }} />
                </div>
                {/* Criteria ticks */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px', fontSize: '0.68rem', color: '#94A3B8', marginTop: '2px' }}>
                  <span style={{ color: hasMinLength ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    {hasMinLength ? <Check size={12} /> : <X size={12} />} 8+ characters
                  </span>
                  <span style={{ color: hasUppercase ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    {hasUppercase ? <Check size={12} /> : <X size={12} />} Uppercase (A-Z)
                  </span>
                  <span style={{ color: hasLowercase ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    {hasLowercase ? <Check size={12} /> : <X size={12} />} Lowercase (a-z)
                  </span>
                  <span style={{ color: hasNumber ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    {hasNumber ? <Check size={12} /> : <X size={12} />} Numeric (0-9)
                  </span>
                  <span style={{ color: hasSpecial ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    {hasSpecial ? <Check size={12} /> : <X size={12} />} Special symbol
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Confirm Password */}
          <div>
            <label style={{ fontSize: '0.78rem', color: '#CBD5E1', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
              Confirm Password *
            </label>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Lock size={16} color="#64748B" style={{ position: 'absolute', left: '12px', pointerEvents: 'none' }} />
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                placeholder="Re-enter password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 20, 0.8)',
                  border: `1px solid ${confirmPassword && confirmPassword !== password ? '#EF4444' : 'rgba(255, 255, 255, 0.1)'}`,
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
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                style={{
                  position: 'absolute',
                  right: '10px',
                  background: 'transparent',
                  border: 'none',
                  color: showConfirmPassword ? '#38BDF8' : '#64748B',
                  cursor: 'pointer',
                  padding: '4px',
                  display: 'flex',
                  alignItems: 'center'
                }}
                title={showConfirmPassword ? 'Hide confirmation' : 'Show confirmation'}
              >
                {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            {confirmPassword && (
              <div style={{ fontSize: '0.72rem', marginTop: '4px', color: passwordsMatch ? '#10B981' : '#EF4444', display: 'flex', alignItems: 'center', gap: '4px' }}>
                {passwordsMatch ? <Check size={12} /> : <X size={12} />}
                {passwordsMatch ? 'Passwords match' : 'Passwords do not match'}
              </div>
            )}
          </div>

          {/* Terms & Conditions Checkbox */}
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginTop: '2px' }}>
            <input
              type="checkbox"
              id="agreeTerms"
              checked={agreeTerms}
              onChange={(e) => setAgreeTerms(e.target.checked)}
              style={{ marginTop: '3px', cursor: 'pointer', accentColor: '#38BDF8' }}
            />
            <label htmlFor="agreeTerms" style={{ fontSize: '0.76rem', color: '#94A3B8', cursor: 'pointer', lineHeight: '1.4' }}>
              I accept the <span style={{ color: '#38BDF8', fontWeight: '600' }}>Terms of Service</span> and <span style={{ color: '#38BDF8', fontWeight: '600' }}>Privacy Policy</span>.
            </label>
          </div>

          {/* Error Banner */}
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

          {/* Success Banner */}
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
                <Loader2 size={16} className="animate-spin" /> Creating Account...
              </div>
            ) : (
              'Create Account'
            )}
          </button>
        </form>

        {/* Link to Sign In */}
        <div style={{ textAlign: 'center', borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '16px' }}>
          <span style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
            Already registered?{' '}
          </span>
          <button
            type="button"
            onClick={onNavigateToSignIn}
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
            Sign In here
          </button>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;
