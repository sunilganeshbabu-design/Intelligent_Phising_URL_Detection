import React, { useState } from 'react';
import { 
  User, Mail, Shield, KeyRound, Calendar, Clock, 
  CheckCircle2, AlertCircle, Edit3, Save, X, Lock, 
  LogOut, ShieldAlert, ShieldCheck, Sparkles, Loader2,
  RefreshCw, Check
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const ProfilePage = ({ onNavigateScanner, onNavigateDashboard }) => {
  const { user, updateProfile, changePassword, logout, isAdmin } = useAuth();

  // Tab: 'overview', 'edit', 'password'
  const [activeSubTab, setActiveSubTab] = useState('overview');

  // Edit Profile Form States
  const [fullNameInput, setFullNameInput] = useState(user?.full_name || '');
  const [avatarUrlInput, setAvatarUrlInput] = useState(user?.avatar_url || '');

  // Change Password Form States
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);

  // Status & Feedback
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Password criteria evaluation for password change
  const hasMinLength = newPassword.length >= 8;
  const hasUppercase = /[A-Z]/.test(newPassword);
  const hasLowercase = /[a-z]/.test(newPassword);
  const hasNumber = /[0-9]/.test(newPassword);
  const hasSpecial = /[^A-Za-z0-9]/.test(newPassword);

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!fullNameInput.trim()) {
      setError('Full Name cannot be empty.');
      return;
    }

    setLoading(true);
    try {
      await updateProfile({
        full_name: fullNameInput.trim(),
        avatar_url: avatarUrlInput.trim() || null
      });
      setSuccessMsg('Profile updated successfully!');
      setTimeout(() => {
        setSuccessMsg('');
        setActiveSubTab('overview');
      }, 1500);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update profile. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!currentPassword) {
      setError('Please enter your current password.');
      return;
    }
    if (!hasMinLength || !hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
      setError('New password does not meet security complexity requirements.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New password and confirmation do not match.');
      return;
    }

    setLoading(true);
    try {
      await changePassword(currentPassword, newPassword, confirmPassword);
      setSuccessMsg('Your password has been changed successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => {
        setSuccessMsg('');
        setActiveSubTab('overview');
      }, 2000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to change password. Please verify current password.');
    } finally {
      setLoading(false);
    }
  };

  if (!user) {
    return (
      <div style={{ padding: '60px 20px', textAlign: 'center', color: '#94A3B8' }}>
        <p>No user session loaded. Please sign in to view your profile.</p>
      </div>
    );
  }

  const initialLetter = (user.full_name || user.username || 'U')[0].toUpperCase();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px', maxWidth: '1000px', margin: '0 auto', padding: '10px 20px 60px' }}>
      {/* Header Banner */}
      <div className="glass-panel" style={{
        padding: '28px',
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.8) 100%)',
        border: '1px solid var(--border-glow)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          {/* Avatar */}
          <div style={{ position: 'relative' }}>
            {user.avatar_url ? (
              <img
                src={user.avatar_url}
                alt="Profile Avatar"
                style={{
                  width: '74px',
                  height: '74px',
                  borderRadius: '50%',
                  objectFit: 'cover',
                  border: '2px solid #38BDF8',
                  boxShadow: '0 0 20px rgba(56, 189, 248, 0.4)'
                }}
              />
            ) : (
              <div style={{
                width: '74px',
                height: '74px',
                borderRadius: '50%',
                background: 'linear-gradient(135deg, #0284C7 0%, #38BDF8 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#FFFFFF',
                fontSize: '2rem',
                fontWeight: '800',
                boxShadow: '0 0 20px rgba(56, 189, 248, 0.4)'
              }}>
                {initialLetter}
              </div>
            )}
            <div style={{
              position: 'absolute',
              bottom: 0,
              right: 0,
              background: user.email_verified ? '#10B981' : '#F59E0B',
              borderRadius: '50%',
              width: '20px',
              height: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '2px solid #0F172A',
              color: '#FFF'
            }} title={user.email_verified ? 'Email Verified' : 'Unverified Email'}>
              {user.email_verified ? <Check size={12} /> : '!'}
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h1 style={{ fontSize: '1.4rem', fontWeight: '800', color: 'var(--text-main)', margin: 0 }}>
                {user.full_name || user.username}
              </h1>
              {isAdmin && (
                <span style={{
                  background: 'rgba(139, 92, 246, 0.25)',
                  color: '#C4B5FD',
                  border: '1px solid rgba(139, 92, 246, 0.5)',
                  fontSize: '0.7rem',
                  fontWeight: '800',
                  padding: '2px 8px',
                  borderRadius: '6px'
                }}>
                  ADMINISTRATOR
                </span>
              )}
            </div>
            <div style={{ fontSize: '0.84rem', color: 'var(--text-dim)', marginTop: '4px' }}>
              {user.email} • @{user.username}
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={() => setActiveSubTab(activeSubTab === 'edit' ? 'overview' : 'edit')}
            className="btn-secondary"
            style={{ fontSize: '0.82rem', padding: '8px 14px' }}
          >
            <Edit3 size={15} />
            {activeSubTab === 'edit' ? 'View Overview' : 'Edit Profile'}
          </button>

          <button
            onClick={logout}
            style={{
              padding: '8px 16px',
              fontSize: '0.82rem',
              fontWeight: '700',
              color: '#EF4444',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              borderRadius: '8px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <LogOut size={15} />
            Sign Out
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          color: '#EF4444',
          padding: '12px 16px',
          borderRadius: '10px',
          fontSize: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div style={{
          background: 'rgba(16, 185, 129, 0.15)',
          border: '1px solid rgba(16, 185, 129, 0.4)',
          color: '#34D399',
          padding: '12px 16px',
          borderRadius: '10px',
          fontSize: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <CheckCircle2 size={18} />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Sub Navigation */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
        <button
          onClick={() => { setActiveSubTab('overview'); setError(''); setSuccessMsg(''); }}
          style={{
            background: activeSubTab === 'overview' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: activeSubTab === 'overview' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: activeSubTab === 'overview' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '7px 14px',
            borderRadius: '8px',
            fontSize: '0.84rem',
            fontWeight: '600',
            cursor: 'pointer'
          }}
        >
          Account Overview
        </button>

        <button
          onClick={() => { setActiveSubTab('edit'); setError(''); setSuccessMsg(''); }}
          style={{
            background: activeSubTab === 'edit' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: activeSubTab === 'edit' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: activeSubTab === 'edit' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '7px 14px',
            borderRadius: '8px',
            fontSize: '0.84rem',
            fontWeight: '600',
            cursor: 'pointer'
          }}
        >
          Edit Profile
        </button>

        <button
          onClick={() => { setActiveSubTab('password'); setError(''); setSuccessMsg(''); }}
          style={{
            background: activeSubTab === 'password' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: activeSubTab === 'password' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: activeSubTab === 'password' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '7px 14px',
            borderRadius: '8px',
            fontSize: '0.84rem',
            fontWeight: '600',
            cursor: 'pointer'
          }}
        >
          Security & Password
        </button>
      </div>

      {/* ================= SUBTAB 1: OVERVIEW ================= */}
      {activeSubTab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
          {/* Card 1: Account Information */}
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <User size={18} color="var(--accent-blue)" />
              Account Details
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.84rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <span style={{ color: 'var(--text-dim)' }}>Full Name:</span>
                <strong style={{ color: 'var(--text-main)' }}>{user.full_name || 'Not provided'}</strong>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <span style={{ color: 'var(--text-dim)' }}>Email Address:</span>
                <strong style={{ color: 'var(--text-main)' }}>{user.email}</strong>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <span style={{ color: 'var(--text-dim)' }}>Authentication Method:</span>
                <span style={{
                  padding: '2px 8px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: '700',
                  background: 'rgba(56, 189, 248, 0.15)',
                  color: 'var(--accent-blue)',
                  border: '1px solid rgba(56, 189, 248, 0.3)'
                }}>
                  Email + Password (Bcrypt)
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <span style={{ color: 'var(--text-dim)' }}>Email Verification:</span>
                <span style={{
                  color: user.email_verified ? '#10B981' : '#F59E0B',
                  fontWeight: '700',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}>
                  {user.email_verified ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                  {user.email_verified ? 'Verified' : 'Pending Verification'}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <span style={{ color: 'var(--text-dim)' }}>Account Role:</span>
                <strong style={{ color: isAdmin ? '#C4B5FD' : 'var(--text-main)', textTransform: 'capitalize' }}>
                  {user.role}
                </strong>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <span style={{ color: 'var(--text-dim)' }}>Account Created:</span>
                <span style={{ color: 'var(--text-main)' }}>
                  {new Date(user.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-dim)' }}>Last Sign In:</span>
                <span style={{ color: 'var(--text-main)' }}>
                  {user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Current session'}
                </span>
              </div>
            </div>
          </div>

          {/* Card 2: Security & Quick Navigation */}
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield size={18} color="#10B981" />
              Cybersecurity Workspace
            </h3>

            <p style={{ fontSize: '0.84rem', color: 'var(--text-dim)' }}>
              Your account is configured with high-priority ML telemetry inspection. Scans, reports, and AI explanations are isolated to your profile.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '4px' }}>
              <button
                onClick={onNavigateScanner}
                className="btn-primary"
                style={{ width: '100%', justifyContent: 'center', padding: '10px', fontSize: '0.84rem' }}
              >
                Launch URL Scanner & XAI Engine
              </button>

              <button
                onClick={onNavigateDashboard}
                className="btn-secondary"
                style={{ width: '100%', justifyContent: 'center', padding: '10px', fontSize: '0.84rem' }}
              >
                View Cybersecurity Dashboard
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ================= SUBTAB 2: EDIT PROFILE ================= */}
      {activeSubTab === 'edit' && (
        <div className="glass-panel" style={{ padding: '28px', maxWidth: '600px' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-main)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Edit3 size={18} color="var(--accent-blue)" />
            Edit Profile Information
          </h3>

          <form onSubmit={handleUpdateProfile} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                Full Name *
              </label>
              <input
                type="text"
                value={fullNameInput}
                onChange={(e) => setFullNameInput(e.target.value)}
                placeholder="e.g. Suneel Kumar"
                style={{
                  width: '100%',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '9px 12px',
                  color: 'var(--text-main)',
                  fontSize: '0.88rem',
                  outline: 'none'
                }}
                required
              />
            </div>

            <div>
              <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                Profile Avatar URL (Optional)
              </label>
              <input
                type="url"
                value={avatarUrlInput}
                onChange={(e) => setAvatarUrlInput(e.target.value)}
                placeholder="https://example.com/avatar.jpg"
                style={{
                  width: '100%',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '9px 12px',
                  color: 'var(--text-main)',
                  fontSize: '0.88rem',
                  outline: 'none'
                }}
              />
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '4px', display: 'block' }}>
                Leave empty to use automatic monogram initials.
              </span>
            </div>

            <div style={{ display: 'flex', gap: '10px', marginTop: '8px' }}>
              <button
                type="submit"
                disabled={loading}
                className="btn-primary"
                style={{ padding: '10px 20px', fontSize: '0.84rem' }}
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save Changes
              </button>

              <button
                type="button"
                onClick={() => setActiveSubTab('overview')}
                className="btn-secondary"
                style={{ padding: '10px 16px', fontSize: '0.84rem' }}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ================= SUBTAB 3: SECURITY & PASSWORD ================= */}
      {activeSubTab === 'password' && (
        <div className="glass-panel" style={{ padding: '28px', maxWidth: '600px' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-main)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <KeyRound size={18} color="var(--accent-blue)" />
            Password & Security Settings
          </h3>

          <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                  Current Password *
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showCurrentPassword ? 'text' : 'password'}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Enter current password"
                    style={{
                      width: '100%',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '8px',
                      padding: '9px 38px 9px 12px',
                      color: 'var(--text-main)',
                      fontSize: '0.88rem',
                      outline: 'none'
                    }}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                    style={{
                      position: 'absolute',
                      right: '10px',
                      top: '10px',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-dim)',
                      cursor: 'pointer'
                    }}
                  >
                    {showCurrentPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                  New Password *
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showNewPassword ? 'text' : 'password'}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="At least 8 characters"
                    style={{
                      width: '100%',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '8px',
                      padding: '9px 38px 9px 12px',
                      color: 'var(--text-main)',
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
                      top: '10px',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-dim)',
                      cursor: 'pointer'
                    }}
                  >
                    {showNewPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>

                {newPassword && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px', fontSize: '0.68rem', color: '#94A3B8', marginTop: '6px' }}>
                    <span style={{ color: hasMinLength ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      {hasMinLength ? <Check size={12} /> : <X size={12} />} 8+ characters
                    </span>
                    <span style={{ color: hasUppercase ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      {hasUppercase ? <Check size={12} /> : <X size={12} />} Uppercase (A-Z)
                    </span>
                    <span style={{ color: hasNumber ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      {hasNumber ? <Check size={12} /> : <X size={12} />} Numeric digit
                    </span>
                    <span style={{ color: hasSpecial ? '#10B981' : '#64748B', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      {hasSpecial ? <Check size={12} /> : <X size={12} />} Special symbol
                    </span>
                  </div>
                )}
              </div>

              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
                  Confirm New Password *
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter new password"
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '8px',
                    padding: '9px 12px',
                    color: 'var(--text-main)',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                  required
                />
              </div>

              <div style={{ display: 'flex', gap: '10px', marginTop: '8px' }}>
                <button
                  type="submit"
                  disabled={loading}
                  className="btn-primary"
                  style={{ padding: '10px 20px', fontSize: '0.84rem' }}
                >
                  {loading ? <Loader2 size={16} className="animate-spin" /> : <Lock size={16} />}
                  Update Password
                </button>
              </div>
            </form>
        </div>
      )}
    </div>
  );
};

export default ProfilePage;
