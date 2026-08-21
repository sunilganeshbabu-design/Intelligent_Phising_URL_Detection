import React, { useState, useRef, useEffect } from 'react';
import { 
  Shield, LogIn, LogOut, User, Layers, Database,
  Sun, Moon, Monitor, ChevronDown, Check
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

const Navbar = ({ onOpenBulkModal, currentTab, setCurrentTab }) => {
  const { user, logout, isAuthenticated, isAdmin } = useAuth();
  const { appearance, setAppearance } = useTheme();
  const [isThemeMenuOpen, setIsThemeMenuOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const themeMenuRef = useRef(null);
  const userMenuRef = useRef(null);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (themeMenuRef.current && !themeMenuRef.current.contains(event.target)) {
        setIsThemeMenuOpen(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
        setIsUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = () => {
    setIsUserMenuOpen(false);
    logout();
    setCurrentTab('scanner');
  };

  const themeOptions = [
    { id: 'light', label: 'Light Mode', icon: Sun, desc: 'Clean, high-contrast light theme' },
    { id: 'dark', label: 'Dark Mode', icon: Moon, desc: 'Deep cyber dark mode' },
    { id: 'system', label: 'System Appearance', icon: Monitor, desc: 'Syncs automatically with OS' },
  ];

  const currentThemeObj = themeOptions.find(t => t.id === appearance) || themeOptions[1];
  const CurrentIcon = currentThemeObj.icon;

  return (
    <header style={{
      background: 'var(--bg-header)',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid var(--border-subtle)',
      position: 'sticky',
      top: 0,
      zIndex: 500,
      padding: '0 16px',
      height: '68px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexWrap: 'nowrap',
      gap: '12px'
    }}>
      {/* Brand Logo */}
      <div
        onClick={() => setCurrentTab('landing')}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          cursor: 'pointer',
          flexShrink: 0
        }}
      >
        <div style={{
          background: 'linear-gradient(135deg, #0284C7 0%, #38BDF8 100%)',
          padding: '8px',
          borderRadius: '12px',
          boxShadow: '0 0 15px rgba(56, 189, 248, 0.4)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0
        }}>
          <Shield size={22} color="#FFFFFF" />
        </div>
        <div style={{ flexShrink: 0 }}>
          <div style={{ fontSize: '0.94rem', fontWeight: '800', letterSpacing: '0.01em', color: 'var(--text-main)', whiteSpace: 'nowrap' }}>
            INTELLIGENT PHISHING URL DETECTION
          </div>
          <div style={{ fontSize: '0.64rem', color: 'var(--text-dim)', letterSpacing: '0.04em', fontWeight: '600', whiteSpace: 'nowrap' }}>
            EXPLAINABLE AI (XAI) CYBERSECURITY SYSTEM
          </div>
        </div>
      </div>

      {/* Center Navigation Links */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: '3px', flexWrap: 'nowrap', flexShrink: 0 }}>
        <button
          onClick={() => setCurrentTab('scanner')}
          style={{
            background: currentTab === 'scanner' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: currentTab === 'scanner' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: currentTab === 'scanner' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '6px 11px',
            borderRadius: '8px',
            fontSize: '0.82rem',
            fontWeight: '600',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.15s ease'
          }}
        >
          URL Scanner
        </button>

        <button
          onClick={() => setCurrentTab('email_scanner')}
          style={{
            background: currentTab === 'email_scanner' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: currentTab === 'email_scanner' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: currentTab === 'email_scanner' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '6px 11px',
            borderRadius: '8px',
            fontSize: '0.82rem',
            fontWeight: '600',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.15s ease'
          }}
        >
          Email Scanner
        </button>

        <button
          onClick={() => setCurrentTab('qr_scanner')}
          style={{
            background: currentTab === 'qr_scanner' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: currentTab === 'qr_scanner' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: currentTab === 'qr_scanner' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '6px 11px',
            borderRadius: '8px',
            fontSize: '0.82rem',
            fontWeight: '600',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.15s ease'
          }}
        >
          QR Quishing
        </button>

        <button
          onClick={() => setCurrentTab('threat_lookup')}
          style={{
            background: currentTab === 'threat_lookup' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: currentTab === 'threat_lookup' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: currentTab === 'threat_lookup' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '6px 11px',
            borderRadius: '8px',
            fontSize: '0.82rem',
            fontWeight: '600',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.15s ease'
          }}
        >
          Threat IOC
        </button>

        <button
          onClick={() => setCurrentTab('dashboard')}
          style={{
            background: currentTab === 'dashboard' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: currentTab === 'dashboard' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: currentTab === 'dashboard' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '6px 11px',
            borderRadius: '8px',
            fontSize: '0.82rem',
            fontWeight: '600',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.15s ease'
          }}
        >
          Dashboard
        </button>

        <button
          onClick={() => setCurrentTab('history')}
          style={{
            background: currentTab === 'history' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: currentTab === 'history' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: currentTab === 'history' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '6px 11px',
            borderRadius: '8px',
            fontSize: '0.82rem',
            fontWeight: '600',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.15s ease'
          }}
        >
          History
        </button>

        <button
          onClick={() => setCurrentTab('reports')}
          style={{
            background: currentTab === 'reports' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: currentTab === 'reports' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
            color: currentTab === 'reports' ? 'var(--accent-blue)' : 'var(--text-muted)',
            padding: '6px 11px',
            borderRadius: '8px',
            fontSize: '0.82rem',
            fontWeight: '600',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.15s ease'
          }}
        >
          Reports
        </button>

        {isAdmin && (
          <button
            onClick={() => setCurrentTab('admin')}
            style={{
              background: currentTab === 'admin' ? 'rgba(139, 92, 246, 0.2)' : 'transparent',
              border: currentTab === 'admin' ? '1px solid rgba(139, 92, 246, 0.4)' : '1px solid transparent',
              color: currentTab === 'admin' ? '#A78BFA' : 'var(--text-muted)',
              padding: '6px 11px',
              borderRadius: '8px',
              fontSize: '0.82rem',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '5px',
              whiteSpace: 'nowrap',
              transition: 'all 0.15s ease'
            }}
          >
            <Database size={13} color="#A78BFA" />
            Admin
          </button>
        )}
      </nav>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0, whiteSpace: 'nowrap' }}>
        {/* Appearance Dropdown Menu */}
        <div style={{ position: 'relative' }} ref={themeMenuRef}>
          <button
            onClick={() => setIsThemeMenuOpen(!isThemeMenuOpen)}
            className="btn-secondary"
            style={{
              padding: '7px 12px',
              fontSize: '0.82rem',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: isThemeMenuOpen ? 'var(--bg-card-hover)' : 'var(--bg-card)',
              borderColor: isThemeMenuOpen ? 'var(--border-active)' : 'var(--border-subtle)'
            }}
            title="Change Appearance"
          >
            <CurrentIcon size={15} color="var(--accent-blue)" />
            <span style={{ fontWeight: '600', color: 'var(--text-main)' }}>Appearance</span>
            <ChevronDown size={14} style={{ transform: isThemeMenuOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s ease' }} />
          </button>

          {/* Dropdown Box */}
          {isThemeMenuOpen && (
            <div
              className="glass-panel"
              style={{
                position: 'absolute',
                top: 'calc(100% + 8px)',
                right: 0,
                width: '240px',
                padding: '8px',
                borderRadius: '12px',
                boxShadow: '0 15px 35px rgba(0, 0, 0, 0.4)',
                border: '1px solid var(--border-glow)',
                zIndex: 600,
                display: 'flex',
                flexDirection: 'column',
                gap: '4px'
              }}
            >
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontWeight: '700', padding: '6px 10px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Select Appearance
              </div>

              {themeOptions.map((opt) => {
                const IconComponent = opt.icon;
                const isSelected = appearance === opt.id;
                return (
                  <button
                    key={opt.id}
                    onClick={() => {
                      setAppearance(opt.id);
                      setIsThemeMenuOpen(false);
                    }}
                    style={{
                      background: isSelected ? 'rgba(56, 189, 248, 0.12)' : 'transparent',
                      border: isSelected ? '1px solid rgba(56, 189, 248, 0.3)' : '1px solid transparent',
                      padding: '8px 12px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      width: '100%',
                      textAlign: 'left',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div style={{
                        color: isSelected ? 'var(--accent-blue)' : 'var(--text-muted)',
                        display: 'flex',
                        alignItems: 'center'
                      }}>
                        <IconComponent size={16} />
                      </div>
                      <div>
                        <div style={{ fontSize: '0.84rem', fontWeight: isSelected ? '700' : '500', color: isSelected ? 'var(--accent-blue)' : 'var(--text-main)' }}>
                          {opt.label}
                        </div>
                        <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>
                          {opt.desc}
                        </div>
                      </div>
                    </div>

                    {isSelected && <Check size={15} color="var(--accent-blue)" />}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <button
          onClick={onOpenBulkModal}
          className="btn-secondary"
          style={{ padding: '7px 12px', fontSize: '0.82rem' }}
        >
          <Layers size={15} color="var(--accent-blue)" />
          Bulk Scanner
        </button>

        {isAuthenticated ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {/* User Profile Chip with Dropdown */}
            <div style={{ position: 'relative' }} ref={userMenuRef}>
              <button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: isUserMenuOpen ? 'var(--bg-card-hover)' : 'var(--bg-card)',
                  padding: '6px 12px',
                  borderRadius: '8px',
                  border: `1px solid ${isUserMenuOpen ? 'var(--accent-blue)' : 'var(--border-subtle)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
                title="Account Settings & Profile"
              >
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg, #0284C7 0%, #38BDF8 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#FFFFFF',
                  fontSize: '0.75rem',
                  fontWeight: '800',
                  overflow: 'hidden'
                }}>
                  {user?.avatar_url ? (
                    <img src={user.avatar_url} alt="avatar" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                  ) : (
                    (user?.full_name || user?.username || 'U')[0].toUpperCase()
                  )}
                </div>
                <span style={{ fontSize: '0.84rem', fontWeight: '600', color: 'var(--text-main)' }}>
                  {user?.full_name || user?.username || 'User'}
                </span>
                {isAdmin && (
                  <span style={{
                    fontSize: '0.66rem',
                    background: 'rgba(139, 92, 246, 0.25)',
                    color: '#C4B5FD',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontWeight: '700'
                  }}>
                    ADMIN
                  </span>
                )}
                <ChevronDown size={13} style={{ transform: isUserMenuOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s ease', color: 'var(--text-muted)' }} />
              </button>

              {/* Account Dropdown Menu */}
              {isUserMenuOpen && (
                <div
                  className="glass-panel"
                  style={{
                    position: 'absolute',
                    top: 'calc(100% + 8px)',
                    right: 0,
                    width: '260px',
                    padding: '12px',
                    borderRadius: '12px',
                    boxShadow: '0 15px 35px rgba(0, 0, 0, 0.4)',
                    border: '1px solid var(--border-glow)',
                    zIndex: 600,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px'
                  }}
                >
                  <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
                    <div style={{ fontSize: '0.88rem', fontWeight: '700', color: 'var(--text-main)' }}>
                      {user?.full_name || user?.username || 'User'}
                    </div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginTop: '2px', wordBreak: 'break-all' }}>
                      {user?.email || 'No email attached'}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '6px' }}>
                      <span style={{
                        fontSize: '0.68rem',
                        color: user?.email_verified ? '#10B981' : '#F59E0B',
                        fontWeight: '700',
                        background: user?.email_verified ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                        padding: '2px 6px',
                        borderRadius: '4px'
                      }}>
                        {user?.email_verified ? 'Verified Email' : 'Pending Verification'}
                      </span>
                    </div>
                  </div>

                  <button
                    onClick={() => { setIsUserMenuOpen(false); setCurrentTab('profile'); }}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: 'var(--text-main)',
                      padding: '8px 10px',
                      borderRadius: '6px',
                      fontSize: '0.82rem',
                      fontWeight: '600',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      cursor: 'pointer',
                      textAlign: 'left'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(56, 189, 248, 0.15)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <User size={15} color="var(--accent-blue)" /> Profile & Security Settings
                  </button>

                  {isAdmin && (
                    <button
                      onClick={() => { setIsUserMenuOpen(false); setCurrentTab('admin'); }}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--text-main)',
                        padding: '8px 10px',
                        borderRadius: '6px',
                        fontSize: '0.82rem',
                        fontWeight: '600',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        cursor: 'pointer',
                        textAlign: 'left'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(139, 92, 246, 0.15)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                    >
                      <Database size={15} color="#A78BFA" /> Admin Management Console
                    </button>
                  )}

                  <button
                    onClick={handleLogout}
                    style={{
                      background: 'rgba(239, 68, 68, 0.12)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      color: '#EF4444',
                      padding: '8px 12px',
                      borderRadius: '8px',
                      fontSize: '0.82rem',
                      fontWeight: '700',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '8px',
                      cursor: 'pointer',
                      marginTop: '4px',
                      transition: 'all 0.15s ease'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.22)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.12)'}
                  >
                    <LogOut size={15} /> Sign Out of Account
                  </button>
                </div>
              )}
            </div>

            {/* Prominent Direct Sign Out Button */}
            <button
              onClick={handleLogout}
              className="btn-secondary"
              style={{
                padding: '7px 14px',
                color: '#EF4444',
                borderColor: 'rgba(239, 68, 68, 0.35)',
                background: 'rgba(239, 68, 68, 0.08)',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '0.82rem',
                fontWeight: '700',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)';
                e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.6)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(239, 68, 68, 0.08)';
                e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.35)';
              }}
              title="Sign Out of Session"
            >
              <LogOut size={15} />
              <span>Sign Out</span>
            </button>
          </div>
        ) : (
          <button
            onClick={() => setCurrentTab('login')}
            className="btn-primary"
            style={{ padding: '7px 16px', fontSize: '0.84rem' }}
          >
            <LogIn size={15} />
            Sign In / Register
          </button>
        )}
      </div>
    </header>
  );
};

export default Navbar;
