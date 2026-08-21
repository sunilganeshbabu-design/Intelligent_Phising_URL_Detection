import React, { useState } from 'react';
import { 
  Mail, ShieldAlert, Search, Lock, Sparkles, 
  Server, Globe, Activity, ShieldCheck, XCircle
} from 'lucide-react';
import { scanEmailAddress } from '../services/api';

const PRESET_EMAILS = [
  {
    category: 'Phishing',
    label: '🚨 PayPal Impersonation (.xyz)',
    email: 'security@paypal-auth-alert.xyz',
    desc: 'Real verified phishing dataset brand spoofing on unverified domain'
  },
  {
    category: 'Phishing',
    label: '🚨 Apple ID Harvester (.top)',
    email: 'account-support@apple-id-notice.top',
    desc: 'Real credential harvest lure targeting Apple IDs'
  },
  {
    category: 'Phishing',
    label: '🚨 Chase Bank Pretext (Gmail)',
    email: 'chase-security-alerts@gmail.com',
    desc: 'Real corporate financial fraud pretext using free public webmail'
  },
  {
    category: 'Phishing',
    label: '🚨 Disposable Burner Mailbox',
    email: 'account-verify@dispostable.com',
    desc: 'Real anonymous throwaway inbox provider used in automated attacks'
  },
  {
    category: 'Phishing',
    label: '🚨 Streaming Fraud Alert (.buzz)',
    email: 'billing-update@netflix-verify-portal.buzz',
    desc: 'Real subscription fraud lure dataset sample'
  },
  {
    category: 'Legitimate',
    label: '🛡️ Google Security Official',
    email: 'security@google.com',
    desc: 'Real Google enterprise mail infrastructure with active SPF/DMARC'
  },
  {
    category: 'Legitimate',
    label: '🛡️ GitHub Notifications',
    email: 'news@github.com',
    desc: 'Real verified Microsoft GitHub mail gateway'
  },
  {
    category: 'Legitimate',
    label: '🛡️ Apple Support Official',
    email: 'support@apple.com',
    desc: 'Real authentic Apple corporate mail gateway'
  },
  {
    category: 'Legitimate',
    label: '🛡️ Chase Bank Official',
    email: 'alerts@chase.com',
    desc: 'Real verified JPMorgan Chase financial institution mail'
  },
  {
    category: 'Legitimate',
    label: '🛡️ PayPal Verified Service',
    email: 'service@paypal.com',
    desc: 'Real PayPal verified transactional mail gateway'
  }
];

export default function EmailScannerPage() {
  const [emailInput, setEmailInput] = useState(PRESET_EMAILS[0].email);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    const cleanEmail = emailInput.trim();
    if (!cleanEmail) {
      setError('Please enter a valid email address to scan.');
      return;
    }

    if (!cleanEmail.includes('@') || !cleanEmail.includes('.')) {
      setError('Please enter a complete email address (e.g. username@domain.com).');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await scanEmailAddress(cleanEmail);
      setScanResult(res);
    } catch (err) {
      console.error('Email scan error:', err);
      const msg = err.response?.data?.detail || 'Failed to analyze email address. Please ensure the backend server is running.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (preset) => {
    setEmailInput(preset.email);
    setError(null);
    // Automatically trigger scan for instantaneous experience
    setLoading(true);
    scanEmailAddress(preset.email)
      .then((res) => {
        setScanResult(res);
      })
      .catch((err) => {
        console.error('Preset scan error:', err);
        const msg = err.response?.data?.detail || 'Failed to analyze email address. Please ensure the backend server is running.';
        setError(msg);
      })
      .finally(() => setLoading(false));
  };

  const getVerdictStyle = (verdict, risk) => {
    if (risk === 'Critical' || verdict?.toLowerCase().includes('phishing') || verdict?.toLowerCase().includes('spoof')) {
      return {
        bg: 'rgba(239, 68, 68, 0.12)',
        border: 'rgba(239, 68, 68, 0.35)',
        text: '#EF4444',
        accentGlow: '0 0 30px rgba(239, 68, 68, 0.25)',
        badge: 'CRITICAL PHISHING RISK'
      };
    }
    if (risk === 'High' || verdict?.toLowerCase().includes('suspicious') || verdict?.toLowerCase().includes('disposable')) {
      return {
        bg: 'rgba(245, 158, 11, 0.12)',
        border: 'rgba(245, 158, 11, 0.35)',
        text: '#F59E0B',
        accentGlow: '0 0 30px rgba(245, 158, 11, 0.2)',
        badge: 'SUSPICIOUS SENDER'
      };
    }
    if (risk === 'Low Risk') {
      return {
        bg: 'rgba(56, 189, 248, 0.12)',
        border: 'rgba(56, 189, 248, 0.35)',
        text: '#38BDF8',
        accentGlow: '0 0 30px rgba(56, 189, 248, 0.2)',
        badge: 'LOW RISK / REVIEW'
      };
    }
    return {
      bg: 'rgba(16, 185, 129, 0.12)',
      border: 'rgba(16, 185, 129, 0.35)',
      text: '#10B981',
      accentGlow: '0 0 30px rgba(16, 185, 129, 0.25)',
      badge: 'VERIFIED LEGITIMATE'
    };
  };

  const verdictStyle = scanResult ? getVerdictStyle(scanResult.overall_verdict, scanResult.risk_level) : null;

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '24px', padding: '0 16px' }}>
      
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.75), rgba(15, 23, 42, 0.95))',
        padding: '28px 32px',
        borderRadius: '16px',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ maxWidth: '780px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(56, 189, 248, 0.12)',
            color: '#38BDF8',
            padding: '4px 12px',
            borderRadius: '20px',
            fontSize: '0.78rem',
            fontWeight: '700',
            letterSpacing: '0.04em',
            marginBottom: '10px'
          }}>
            <Mail size={14} /> REAL-TIME EMAIL ADDRESS & SENDER VERIFICATION
          </div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: '800', margin: '0 0 8px', color: '#F8FAFC' }}>
            Email Phishing & Sender Legitimacy Inspector
          </h1>
          <p style={{ margin: 0, fontSize: '0.88rem', color: '#94A3B8', lineHeight: '1.5' }}>
            Enter any email address to inspect sender legitimacy in real-time. The system checks for brand spoofing, lookalike typosquatting, disposable burner inboxes, live DNS MX mail infrastructure, SPF/DMARC policies, and Explainable AI (XAI) feature contributions.
          </p>
        </div>
      </div>

      {/* Main Single Email Search Bar */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <label style={{ fontSize: '0.86rem', color: '#CBD5E1', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Mail size={16} color="#38BDF8" /> Enter Real-Time Email Address to Scan
          </label>
          
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: 1, minWidth: '280px' }}>
              <input
                type="text"
                className="input-field"
                placeholder="e.g. security-alert@paypal-update.top or user@company.com"
                value={emailInput}
                onChange={(e) => setEmailInput(e.target.value)}
                style={{
                  fontSize: '0.96rem',
                  padding: '14px 18px',
                  fontFamily: 'monospace',
                  width: '100%',
                  background: 'rgba(15, 23, 42, 0.85)',
                  borderColor: error ? '#EF4444' : 'rgba(56, 189, 248, 0.3)'
                }}
              />
              {emailInput && (
                <button
                  type="button"
                  onClick={() => { setEmailInput(''); setScanResult(null); }}
                  style={{
                    position: 'absolute',
                    right: '12px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'transparent',
                    border: 'none',
                    color: '#64748B',
                    cursor: 'pointer',
                    fontSize: '1.1rem',
                    padding: '4px'
                  }}
                  title="Clear input"
                >
                  ✕
                </button>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{
                padding: '14px 28px',
                fontSize: '0.92rem',
                fontWeight: '700',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                minWidth: '170px',
                justifyContent: 'center'
              }}
            >
              {loading ? (
                <>
                  <span className="spinner" /> Analyzing...
                </>
              ) : (
                <>
                  <Search size={18} /> Check Email
                </>
              )}
            </button>
          </div>

          {error && (
            <div style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              color: '#EF4444',
              padding: '10px 14px',
              borderRadius: '8px',
              fontSize: '0.84rem',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              <XCircle size={16} /> {error}
            </div>
          )}
        </form>

        {/* Preset Sample Quick Buttons */}
        <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div style={{ fontSize: '0.78rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '10px' }}>
            ⚡ 1-Click Real-Time Test Samples:
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {PRESET_EMAILS.map((p, idx) => (
              <button
                key={idx}
                onClick={() => loadPreset(p)}
                style={{
                  background: p.category === 'Phishing' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                  border: `1px solid ${p.category === 'Phishing' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                  color: p.category === 'Phishing' ? '#FCA5A5' : '#86EFAC',
                  padding: '6px 12px',
                  borderRadius: '8px',
                  fontSize: '0.76rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
                title={p.desc}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Real-Time Scan Results Display */}
      {scanResult && verdictStyle && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Main Verdict Card */}
          <div
            className="glass-panel"
            style={{
              background: verdictStyle.bg,
              borderColor: verdictStyle.border,
              boxShadow: verdictStyle.accentGlow,
              padding: '24px 28px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                {scanResult.risk_level === 'Critical' || scanResult.risk_level === 'High' ? (
                  <div style={{ background: 'rgba(239, 68, 68, 0.2)', padding: '12px', borderRadius: '14px', border: '1px solid rgba(239, 68, 68, 0.4)' }}>
                    <ShieldAlert size={40} color="#EF4444" />
                  </div>
                ) : (
                  <div style={{ background: 'rgba(16, 185, 129, 0.2)', padding: '12px', borderRadius: '14px', border: '1px solid rgba(16, 185, 129, 0.4)' }}>
                    <ShieldCheck size={40} color="#10B981" />
                  </div>
                )}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{
                      background: verdictStyle.text,
                      color: '#070B14',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '0.72rem',
                      fontWeight: '800',
                      letterSpacing: '0.04em'
                    }}>
                      {verdictStyle.badge}
                    </span>
                    <span style={{ fontSize: '0.8rem', color: '#94A3B8' }}>
                      Analyzed Target: <strong style={{ color: '#F8FAFC', fontFamily: 'monospace' }}>{scanResult.email}</strong>
                    </span>
                  </div>
                  <h2 style={{ fontSize: '1.6rem', fontWeight: '800', color: verdictStyle.text, margin: '4px 0 2px' }}>
                    {scanResult.overall_verdict}
                  </h2>
                  <div style={{ fontSize: '0.82rem', color: '#CBD5E1' }}>
                    Risk Level: <strong style={{ color: verdictStyle.text }}>{scanResult.risk_level}</strong> • Confidence Rating: <strong>{scanResult.confidence_score}%</strong>
                  </div>
                </div>
              </div>

              {/* Phishing Probability Meter */}
              <div style={{
                background: 'rgba(15, 23, 42, 0.75)',
                padding: '16px 20px',
                borderRadius: '12px',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                minWidth: '220px',
                textAlign: 'right'
              }}>
                <div style={{ fontSize: '0.74rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: '700' }}>
                  Phishing Probability
                </div>
                <div style={{ fontSize: '2rem', fontWeight: '900', color: verdictStyle.text, lineHeight: '1.2' }}>
                  {scanResult.phishing_probability}%
                </div>
                <div style={{
                  width: '100%',
                  height: '6px',
                  background: 'rgba(255, 255, 255, 0.1)',
                  borderRadius: '3px',
                  overflow: 'hidden',
                  marginTop: '6px'
                }}>
                  <div style={{
                    width: `${scanResult.phishing_probability}%`,
                    height: '100%',
                    background: scanResult.phishing_probability > 50 ? 'linear-gradient(90deg, #F59E0B, #EF4444)' : 'linear-gradient(90deg, #10B981, #38BDF8)',
                    borderRadius: '3px',
                    transition: 'width 0.5s ease'
                  }} />
                </div>
              </div>
            </div>
          </div>

          {/* 4-Card Identity & Technical Architecture Breakdown */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
            
            {/* Card 1: User Identity / Local-Part */}
            <div className="glass-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Mail size={14} color="#38BDF8" /> Mailbox User Local-Part
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: '700', color: '#F8FAFC', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {scanResult.username}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94A3B8', display: 'flex', alignItems: 'center', gap: '6px', marginTop: 'auto' }}>
                Syntax: <span style={{ color: scanResult.is_valid_format ? '#10B981' : '#EF4444', fontWeight: '700' }}>
                  {scanResult.is_valid_format ? '✓ RFC-5322 Compliant' : '⚠ Invalid Syntax'}
                </span>
              </div>
            </div>

            {/* Card 2: Destination Domain & TLD Abuse */}
            <div className="glass-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Globe size={14} color="#8B5CF6" /> Domain & Abuse Registry
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: '700', color: '#F8FAFC', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {scanResult.domain}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94A3B8', display: 'flex', alignItems: 'center', gap: '6px', marginTop: 'auto' }}>
                TLD Risk: <span style={{ color: scanResult.tld_risk_score >= 0.7 ? '#EF4444' : '#10B981', fontWeight: '700' }}>
                  {Math.round(scanResult.tld_risk_score * 100)}% Abuse Rating
                </span>
                • Entropy: <strong style={{ color: '#F8FAFC' }}>{scanResult.entropy_score}</strong>
              </div>
            </div>

            {/* Card 3: Mail Routing & MX Provider */}
            <div className="glass-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Server size={14} color="#10B981" /> Live MX Mail Infrastructure
              </div>
              <div style={{ fontSize: '0.95rem', fontWeight: '700', color: scanResult.dns_info.has_mx ? '#10B981' : '#EF4444' }}>
                {scanResult.dns_info.has_mx ? scanResult.dns_info.mail_provider : 'No Active MX Records'}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: 'auto' }}>
                Host: <span style={{ fontFamily: 'monospace', color: '#CBD5E1' }}>{scanResult.dns_info.primary_mx || scanResult.dns_info.dns_status}</span>
              </div>
            </div>

            {/* Card 4: Sender Authentication (SPF / DMARC) */}
            <div className="glass-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Lock size={14} color="#F59E0B" /> Anti-Spoofing Authentication
              </div>
              <div style={{ fontSize: '0.9rem', fontWeight: '700', color: scanResult.is_brand_spoofed ? '#EF4444' : '#F8FAFC' }}>
                {scanResult.is_brand_spoofed ? `⚠️ Spoofs ${scanResult.spoofed_brand}` : (scanResult.is_disposable ? '🚫 Disposable Inbox' : (scanResult.is_free_webmail ? 'Public Webmail' : 'Verified Domain'))}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8', display: 'flex', gap: '10px', marginTop: 'auto' }}>
                <span>DMARC: <strong style={{ color: scanResult.dns_info.has_dmarc ? '#10B981' : '#F59E0B' }}>{scanResult.dns_info.has_dmarc ? 'Active' : 'Unpublished'}</strong></span>
                <span>SPF: <strong style={{ color: scanResult.dns_info.has_spf ? '#10B981' : '#94A3B8' }}>{scanResult.dns_info.has_spf ? 'Found' : 'None'}</strong></span>
              </div>
            </div>

          </div>

          {/* Explainable AI (XAI) Feature Contributions & Threat Indicators */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
            
            {/* Left: XAI Feature Contributions */}
            <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Sparkles size={18} color="#38BDF8" /> Explainable AI (XAI) Feature Impact
                </h3>
                <p style={{ margin: '4px 0 0', fontSize: '0.78rem', color: '#94A3B8' }}>
                  Mathematical attribution showing why this email address was classified as {scanResult.risk_level === 'Safe' ? 'Legitimate' : 'Phishing / Suspicious'}:
                </p>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {scanResult.feature_contributions.map((feat, idx) => {
                  const isPhish = feat.direction === 'phishing';
                  const percentImpact = Math.min(100, Math.round(Math.abs(feat.contribution) * 100));
                  return (
                    <div
                      key={idx}
                      style={{
                        background: 'rgba(15, 23, 42, 0.6)',
                        padding: '12px 14px',
                        borderRadius: '10px',
                        border: `1px solid ${isPhish ? 'rgba(239, 68, 68, 0.25)' : 'rgba(16, 185, 129, 0.25)'}`
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <span style={{ fontSize: '0.84rem', fontWeight: '700', color: '#F8FAFC' }}>
                          {feat.display_name}
                        </span>
                        <span style={{
                          background: isPhish ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                          color: isPhish ? '#EF4444' : '#10B981',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '0.72rem',
                          fontWeight: '800'
                        }}>
                          {isPhish ? `+${percentImpact}% Phishing Risk` : `-${percentImpact}% Legitimate`}
                        </span>
                      </div>

                      {/* Visual Contribution Bar */}
                      <div style={{ width: '100%', height: '4px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden', marginBottom: '8px' }}>
                        <div style={{
                          width: `${percentImpact}%`,
                          height: '100%',
                          background: isPhish ? '#EF4444' : '#10B981',
                          borderRadius: '2px'
                        }} />
                      </div>

                      <div style={{ fontSize: '0.75rem', color: '#94A3B8', lineHeight: '1.4' }}>
                        {feat.description}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Right: Detected Threat Indicators & Actionable Guidance */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              
              {/* Threat Indicators List */}
              <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Activity size={18} color="#F59E0B" /> Detected Security Indicators
                </h3>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {scanResult.threat_indicators.map((ind, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: ind.severity === 'Critical' ? 'rgba(239, 68, 68, 0.1)' : (ind.severity === 'High' ? 'rgba(245, 158, 11, 0.1)' : (ind.severity === 'Safe' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(56, 189, 248, 0.1)')),
                        border: `1px solid ${ind.severity === 'Critical' ? 'rgba(239, 68, 68, 0.3)' : (ind.severity === 'High' ? 'rgba(245, 158, 11, 0.3)' : (ind.severity === 'Safe' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(56, 189, 248, 0.3)'))}`,
                        padding: '12px',
                        borderRadius: '8px'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontSize: '0.82rem', fontWeight: '700', color: '#F8FAFC' }}>
                          {ind.category}
                        </span>
                        <span style={{
                          fontSize: '0.68rem',
                          fontWeight: '800',
                          padding: '1px 6px',
                          borderRadius: '4px',
                          textTransform: 'uppercase',
                          background: ind.severity === 'Critical' ? '#EF4444' : (ind.severity === 'High' ? '#F59E0B' : (ind.severity === 'Safe' ? '#10B981' : '#38BDF8')),
                          color: '#070B14'
                        }}>
                          {ind.severity}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#CBD5E1', lineHeight: '1.4' }}>
                        {ind.detail}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Actionable Recommendations */}
              <div className="glass-panel" style={{ padding: '20px', background: 'rgba(56, 189, 248, 0.06)', borderColor: 'rgba(56, 189, 248, 0.25)', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ fontSize: '0.84rem', fontWeight: '700', color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <ShieldCheck size={16} /> Recommended Defensive Actions:
                </div>
                <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.78rem', color: '#CBD5E1', display: 'flex', flexDirection: 'column', gap: '6px', lineHeight: '1.4' }}>
                  {scanResult.actionable_advice.map((adv, idx) => (
                    <li key={idx}>{adv}</li>
                  ))}
                </ul>
              </div>

            </div>

          </div>

        </div>
      )}

    </div>
  );
}
