import React, { useState } from 'react';
import { Shield, Sparkles, Zap, Brain, Layers, CheckCircle2, ClipboardPaste, Globe, Radio } from 'lucide-react';

const LandingPage = ({ setCurrentTab, onQuickScan }) => {
  const [quickUrl, setQuickUrl] = useState('');

  const handleStartScan = (e) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    onQuickScan(quickUrl.trim());
    setCurrentTab('scanner');
  };

  const handlePasteAndScan = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text && text.trim()) {
        onQuickScan(text.trim());
        setCurrentTab('scanner');
      }
    } catch (err) {
      console.warn('Clipboard read error:', err);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '60px', paddingBottom: '60px' }}>
      {/* Hero Section */}
      <section style={{
        textAlign: 'center',
        padding: '60px 20px 40px',
        maxWidth: '900px',
        margin: '0 auto',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '20px'
      }}>
        {/* Glow Tag */}
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 16px',
          borderRadius: '9999px',
          background: 'rgba(56, 189, 248, 0.12)',
          border: '1px solid rgba(56, 189, 248, 0.3)',
          color: '#38BDF8',
          fontSize: '0.82rem',
          fontWeight: '700',
          letterSpacing: '0.06em'
        }}>
          <Sparkles size={15} />
          REAL-TIME EXPLAINABLE AI CYBER DEFENSE
        </div>

        {/* Main Heading */}
        <h1 style={{
          fontSize: 'clamp(2.4rem, 5vw, 3.8rem)',
          fontWeight: '900',
          lineHeight: '1.15',
          letterSpacing: '-0.03em',
          background: 'linear-gradient(135deg, #FFFFFF 30%, #94A3B8 70%, #38BDF8 100%)',
          WebkitBackgroundClip: 'text',
          backgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          color: 'transparent'
        }}>
          Intelligent Phishing URL Detection Using Explainable AI
        </h1>

        {/* Subtitle */}
        <p style={{
          fontSize: '1.1rem',
          color: '#94A3B8',
          maxWidth: '700px',
          lineHeight: '1.6'
        }}>
          Defend against sophisticated credential harvesting and brand spoofing.
          Paste <strong>any real-time link</strong> to extract 20+ URL attributes, perform live DNS/SSL handshake inspection, and view <strong>SHAP</strong> & <strong>LIME</strong> explanations.
        </p>

        {/* Quick URL Input Bar */}
        <form
          onSubmit={handleStartScan}
          style={{
            width: '100%',
            maxWidth: '680px',
            marginTop: '10px',
            position: 'relative',
            display: 'flex',
            alignItems: 'center'
          }}
        >
          <input
            type="text"
            placeholder="Paste ANY link to scan (e.g. https://... or domain.com)..."
            value={quickUrl}
            onChange={(e) => setQuickUrl(e.target.value)}
            style={{
              width: '100%',
              background: 'rgba(15, 23, 42, 0.85)',
              backdropFilter: 'blur(12px)',
              border: '1px solid rgba(56, 189, 248, 0.35)',
              borderRadius: '12px',
              padding: '16px 140px 16px 20px',
              color: '#F8FAFC',
              fontSize: '0.98rem',
              outline: 'none',
              boxShadow: '0 0 25px rgba(56, 189, 248, 0.15)'
            }}
          />
          <button
            type="submit"
            className="btn-primary"
            style={{
              position: 'absolute',
              right: '8px',
              padding: '10px 20px',
              borderRadius: '8px'
            }}
          >
            <Zap size={16} />
            Scan URL
          </button>
        </form>

        {/* Real-Time Clipboard Action & Badges */}
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', alignItems: 'center', gap: '12px', marginTop: '6px' }}>
          <button
            type="button"
            onClick={handlePasteAndScan}
            style={{
              background: 'rgba(30, 41, 59, 0.7)',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              color: '#38BDF8',
              padding: '6px 16px',
              borderRadius: '9999px',
              fontSize: '0.82rem',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.15s ease'
            }}
          >
            <ClipboardPaste size={14} />
            Paste Copied Link & Scan
          </button>

          <span style={{ fontSize: '0.8rem', color: '#64748B' }}>•</span>

          <span style={{ fontSize: '0.8rem', color: '#10B981', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Radio size={12} className="animate-pulse" />
            Live Network Telemetry Active
          </span>
        </div>

        {/* 1-Click Test Samples Quick Bar */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '8px',
          marginTop: '10px',
          width: '100%',
          maxWidth: '780px'
        }}>
          <div style={{ fontSize: '0.76rem', color: '#94A3B8', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            ⚡ 1-Click Test Samples (Click to Analyze):
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: '8px' }}>
            <button
              type="button"
              onClick={() => { onQuickScan('http://login-verify-paypal-account-security-update-portal.monster/update-password/form.php?email=victim@target.com'); setCurrentTab('scanner'); }}
              style={{
                background: 'rgba(30, 41, 59, 0.75)',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                color: '#CBD5E1',
                padding: '5px 12px',
                borderRadius: '8px',
                fontSize: '0.75rem',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Sample: paypal-portal.monster
            </button>
            <button
              type="button"
              onClick={() => { onQuickScan('https://www.google.com/search?q=machine+learning'); setCurrentTab('scanner'); }}
              style={{
                background: 'rgba(30, 41, 59, 0.75)',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                color: '#CBD5E1',
                padding: '5px 12px',
                borderRadius: '8px',
                fontSize: '0.75rem',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Sample: google.com/search
            </button>
            <button
              type="button"
              onClick={() => { onQuickScan('http://www.ch4s3-b4nk-support.xyz/update-password/form.php?email=victim@target.com'); setCurrentTab('scanner'); }}
              style={{
                background: 'rgba(30, 41, 59, 0.75)',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                color: '#CBD5E1',
                padding: '5px 12px',
                borderRadius: '8px',
                fontSize: '0.75rem',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Sample: ch4s3-b4nk.xyz
            </button>
            <button
              type="button"
              onClick={() => { onQuickScan('https://github.com/torvalds/linux'); setCurrentTab('scanner'); }}
              style={{
                background: 'rgba(30, 41, 59, 0.75)',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                color: '#CBD5E1',
                padding: '5px 12px',
                borderRadius: '8px',
                fontSize: '0.75rem',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Sample: github.com/torvalds
            </button>
            <button
              type="button"
              onClick={() => { onQuickScan('http://192.168.1.100/login/bankofamerica-auth.php?token=928103'); setCurrentTab('scanner'); }}
              style={{
                background: 'rgba(30, 41, 59, 0.75)',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                color: '#CBD5E1',
                padding: '5px 12px',
                borderRadius: '8px',
                fontSize: '0.75rem',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Sample: 192.168.1.100/login
            </button>
          </div>
        </div>
      </section>

      {/* Feature Pillar Cards */}
      <section style={{
        maxWidth: '1100px',
        margin: '0 auto',
        padding: '0 20px',
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap: '24px'
      }}>
        {/* Pillar 1 */}
        <div className="glass-panel glass-panel-hover" style={{ padding: '28px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{
            background: 'rgba(56, 189, 248, 0.12)',
            width: '48px',
            height: '48px',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Brain size={24} color="#38BDF8" />
          </div>
          <h3 style={{ fontSize: '1.2rem', fontWeight: '700', color: '#F8FAFC' }}>
            Explainable AI (XAI)
          </h3>
          <p style={{ fontSize: '0.88rem', color: '#94A3B8', lineHeight: '1.6' }}>
            Unlike black-box models, the platform integrates <strong>SHAP TreeExplainer</strong> and <strong>LIME</strong> to reveal the exact mathematical impact of each URL token, domain attribute, and character entropy.
          </p>
        </div>

        {/* Pillar 2 */}
        <div className="glass-panel glass-panel-hover" style={{ padding: '28px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{
            background: 'rgba(139, 92, 246, 0.12)',
            width: '48px',
            height: '48px',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Layers size={24} color="#8B5CF6" />
          </div>
          <h3 style={{ fontSize: '1.2rem', fontWeight: '700', color: '#F8FAFC' }}>
            20+ Feature Extraction Engine
          </h3>
          <p style={{ fontSize: '0.88rem', color: '#94A3B8', lineHeight: '1.6' }}>
            Deep inspection of lexical length, subdomain nesting, Shannon entropy, RFC-1738 tricks, top-level domain abuse ratings, homograph spoofing, and credential harvesting keywords.
          </p>
        </div>

        {/* Pillar 3 */}
        <div className="glass-panel glass-panel-hover" style={{ padding: '28px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{
            background: 'rgba(16, 185, 129, 0.12)',
            width: '48px',
            height: '48px',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Shield size={24} color="#10B981" />
          </div>
          <h3 style={{ fontSize: '1.2rem', fontWeight: '700', color: '#F8FAFC' }}>
            Threat Intel & PDF Audit Reports
          </h3>
          <p style={{ fontSize: '0.88rem', color: '#94A3B8', lineHeight: '1.6' }}>
            Real-time reputation checks against known bad domain feeds, SSL analysis, bulk multi-URL processing, and executive-ready security audit PDF downloads.
          </p>
        </div>
      </section>

      {/* Enterprise Security Architecture Highlight Banner */}
      <section style={{
        maxWidth: '1100px',
        margin: '0 auto',
        padding: '0 20px',
        width: '100%'
      }}>
        <div className="glass-panel" style={{
          padding: '36px',
          background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.6) 100%)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          alignItems: 'center',
          gap: '30px'
        }}>
          <div>
            <span style={{ fontSize: '0.78rem', color: '#38BDF8', fontWeight: '700', letterSpacing: '0.08em' }}>
              ENTERPRISE DEFENSE PIPELINE & ARCHITECTURE
            </span>
            <h2 style={{ fontSize: '1.6rem', fontWeight: '800', color: '#F8FAFC', marginTop: '6px' }}>
              Full-Stack Cyber Defense Pipeline
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.88rem', color: '#CBD5E1' }}>
                <CheckCircle2 size={18} color="#10B981" />
                <span><strong>Frontend:</strong> React, Vite, Chart.js, Glassmorphic UI</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.88rem', color: '#CBD5E1' }}>
                <CheckCircle2 size={18} color="#10B981" />
                <span><strong>Backend:</strong> FastAPI, SQLite, SQLAlchemy, JWT Auth</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.88rem', color: '#CBD5E1' }}>
                <CheckCircle2 size={18} color="#10B981" />
                <span><strong>ML & XAI:</strong> XGBoost model (Extreme Gradient Boosting), SHAP, LIME</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.88rem', color: '#CBD5E1' }}>
                <CheckCircle2 size={18} color="#10B981" />
                <span><strong>Reporting:</strong> ReportLab PDF Generator & CSV Audit Export</span>
              </div>
            </div>
          </div>

          <div style={{
            background: 'rgba(7, 11, 20, 0.7)',
            borderRadius: '12px',
            padding: '20px',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            fontFamily: 'monospace',
            fontSize: '0.82rem',
            color: '#94A3B8',
            lineHeight: '1.7'
          }}>
            <div style={{ color: '#38BDF8', fontWeight: 'bold', marginBottom: '8px' }}>// Data Flow Lifecycle</div>
            <div>[User Input] ➔ Raw URL String</div>
            <div>➔ Feature Extraction Engine (21 Features)</div>
            <div>➔ XGBoost Classifier (XGBoost model Engine)</div>
            <div>➔ SHAP TreeExplainer & LIME Perturbation</div>
            <div>➔ Threat Intelligence & Heuristic Fusion</div>
            <div>➔ Risk Meter Gauge + Audit PDF Report</div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default LandingPage;
