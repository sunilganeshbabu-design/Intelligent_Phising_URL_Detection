import React, { useState, useEffect } from 'react';
import { 
  Search, Zap, RefreshCw, Download, Bot, Shield, 
  Layers, FileText, CheckCircle2, Sparkles, Copy, Check,
  ClipboardPaste, X, Globe, Radio, AlertTriangle, ShieldAlert,
  ShieldCheck, ArrowRight, Bookmark, Lock, Cpu
} from 'lucide-react';
import { predictSingleUrl, getPdfDownloadUrl, downloadScanPdf } from '../services/api';
import RiskMeter from '../components/RiskMeter';
import ShapWaterfallChart from '../components/ShapWaterfallChart';
import LimeBreakdownChart from '../components/LimeBreakdownChart';
import FeatureTable from '../components/FeatureTable';
import ThreatIntelCard from '../components/ThreatIntelCard';
import XaiWhatIfSimulator from '../components/XaiWhatIfSimulator';
import TenModulesPipelineInspector from '../components/TenModulesPipelineInspector';
import confetti from 'canvas-confetti';

const PRESET_URLS = [
  {
    category: 'Phishing',
    label: '🚨 PayPal Credential Harvester (.xyz)',
    url: 'http://paypal-security-update.xyz/signin.php',
    desc: 'Real verified PhishTank/APWG dataset credential spoof'
  },
  {
    category: 'Phishing',
    label: '🚨 Apple ID Clone (.com)',
    url: 'http://apple-id-recovery-support.com/auth/challenge',
    desc: 'Real verified OpenPhish dataset active credential phishing link'
  },
  {
    category: 'Phishing',
    label: '🚨 Chase Banking Trojan (.top)',
    url: 'http://chase-verify-identity-login.top/login.html',
    desc: 'Real financial Trojan & identity theft attack dataset sample'
  },
  {
    category: 'Phishing',
    label: '🚨 Crypto Wallet Drainer (.buzz)',
    url: 'http://binance-security-kyc.buzz/wallet/verify',
    desc: 'Real cryptocurrency wallet phishing attack dataset sample'
  },
  {
    category: 'Phishing',
    label: '🚨 Streaming Fraud Alert (.buzz)',
    url: 'http://netflix-billing-resolve-account.buzz/verify?ref=39104',
    desc: 'Real subscription fraud lure dataset sample'
  },
  {
    category: 'Phishing',
    label: '🚨 RFC-1738 @ Spoof Attack',
    url: 'http://google.com@chase-security.top/login',
    desc: 'Real destination userinfo URL spoofing trick'
  },
  {
    category: 'Legitimate',
    label: '🛡️ Google Search Official',
    url: 'https://www.google.com/search?q=machine+learning',
    desc: 'Real authoritative Google infrastructure'
  },
  {
    category: 'Legitimate',
    label: '🛡️ GitHub Public Repo',
    url: 'https://github.com/torvalds/linux',
    desc: 'Real Microsoft GitHub repository with TLS certificate'
  },
  {
    category: 'Legitimate',
    label: '🛡️ OpenAI ChatGPT Official',
    url: 'https://openai.com/index/chatgpt',
    desc: 'Real OpenAI web portal with verified certificate'
  },
  {
    category: 'Legitimate',
    label: '🛡️ Amazon Product Portal',
    url: 'https://www.amazon.com/dp/B08N5WRWNW',
    desc: 'Real Amazon web services e-commerce page'
  },
  {
    category: 'Legitimate',
    label: '🛡️ Wikipedia Article',
    url: 'https://en.wikipedia.org/wiki/Phishing',
    desc: 'Real Wikimedia Foundation verified article'
  },
  {
    category: 'Legitimate',
    label: '🛡️ Python Official Docs',
    url: 'https://docs.python.org/3/library/urllib.parse.html',
    desc: 'Real Python Software Foundation documentation'
  }
];

const ScannerPage = ({ initialUrl = '', initialTab = 'shap', onSetScanContext, onOpenChatbotWithContext }) => {
  const [urlInput, setUrlInput] = useState(initialUrl);
  const [modelName, setModelName] = useState('XGBoost');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState(initialTab || 'shap');
  const [copied, setCopied] = useState(false);
  const [showModulesPreview, setShowModulesPreview] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfNotification, setPdfNotification] = useState(null);

  useEffect(() => {
    if (initialTab) {
      setActiveTab(initialTab);
    }
  }, [initialTab]);

  useEffect(() => {
    if (initialUrl && initialUrl !== urlInput) {
      setUrlInput(initialUrl);
      handleAnalyze(initialUrl);
    }
  }, [initialUrl]);

  const handleAnalyze = async (urlToScan) => {
    const target = (urlToScan !== undefined ? urlToScan : urlInput).trim();
    if (!target) {
      setError('Please enter or paste a valid URL to analyze.');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const data = await predictSingleUrl(target, modelName, true);
      setResult(data);
      if (onSetScanContext) {
        onSetScanContext(data);
      }

      if (data.prediction === 'Legitimate' && data.phishing_probability < 20) {
        confetti({
          particleCount: 50,
          spread: 60,
          origin: { y: 0.8 },
          colors: ['#10B981', '#34D399', '#38BDF8']
        });
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Analysis failed. Please ensure the backend server is reachable.');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (preset) => {
    setUrlInput(preset.url);
    setError('');
    handleAnalyze(preset.url);
  };

  const handlePasteAndScan = async () => {
    try {
      const clipboardText = await navigator.clipboard.readText();
      if (clipboardText && clipboardText.trim()) {
        const clean = clipboardText.trim();
        setUrlInput(clean);
        handleAnalyze(clean);
      } else {
        setError('Clipboard is empty. Please copy a URL first.');
      }
    } catch (err) {
      console.warn('Clipboard read failed:', err);
      setError('Unable to read clipboard automatically. Please paste using Ctrl+V or right-click.');
    }
  };

  const handleClear = () => {
    setUrlInput('');
    setResult(null);
    setError('');
  };

  const handleCopy = () => {
    if (!result) return;
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPdf = async () => {
    if (!result || !result.id) return;
    setPdfLoading(true);
    setPdfNotification(null);
    try {
      const filename = await downloadScanPdf(result.id);
      setPdfNotification({
        type: 'success',
        message: `PDF Audit Report downloaded successfully: ${filename}`
      });
      setTimeout(() => {
        setPdfNotification(null);
      }, 5000);
    } catch (err) {
      console.error('PDF download error:', err);
      setPdfNotification({
        type: 'error',
        message: err.response?.data?.detail || 'Failed to download PDF audit report. Please try again.'
      });
      setTimeout(() => {
        setPdfNotification(null);
      }, 6000);
    } finally {
      setPdfLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '30px', maxWidth: '1200px', margin: '0 auto', padding: '10px 20px 60px' }}>
      {/* Scanner Input Header */}
      <div className="glass-panel" style={{ padding: '30px', position: 'relative', overflow: 'hidden' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          <div>
            <div style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              background: 'rgba(16, 185, 129, 0.12)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              color: '#34D399',
              padding: '4px 10px',
              borderRadius: '20px',
              fontSize: '0.74rem',
              fontWeight: '700',
              letterSpacing: '0.04em',
              marginBottom: '8px'
            }}>
              <Radio size={12} className="animate-pulse" color="#10B981" />
              LIVE REAL-TIME TELEMETRY ENGINE
            </div>
            <h1 style={{ fontSize: '1.6rem', fontWeight: '800', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Zap size={24} color="#38BDF8" />
              Intelligent Real-Time URL Scanner
            </h1>
            <p style={{ fontSize: '0.88rem', color: '#94A3B8', marginTop: '4px', lineHeight: '1.5' }}>
              Type or paste <strong>any custom link</strong> to analyze, or test with any of the <strong>sample URL links</strong> below. The AI detection system will inspect the URL features and live telemetry to determine whether it is <strong>Safe</strong> or <strong>Phishing</strong>.
            </p>
          </div>

          {/* Search Bar & Options */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleAnalyze();
            }}
            style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}
          >
            <div style={{ flex: 1, minWidth: '280px', position: 'relative' }}>
              <Search size={18} color="#64748B" style={{ position: 'absolute', left: '14px', top: '15px' }} />
              <input
                type="text"
                placeholder="Type or paste ANY custom URL here (e.g. https://google.com, http://example-site.com)..."
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 20, 0.8)',
                  border: '1px solid rgba(56, 189, 248, 0.35)',
                  borderRadius: '10px',
                  padding: '13px 40px 13px 42px',
                  color: '#F8FAFC',
                  fontSize: '0.92rem',
                  outline: 'none',
                  boxShadow: '0 0 15px rgba(56, 189, 248, 0.08)'
                }}
              />
              {urlInput && (
                <button
                  type="button"
                  onClick={handleClear}
                  style={{
                    position: 'absolute',
                    right: '12px',
                    top: '14px',
                    background: 'transparent',
                    border: 'none',
                    color: '#64748B',
                    cursor: 'pointer',
                    padding: 0
                  }}
                  title="Clear input"
                >
                  <X size={18} />
                </button>
              )}
            </div>

            {/* Quick Paste & Scan Button */}
            <button
              type="button"
              onClick={handlePasteAndScan}
              className="btn-secondary"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '0 16px',
                fontSize: '0.85rem',
                fontWeight: '600',
                background: 'rgba(30, 41, 59, 0.8)'
              }}
              title="Paste URL directly from clipboard and analyze immediately"
            >
              <ClipboardPaste size={16} color="#38BDF8" />
              Paste & Scan
            </button>

            {/* Model Indicator (Single Model - No Dropdown Arrow) */}
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                background: 'rgba(30, 41, 59, 0.85)',
                color: '#38BDF8',
                border: '1px solid rgba(56, 189, 248, 0.35)',
                borderRadius: '10px',
                padding: '0 14px',
                fontSize: '0.85rem',
                fontWeight: '700',
                userSelect: 'none',
                whiteSpace: 'nowrap',
                height: '42px',
                boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.05)'
              }}
              title="Active Machine Learning Model"
            >
              <Cpu size={15} color="#38BDF8" />
              <span>XGBoost model</span>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ minWidth: '150px', justifyContent: 'center' }}
            >
              {loading ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  Analyzing Live...
                </>
              ) : (
                <>
                  <Zap size={16} />
                  Analyze URL
                </>
              )}
            </button>
          </form>

          {error && (
            <div style={{ color: '#EF4444', fontSize: '0.85rem', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <AlertTriangle size={15} /> {error}
            </div>
          )}

          {/* Preset Sample Quick Buttons (Email Scanner Format) */}
          <div style={{
            marginTop: '8px',
            paddingTop: '16px',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ fontSize: '0.78rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Sparkles size={14} color="#38BDF8" /> ⚡ 1-Click Real-Time Test Samples:
              </div>
              <span style={{ fontSize: '0.72rem', color: '#64748B' }}>
                Select a preset sample or enter your own custom URL to analyze
              </span>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {PRESET_URLS.map((p, idx) => (
                <button
                  key={idx}
                  type="button"
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
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = p.category === 'Phishing' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = p.category === 'Phishing' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)';
                  }}
                  title={`${p.desc}\nURL: ${p.url}`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          {/* Real-time Dynamic Info Bar */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center', marginTop: '4px', fontSize: '0.78rem', color: '#94A3B8' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#CBD5E1' }}>
              <Globe size={14} color="#38BDF8" />
              <strong>Real-Time Live Dynamic Analysis:</strong> Probes live network socket & DNS for any link
            </span>
            <span style={{ color: '#64748B' }}>•</span>
            <span>Live TLS/SSL Handshake</span>
            <span style={{ color: '#64748B' }}>•</span>
            <span>SHAP & LIME Feature Attribution</span>
          </div>
        </div>
      </div>

      {/* Analysis Results View */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Main Verdict Card */}
          <div
            className="glass-panel"
            style={{
              padding: '24px',
              border: `1px solid ${result.prediction === 'Phishing' ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
              background: result.prediction === 'Phishing' ? 'rgba(239, 68, 68, 0.03)' : 'rgba(16, 185, 129, 0.03)'
            }}
          >
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px', alignItems: 'center' }}>
              {/* Left Details */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Scanned URL Target
                  </div>
                  <div style={{
                    fontSize: '1rem',
                    fontWeight: '700',
                    color: '#F8FAFC',
                    fontFamily: 'monospace',
                    wordBreak: 'break-all',
                    marginTop: '4px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}>
                    <span>{result.url}</span>
                    <button
                      onClick={handleCopy}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: '#64748B',
                        cursor: 'pointer',
                        padding: '4px'
                      }}
                      title="Copy URL"
                    >
                      {copied ? <Check size={16} color="#10B981" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
                  <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>DETECTION ENGINE</div>
                    <div style={{ fontSize: '0.88rem', fontWeight: '700', color: '#38BDF8' }}>
                      {result.model_name === 'XGBoost' || result.model_name === 'XGBooster' ? 'XGBoost model (Extreme Gradient Boosting)' : result.model_name}
                    </div>
                  </div>

                  <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>DOMAIN HOST</div>
                    <div style={{ fontSize: '0.88rem', fontWeight: '700', color: '#F8FAFC' }}>{result.domain}</div>
                  </div>

                  <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>DETECTION TIME (REAL-TIME)</div>
                    <div style={{ fontSize: '0.88rem', fontWeight: '700', color: '#10B981', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10B981', display: 'inline-block', boxShadow: '0 0 8px #10B981' }} />
                      <span>{new Date(result.created_at || Date.now()).toLocaleTimeString()}</span>
                      {result.execution_time_ms ? (
                        <span style={{ fontSize: '0.74rem', color: '#38BDF8', background: 'rgba(56, 189, 248, 0.15)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'monospace' }}>
                          ⚡ {result.execution_time_ms} ms
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.74rem', color: '#38BDF8', background: 'rgba(56, 189, 248, 0.15)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'monospace' }}>
                          ⚡ Real-Time
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Action Buttons */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px' }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
                    {result.id && (
                      <button
                        type="button"
                        onClick={handleDownloadPdf}
                        disabled={pdfLoading}
                        className="btn-primary"
                        style={{
                          fontSize: '0.82rem',
                          padding: '8px 16px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          cursor: pdfLoading ? 'wait' : 'pointer',
                          opacity: pdfLoading ? 0.8 : 1
                        }}
                      >
                        {pdfLoading ? (
                          <>
                            <RefreshCw size={15} className="animate-spin" />
                            <span>Generating PDF Audit Report...</span>
                          </>
                        ) : (
                          <>
                            <Download size={15} />
                            <span>Download PDF Audit Report</span>
                          </>
                        )}
                      </button>
                    )}

                    <button
                      onClick={() => onOpenChatbotWithContext && onOpenChatbotWithContext(result, true)}
                      className="btn-secondary"
                      style={{ fontSize: '0.82rem', padding: '8px 16px' }}
                    >
                      <Bot size={15} color="#38BDF8" />
                      Ask AI Why Flagged
                    </button>
                  </div>

                  {pdfNotification && (
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '8px 12px',
                      borderRadius: '8px',
                      fontSize: '0.78rem',
                      fontWeight: '600',
                      background: pdfNotification.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                      border: `1px solid ${pdfNotification.type === 'success' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
                      color: pdfNotification.type === 'success' ? '#34D399' : '#F87171',
                      animation: 'fadeIn 0.2s ease-in-out'
                    }}>
                      {pdfNotification.type === 'success' ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                      <span>{pdfNotification.message}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Right Gauge */}
              <div style={{ display: 'flex', justifyContent: 'center' }}>
                <RiskMeter
                  probability={result.phishing_probability}
                  riskLevel={result.risk_level}
                  confidence={result.confidence_score}
                  prediction={result.prediction}
                />
              </div>
            </div>
          </div>

          {/* Deep Inspection Section Tabs */}
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Tab Navigation */}
            <div style={{
              display: 'flex',
              gap: '6px',
              borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
              paddingBottom: '12px',
              overflowX: 'auto'
            }}>
              <button
                onClick={() => setActiveTab('modules')}
                style={{
                  background: activeTab === 'modules' ? 'rgba(59, 130, 246, 0.2)' : 'transparent',
                  border: activeTab === 'modules' ? '1px solid #3B82F6' : '1px solid transparent',
                  color: activeTab === 'modules' ? '#60A5FA' : '#94A3B8',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '0.86rem',
                  fontWeight: '700',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  boxShadow: activeTab === 'modules' ? '0 0 12px rgba(59, 130, 246, 0.3)' : 'none'
                }}
              >
                <Layers size={16} color={activeTab === 'modules' ? '#60A5FA' : '#94A3B8'} />
                10-Module Pipeline
              </button>

              <button
                onClick={() => setActiveTab('shap')}
                style={{
                  background: activeTab === 'shap' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  border: activeTab === 'shap' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
                  color: activeTab === 'shap' ? '#38BDF8' : '#94A3B8',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '0.86rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <Sparkles size={16} />
                SHAP Explanation
              </button>

              <button
                onClick={() => setActiveTab('lime')}
                style={{
                  background: activeTab === 'lime' ? 'rgba(139, 92, 246, 0.15)' : 'transparent',
                  border: activeTab === 'lime' ? '1px solid rgba(139, 92, 246, 0.4)' : '1px solid transparent',
                  color: activeTab === 'lime' ? '#A78BFA' : '#94A3B8',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '0.86rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <Layers size={16} />
                LIME Local Rules
              </button>

              <button
                onClick={() => setActiveTab('features')}
                style={{
                  background: activeTab === 'features' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  border: activeTab === 'features' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
                  color: activeTab === 'features' ? '#38BDF8' : '#94A3B8',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '0.86rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <FileText size={16} />
                20+ Extracted Features
              </button>

              <button
                onClick={() => setActiveTab('threat_intel')}
                style={{
                  background: activeTab === 'threat_intel' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  border: activeTab === 'threat_intel' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid transparent',
                  color: activeTab === 'threat_intel' ? '#38BDF8' : '#94A3B8',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '0.86rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <Shield size={16} />
                Threat Intel & SSL
              </button>

              <button
                onClick={() => setActiveTab('advice')}
                style={{
                  background: activeTab === 'advice' ? 'rgba(16, 185, 129, 0.15)' : 'transparent',
                  border: activeTab === 'advice' ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid transparent',
                  color: activeTab === 'advice' ? '#34D399' : '#94A3B8',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '0.86rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <CheckCircle2 size={16} />
                AI Security Advice
              </button>

              <button
                onClick={() => setActiveTab('whatif')}
                style={{
                  background: activeTab === 'whatif' ? 'rgba(245, 158, 11, 0.15)' : 'transparent',
                  border: activeTab === 'whatif' ? '1px solid rgba(245, 158, 11, 0.4)' : '1px solid transparent',
                  color: activeTab === 'whatif' ? '#FBBF24' : '#94A3B8',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontSize: '0.86rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <Sparkles size={16} color="#F59E0B" />
                XAI "What-If" Simulator
              </button>
            </div>

            {/* Tab Contents */}
            <div>
              {activeTab === 'modules' && (
                <TenModulesPipelineInspector
                  scanResult={result}
                  currentModel={modelName || 'XGBoost'}
                  onReAnalyze={(url) => {
                    setUrlInput(url);
                    handleAnalyze(url);
                  }}
                />
              )}
              {activeTab === 'shap' && <ShapWaterfallChart shapExplanation={result.shap_explanation} />}
              {activeTab === 'lime' && <LimeBreakdownChart limeExplanation={result.lime_explanation} />}
              {activeTab === 'features' && <FeatureTable features={result.features} />}
              {activeTab === 'threat_intel' && <ThreatIntelCard threatIntel={result.threat_intel} />}
              {activeTab === 'whatif' && <XaiWhatIfSimulator initialFeatures={result?.features} currentModel={modelName || 'XGBoost'} />}
              {activeTab === 'advice' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                  {/* Header Summary Banner */}
                  <div style={{
                    background: result.prediction === 'Phishing' || result.risk_level === 'High' || result.risk_level === 'Critical'
                      ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(15, 23, 42, 0.8))'
                      : 'linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(15, 23, 42, 0.8))',
                    border: `1px solid ${result.prediction === 'Phishing' || result.risk_level === 'High' || result.risk_level === 'Critical' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                    borderRadius: '12px',
                    padding: '20px 24px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                      <div style={{
                        background: result.prediction === 'Phishing' || result.risk_level === 'High' || result.risk_level === 'Critical' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                        padding: '10px',
                        borderRadius: '10px'
                      }}>
                        {result.prediction === 'Phishing' || result.risk_level === 'High' || result.risk_level === 'Critical' ? (
                          <ShieldAlert size={26} color="#EF4444" />
                        ) : (
                          <ShieldCheck size={26} color="#10B981" />
                        )}
                      </div>
                      <div>
                        <h3 style={{ fontSize: '1.15rem', fontWeight: '800', color: '#F8FAFC', margin: 0 }}>
                          {result.prediction === 'Phishing' || result.risk_level === 'High' || result.risk_level === 'Critical'
                            ? 'Critical Incident Defense Playbook'
                            : 'Safe & Verified Destination Advisory'}
                        </h3>
                        <p style={{ fontSize: '0.82rem', color: '#94A3B8', margin: '3px 0 0 0' }}>
                          Actionable AI-synthesized mitigation steps based on live forensic indicators for {result.domain || result.url}
                        </p>
                      </div>
                    </div>

                    <div style={{
                      padding: '6px 14px',
                      borderRadius: '20px',
                      background: result.prediction === 'Phishing' || result.risk_level === 'High' || result.risk_level === 'Critical' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                      color: result.prediction === 'Phishing' || result.risk_level === 'High' || result.risk_level === 'Critical' ? '#F87171' : '#34D399',
                      fontSize: '0.8rem',
                      fontWeight: '700'
                    }}>
                      Risk Tier: {result.risk_level || 'Safe'} ({result.phishing_probability || 0}%)
                    </div>
                  </div>

                  {/* AI Forensic Insights */}
                  {result.ai_security_insights && result.ai_security_insights.length > 0 && (
                    <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '18px', borderRadius: '12px', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
                      <h4 style={{ fontSize: '0.88rem', fontWeight: '700', color: '#38BDF8', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Sparkles size={16} />
                        Forensic Telemetry Insights
                      </h4>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {result.ai_security_insights.map((item, idx) => {
                          const text = typeof item === 'string' ? item : (item?.text || item?.title || item?.action || JSON.stringify(item));
                          return (
                            <div key={idx} style={{ fontSize: '0.84rem', color: '#CBD5E1', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                              <span style={{ color: '#38BDF8', fontWeight: 'bold' }}>➔</span>
                              <span style={{ lineHeight: '1.45' }}>{text}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Actionable Recommendations Playbook */}
                  <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '18px', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <h4 style={{ fontSize: '0.88rem', fontWeight: '700', color: '#10B981', margin: '0 0 14px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <ShieldCheck size={16} />
                      Actionable Remediation Procedures
                    </h4>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {(result.ai_recommendations && result.ai_recommendations.length > 0 ? result.ai_recommendations : [
                        result.prediction === 'Phishing' ? 'Do NOT enter credentials or passwords on this web destination.' : 'URL appears safe for standard web browsing.'
                      ]).map((item, idx) => {
                        if (typeof item === 'object' && item !== null) {
                          const priorityColor = item.priority === 'CRITICAL' ? '#EF4444' : item.priority === 'HIGH' ? '#F97316' : item.priority === 'MEDIUM' ? '#F59E0B' : '#10B981';
                          const priorityBg = item.priority === 'CRITICAL' ? 'rgba(239, 68, 68, 0.15)' : item.priority === 'HIGH' ? 'rgba(249, 115, 22, 0.15)' : item.priority === 'MEDIUM' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)';

                          return (
                            <div key={idx} style={{
                              background: 'rgba(30, 41, 59, 0.6)',
                              border: `1px solid rgba(255, 255, 255, 0.08)`,
                              borderLeft: `4px solid ${priorityColor}`,
                              borderRadius: '8px',
                              padding: '14px 16px',
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '6px'
                            }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '6px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <span style={{
                                    fontSize: '0.68rem',
                                    fontWeight: '800',
                                    color: priorityColor,
                                    background: priorityBg,
                                    border: `1px solid ${priorityColor}40`,
                                    padding: '2px 8px',
                                    borderRadius: '4px',
                                    textTransform: 'uppercase'
                                  }}>
                                    {item.priority || 'ACTION'}
                                  </span>
                                  {item.category && (
                                    <span style={{ fontSize: '0.72rem', color: '#94A3B8' }}>
                                      {item.category}
                                    </span>
                                  )}
                                </div>
                                {item.icon === 'ShieldAlert' && <ShieldAlert size={16} color="#EF4444" />}
                                {item.icon === 'Lock' && <Lock size={16} color="#F97316" />}
                                {item.icon === 'CheckCircle2' && <CheckCircle2 size={16} color="#10B981" />}
                              </div>

                              {item.title && (
                                <div style={{ fontSize: '0.88rem', fontWeight: '700', color: '#F1F5F9' }}>
                                  {item.title}
                                </div>
                              )}

                              <div style={{ fontSize: '0.84rem', color: '#CBD5E1', lineHeight: '1.45' }}>
                                {item.action || item.details || JSON.stringify(item)}
                              </div>

                              {item.details && item.title && (
                                <div style={{ fontSize: '0.76rem', color: '#94A3B8', marginTop: '2px', borderTop: '1px solid rgba(255, 255, 255, 0.04)', paddingTop: '6px' }}>
                                  💡 {item.details}
                                </div>
                              )}
                            </div>
                          );
                        }

                        // Plain string item
                        return (
                          <div key={idx} style={{
                            background: 'rgba(30, 41, 59, 0.5)',
                            border: '1px solid rgba(255, 255, 255, 0.06)',
                            borderRadius: '8px',
                            padding: '12px 14px',
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: '10px',
                            fontSize: '0.84rem',
                            color: '#CBD5E1'
                          }}>
                            <CheckCircle2 size={16} color="#10B981" style={{ flexShrink: 0, marginTop: '2px' }} />
                            <span style={{ lineHeight: '1.45' }}>{item}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 10-Module Framework Overview Card when no scan is active */}
      {!result && (
        <div className="glass-panel" style={{ padding: '24px', position: 'relative', overflow: 'hidden' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ background: 'rgba(59, 130, 246, 0.15)', padding: '8px', borderRadius: '10px', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
                <Layers size={20} color="#60A5FA" />
              </div>
              <div>
                <h2 style={{ fontSize: '1.15rem', fontWeight: '800', color: '#F8FAFC', margin: 0 }}>
                  Integrated 10-Module Architectural Pipeline
                </h2>
                <div style={{ fontSize: '0.78rem', color: '#94A3B8' }}>
                  Every scan is evaluated across 10 sequential machine learning, XAI, and database modules
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setShowModulesPreview(!showModulesPreview)}
              className="btn-secondary"
              style={{ fontSize: '0.8rem', padding: '6px 14px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Zap size={14} color="#38BDF8" />
              {showModulesPreview ? 'Hide Framework Details' : 'Explore 10 Core Modules'}
            </button>
          </div>

          {showModulesPreview && (
            <div style={{ marginTop: '16px' }}>
              <TenModulesPipelineInspector
                scanResult={{
                  url: urlInput || 'http://paypal-security-update.account-verify.xyz/signin.php?token=928103',
                  domain: 'paypal-security-update.account-verify.xyz',
                  prediction: 'Phishing',
                  phishing_probability: 85.0,
                  confidence_score: 96.5,
                  risk_level: 'Critical',
                  features: {
                    url_length: 76,
                    domain_length: 42,
                    subdomain_count: 3,
                    entropy: 4.85,
                    tld_risk_score: 0.8,
                    detected_tld: '.xyz',
                    suspicious_keywords: 2,
                    ip_address: false,
                    https_status: false
                  },
                  shap_explanation: {
                    base_value: 0.4995,
                    summary_text: 'High-risk TLD (.xyz) and multiple subdomains pushed prediction towards Phishing.',
                    contributions: [
                      { feature_name: 'Subdomain Count', value: 0.22 },
                      { feature_name: 'TLD Risk Rating', value: 0.18 },
                      { feature_name: 'Shannon Entropy', value: 0.15 }
                    ]
                  },
                  ai_recommendations: [
                    'Do not submit login credentials or sensitive data on this unverified host.',
                    'Verify the authentic domain via official bookmark.',
                    'Report to security operations team.'
                  ]
                }}
                currentModel={modelName}
                onReAnalyze={(url) => {
                  setUrlInput(url);
                  handleAnalyze(url);
                }}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ScannerPage;
