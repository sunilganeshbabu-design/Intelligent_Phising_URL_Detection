import React, { useState, useRef } from 'react';
import jsQR from 'jsqr';
import { 
  QrCode, Upload, Zap, ShieldAlert, ShieldCheck, 
  Globe, Lock, Sparkles, RefreshCw, AlertTriangle, ArrowRight, Link as LinkIcon
} from 'lucide-react';
import { predictSingleUrl } from '../services/api';
import RiskMeter from '../components/RiskMeter';
import ShapWaterfallChart from '../components/ShapWaterfallChart';

const SAMPLE_QUISHING_QRS = [
  {
    category: 'Phishing',
    title: '🚨 PayPal Credential Spoof QR (.xyz)',
    url: 'http://paypal-security-update.xyz/signin.php',
    desc: 'Real verified PhishTank/APWG dataset credential spoofing campaign QR'
  },
  {
    category: 'Phishing',
    title: '🚨 Apple ID Harvester QR (.com)',
    url: 'http://apple-id-recovery-support.com/auth/challenge',
    desc: 'Real OpenPhish dataset credential harvest campaign QR'
  },
  {
    category: 'Phishing',
    title: '🚨 Banking Trojan Lure QR (.top)',
    url: 'http://chase-verify-identity-login.top/login.html',
    desc: 'Real financial malware and credential spoofing dataset QR'
  },
  {
    category: 'Phishing',
    title: '🚨 Crypto Wallet Drainer QR (.buzz)',
    url: 'http://binance-security-kyc.buzz/wallet/verify',
    desc: 'Real crypto drainer and social engineering campaign QR'
  },
  {
    category: 'Safe',
    title: '🛡️ Verified GitHub Repo QR',
    url: 'https://github.com/torvalds/linux',
    desc: 'Real authentic developer code repository'
  },
  {
    category: 'Safe',
    title: '🛡️ Verified Google Search QR',
    url: 'https://www.google.com/search?q=cybersecurity+best+practices',
    desc: 'Real search engine resource on authenticated Google infrastructure'
  },
  {
    category: 'Safe',
    title: '🛡️ Verified OpenAI ChatGPT QR',
    url: 'https://openai.com/index/chatgpt',
    desc: 'Real authentic artificial intelligence platform QR'
  }
];

export default function QrScannerPage() {
  const [activeMode, setActiveMode] = useState('upload'); // 'upload' or 'url'
  const [customUrlInput, setCustomUrlInput] = useState('');
  const [imagePreview, setImagePreview] = useState(null);
  const [decodedUrl, setDecodedUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const decodeImageAndScan = (imgElement) => {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = imgElement.naturalWidth || imgElement.width || 300;
      canvas.height = imgElement.naturalHeight || imgElement.height || 300;
      ctx.drawImage(imgElement, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'dontInvert',
      });

      if (code && code.data) {
        setDecodedUrl(code.data);
        runScan(code.data);
      } else {
        setError('No valid QR code pattern detected in the image. Please upload a clear QR code image or type a custom URL below.');
        setLoading(false);
      }
    } catch (err) {
      console.error('QR decode error:', err);
      setError('Failed to decode image data.');
      setLoading(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setError(null);
    setResult(null);
    setLoading(true);

    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target.result;
      setImagePreview(dataUrl);

      const img = new Image();
      img.onload = () => {
        decodeImageAndScan(img);
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  const runScan = async (urlToScan) => {
    setLoading(true);
    setError(null);
    try {
      const res = await predictSingleUrl(urlToScan, 'XGBoost', true, 'qr');
      setResult(res);
    } catch (err) {
      console.error('Scan error:', err);
      setError('Failed to scan URL from QR code.');
    } finally {
      setLoading(false);
    }
  };

  const handleCustomUrlSubmit = (e) => {
    if (e) e.preventDefault();
    const clean = customUrlInput.trim();
    if (!clean) {
      setError('Please enter a valid URL to generate and scan.');
      return;
    }
    setError(null);
    setDecodedUrl(clean);
    setImagePreview(`https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(clean)}`);
    runScan(clean);
  };

  const handlePresetSelect = (preset) => {
    setError(null);
    setDecodedUrl(preset.url);
    setCustomUrlInput(preset.url);
    setImagePreview(`https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(preset.url)}`);
    runScan(preset.url);
  };

  return (
    <div style={{ maxWidth: '1240px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '28px', padding: '0 16px' }}>
      
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.85), rgba(15, 23, 42, 0.98))',
        padding: '28px 32px',
        borderRadius: '16px',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        boxShadow: '0 10px 30px -10px rgba(0, 0, 0, 0.5)',
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
            <QrCode size={14} /> REAL-TIME QUISHING (QR CODE PHISHING) DETECTOR
          </div>
          <h1 style={{ fontSize: '1.8rem', fontWeight: '800', margin: '0 0 8px', color: '#F8FAFC' }}>
            QR Code Quishing & Threat Intelligence Analyzer
          </h1>
          <p style={{ margin: 0, fontSize: '0.9rem', color: '#94A3B8', lineHeight: '1.55' }}>
            Inspect any physical poster, email attachment, or 2FA login QR code. The engine decodes the target payload and evaluates it in real time against <strong style={{ color: '#EF4444' }}>OpenPhish & URLhaus live threat datasets</strong>, <strong style={{ color: '#10B981' }}>genuine TLS certificate handshakes</strong>, and <strong style={{ color: '#38BDF8' }}>Explainable AI (SHAP & LIME)</strong>.
          </p>
        </div>
      </div>

      {/* Preset Quishing Samples */}
      <div className="glass-panel" style={{ padding: '16px 20px', borderRadius: '12px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
          <div style={{ fontSize: '0.78rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Sparkles size={14} color="#38BDF8" /> ⚡ 1-Click Real-Time Test Targets:
          </div>
          <span style={{ fontSize: '0.72rem', color: '#64748B' }}>
            Click any sample or upload your own custom QR image / URL
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
          {SAMPLE_QUISHING_QRS.map((s, idx) => (
            <button
              key={idx}
              onClick={() => handlePresetSelect(s)}
              style={{
                background: s.category === 'Phishing' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${s.category === 'Phishing' ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                color: s.category === 'Phishing' ? '#FCA5A5' : '#86EFAC',
                fontSize: '0.78rem',
                padding: '6px 12px',
                borderRadius: '8px',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
              title={`${s.desc}\nURL: ${s.url}`}
            >
              {s.title}
            </button>
          ))}
        </div>
      </div>

      {/* Mode Switcher Tabs */}
      <div style={{ display: 'flex', gap: '10px' }}>
        <button
          onClick={() => setActiveMode('upload')}
          style={{
            background: activeMode === 'upload' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(30, 41, 59, 0.5)',
            border: `1px solid ${activeMode === 'upload' ? '#38BDF8' : 'rgba(255, 255, 255, 0.1)'}`,
            color: activeMode === 'upload' ? '#38BDF8' : '#94A3B8',
            padding: '10px 20px',
            borderRadius: '10px',
            fontSize: '0.86rem',
            fontWeight: '700',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <Upload size={16} /> Mode 1: Upload QR Image File
        </button>

        <button
          onClick={() => setActiveMode('url')}
          style={{
            background: activeMode === 'url' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(30, 41, 59, 0.5)',
            border: `1px solid ${activeMode === 'url' ? '#38BDF8' : 'rgba(255, 255, 255, 0.1)'}`,
            color: activeMode === 'url' ? '#38BDF8' : '#94A3B8',
            padding: '10px 20px',
            borderRadius: '10px',
            fontSize: '0.86rem',
            fontWeight: '700',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <LinkIcon size={16} /> Mode 2: Enter Custom Target URL & Scan
        </button>
      </div>

      {/* Upload and Scanner Area */}
      <div style={{ display: 'grid', gridTemplateColumns: result ? '1fr 1fr' : '1fr', gap: '24px', transition: 'all 0.3s ease' }}>
        {/* Upload Container */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', alignItems: 'center', textAlign: 'center' }}>
          
          {activeMode === 'upload' ? (
            <>
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                accept="image/*"
                style={{ display: 'none' }}
              />

              <div
                onClick={() => fileInputRef.current?.click()}
                style={{
                  width: '100%',
                  border: '2px dashed rgba(56, 189, 248, 0.35)',
                  borderRadius: '12px',
                  padding: '36px 20px',
                  background: 'rgba(15, 23, 42, 0.6)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '12px',
                  transition: 'all 0.2s ease'
                }}
              >
                {imagePreview ? (
                  <img
                    src={imagePreview}
                    alt="QR Preview"
                    style={{ maxHeight: '200px', maxWidth: '200px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.15)' }}
                  />
                ) : (
                  <div style={{ background: 'rgba(56, 189, 248, 0.15)', padding: '18px', borderRadius: '50%', color: '#38BDF8' }}>
                    <Upload size={36} />
                  </div>
                )}

                <div>
                  <div style={{ fontSize: '0.96rem', fontWeight: '700', color: '#F8FAFC' }}>
                    {imagePreview ? 'Click to Change QR Code Image' : 'Click to Upload or Drag & Drop QR Image'}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#64748B', marginTop: '4px' }}>
                    Supports PNG, JPG, JPEG, WebP
                  </div>
                </div>
              </div>
            </>
          ) : (
            <form onSubmit={handleCustomUrlSubmit} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '12px', textAlign: 'left' }}>
              <label style={{ fontSize: '0.85rem', color: '#CBD5E1', fontWeight: '600' }}>
                Enter Any Custom URL to Generate & Scan QR Code in Real Time:
              </label>
              <div style={{ display: 'flex', gap: '10px' }}>
                <input
                  type="text"
                  className="input-field"
                  placeholder="e.g. http://custom-test-phishing-site.xyz/login or https://github.com"
                  value={customUrlInput}
                  onChange={(e) => setCustomUrlInput(e.target.value)}
                  style={{ flex: 1, fontFamily: 'monospace', fontSize: '0.92rem' }}
                />
                <button type="submit" disabled={loading} className="btn-primary" style={{ padding: '10px 20px' }}>
                  <Zap size={16} /> Scan
                </button>
              </div>

              {imagePreview && (
                <div style={{ display: 'flex', justifyContent: 'center', marginTop: '10px' }}>
                  <img
                    src={imagePreview}
                    alt="Generated QR"
                    style={{ maxHeight: '180px', maxWidth: '180px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.15)' }}
                  />
                </div>
              )}
            </form>
          )}

          {error && (
            <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.35)', color: '#EF4444', padding: '10px 14px', borderRadius: '8px', fontSize: '0.82rem', width: '100%', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangle size={16} /> {error}
            </div>
          )}

          {decodedUrl && (
            <div style={{ width: '100%', background: 'rgba(15, 23, 42, 0.8)', padding: '14px 16px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.1)', textAlign: 'left' }}>
              <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase' }}>DECODED TARGET PAYLOAD URL</div>
              <div style={{ fontSize: '0.92rem', fontWeight: '700', color: '#38BDF8', fontFamily: 'monospace', wordBreak: 'break-all', marginTop: '4px' }}>
                {decodedUrl}
              </div>
            </div>
          )}
        </div>

        {/* Results Container */}
        {result && (
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '12px' }}>
              <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: '700' }}>
                <QrCode size={18} color="#38BDF8" /> Quishing Threat Assessment
              </h3>
              <span style={{ fontSize: '0.74rem', color: '#10B981', display: 'flex', alignItems: 'center', gap: '5px', fontWeight: '600' }}>
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10B981' }} />
                Live Real-Time Scan
              </span>
            </div>

            {/* Verdict Box */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: '16px', flexWrap: 'wrap' }}>
              <RiskMeter 
                probability={result.phishing_probability} 
                riskLevel={result.risk_level} 
                confidence={result.confidence_score}
                prediction={result.prediction}
              />

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', minWidth: '180px' }}>
                <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                  Target Domain: <strong style={{ color: '#F8FAFC' }}>{result.domain}</strong>
                </div>
                <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                  Protocol: <strong style={{ color: result.features?.https_status ? '#10B981' : '#EF4444' }}>{result.features?.https_status ? 'HTTPS (Encrypted)' : 'HTTP (Insecure)'}</strong>
                </div>
                {result.threat_intel?.realtime_dataset_source && (
                  <div style={{ fontSize: '0.74rem', color: '#EF4444', fontWeight: '700', background: 'rgba(239, 68, 68, 0.12)', padding: '4px 8px', borderRadius: '6px' }}>
                    🚨 {result.threat_intel.realtime_dataset_source}
                  </div>
                )}
                {result.threat_intel?.is_authentic_authority && (
                  <div style={{ fontSize: '0.74rem', color: '#10B981', fontWeight: '700', background: 'rgba(16, 185, 129, 0.12)', padding: '4px 8px', borderRadius: '6px' }}>
                    🛡️ Verified Authentic Organization
                  </div>
                )}
              </div>
            </div>

            {/* Real-time Threat Intelligence Preview */}
            {result.threat_intel && (
              <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.08)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.78rem' }}>
                <div>
                  <span style={{ color: '#94A3B8' }}>Live DNS Resolution:</span>
                  <div style={{ color: '#F8FAFC', fontWeight: '700', marginTop: '2px', fontFamily: 'monospace' }}>
                    {result.threat_intel.dns_resolved_ip || result.threat_intel.dns_status}
                  </div>
                </div>
                <div>
                  <span style={{ color: '#94A3B8' }}>SSL/TLS Security:</span>
                  <div style={{ color: result.threat_intel.ssl_valid ? '#10B981' : '#EF4444', fontWeight: '700', marginTop: '2px' }}>
                    {result.threat_intel.ssl_valid ? `Active (${result.threat_intel.ssl_protocol})` : 'Unencrypted / No SSL'}
                  </div>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <span style={{ color: '#94A3B8' }}>Registration Longevity:</span>
                  <div style={{ color: '#F8FAFC', fontWeight: '600', marginTop: '2px' }}>
                    {result.threat_intel.domain_age}
                  </div>
                </div>
              </div>
            )}

            {/* SHAP Waterfall Preview */}
            {result.shap_explanation && (
              <div>
                <div style={{ fontSize: '0.82rem', fontWeight: '700', color: '#F8FAFC', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Sparkles size={14} color="#38BDF8" /> XAI Feature Attribution Breakdown (SHAP):
                </div>
                <ShapWaterfallChart shapExplanation={result.shap_explanation} />
              </div>
            )}
          </div>
        )}
      </div>

      {loading && !result && (
        <div style={{ textAlign: 'center', padding: '24px', color: '#38BDF8', fontSize: '0.92rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px' }}>
          <RefreshCw size={18} className="animate-spin" /> Decoding QR payload and running real-time AI security scan...
        </div>
      )}
    </div>
  );
}
