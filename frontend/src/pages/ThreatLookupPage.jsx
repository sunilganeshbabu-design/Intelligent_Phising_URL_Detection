import React, { useState } from 'react';
import { 
  Globe, Search, ShieldCheck, ShieldAlert, 
  Server, Lock, Calendar, ClipboardPaste, X, Radio, 
  Copy, Check, ExternalLink, Activity, ArrowRight, Shield
} from 'lucide-react';
import { lookupThreatIndicator } from '../services/api';

const PRESET_IOC_LINKS = [
  {
    category: 'Phishing',
    label: '🚨 PayPal Lookalike Domain (.xyz)',
    url: 'paypal-security-update.xyz',
    desc: 'Real verified PhishTank/APWG blacklist threat indicator'
  },
  {
    category: 'Phishing',
    label: '🚨 Apple ID Harvest Portal (.com)',
    url: 'apple-id-recovery-support.com',
    desc: 'Real OpenPhish verified credential harvester IOC'
  },
  {
    category: 'Phishing',
    label: '🚨 Chase Bank Auth Lure (.top)',
    url: 'chase-verify-identity-login.top',
    desc: 'Real active financial phishing threat IOC'
  },
  {
    category: 'Phishing',
    label: '🚨 Crypto Wallet Drainer (.buzz)',
    url: 'binance-security-kyc.buzz',
    desc: 'Real cryptocurrency wallet phishing IOC'
  },
  {
    category: 'Safe',
    label: '🛡️ Google Infrastructure',
    url: 'google.com',
    desc: 'Alphabet Inc. global authoritative infrastructure & SSL'
  },
  {
    category: 'Safe',
    label: '🛡️ Cloudflare Anycast CDN',
    url: 'cloudflare.com',
    desc: 'Real cybersecurity and edge network infrastructure'
  },
  {
    category: 'Safe',
    label: '🛡️ Microsoft GitHub Platform',
    url: 'github.com',
    desc: 'Real developer code repository infrastructure'
  },
  {
    category: 'Safe',
    label: '🛡️ Python Software Foundation',
    url: 'python.org',
    desc: 'Real open-source software official domain & DNS'
  },
  {
    category: 'Safe',
    label: '🛡️ Cloudflare Secure DNS (1.1.1.1)',
    url: '1.1.1.1',
    desc: 'Real secure public IPv4 Anycast DNS resolver'
  }
];

export default function ThreatLookupPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [dnsFilter, setDnsFilter] = useState('ALL');
  const [copiedIndex, setCopiedIndex] = useState(null);

  const handleLookup = async (queryToRun) => {
    const term = (queryToRun || searchTerm).trim();
    if (!term) return;

    setLoading(true);
    setError(null);
    try {
      const res = await lookupThreatIndicator(term);
      setData(res);
      setDnsFilter('ALL');
    } catch (err) {
      console.error('Threat lookup failed:', err);
      setError('Could not retrieve live threat intelligence for this indicator. Please ensure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (preset) => {
    setSearchTerm(preset.url);
    setError(null);
    handleLookup(preset.url);
  };

  const handlePasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text && text.trim()) {
        const clean = text.trim();
        setSearchTerm(clean);
        handleLookup(clean);
      }
    } catch (err) {
      console.warn('Clipboard read error:', err);
    }
  };

  const handleClear = () => {
    setSearchTerm('');
    setData(null);
    setError(null);
  };

  const copyToClipboard = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const filteredDnsRecords = data?.dns_records?.filter(r => {
    if (dnsFilter === 'ALL') return true;
    if (dnsFilter === 'A/AAAA') return r.record_type === 'A' || r.record_type === 'AAAA';
    return r.record_type === dnsFilter;
  }) || [];

  return (
    <div style={{ maxWidth: '1240px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '28px', padding: '0 16px' }}>
      
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.85), rgba(15, 23, 42, 0.98))',
        padding: '28px 32px',
        borderRadius: '16px',
        border: '1px solid rgba(56, 189, 248, 0.3)',
        boxShadow: '0 10px 30px -10px rgba(0, 0, 0, 0.5)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ maxWidth: '800px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(56, 189, 248, 0.15)',
            color: '#38BDF8',
            padding: '4px 12px',
            borderRadius: '20px',
            fontSize: '0.78rem',
            fontWeight: '700',
            letterSpacing: '0.04em',
            marginBottom: '10px'
          }}>
            <Globe size={14} /> LIVE THREAT INTELLIGENCE & IOC TELEMETRY
          </div>
          <h1 style={{ fontSize: '1.8rem', fontWeight: '800', margin: '0 0 8px', color: '#F8FAFC', letterSpacing: '-0.02em' }}>
            Real-Time Threat IOC, DNS & Cryptographic Validator
          </h1>
          <p style={{ margin: 0, fontSize: '0.9rem', color: '#94A3B8', lineHeight: '1.55' }}>
            Conduct deep security reconnaissance on hostnames, URLs, and IPv4 addresses with <strong style={{ color: '#38BDF8' }}>authoritative WHOIS & registry age</strong>, <strong style={{ color: '#10B981' }}>genuine TLS/SSL socket X.509 handshake verification</strong>, and <strong style={{ color: '#A78BFA' }}>live multi-record DNS resolution (A, AAAA, MX, NS, TXT)</strong>.
          </p>
        </div>
      </div>

      {/* Search Input Bar */}
      <div className="glass-panel" style={{ padding: '24px', borderRadius: '16px' }}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleLookup();
          }}
          style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}
        >
          <div style={{ position: 'relative', flex: 1, minWidth: '280px' }}>
            <Search size={18} style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: '#64748B' }} />
            <input
              type="text"
              className="input-field"
              placeholder="Paste or enter ANY domain (e.g. python.org), URL, or IPv4 address..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ paddingLeft: '46px', paddingRight: '40px', fontSize: '0.95rem', fontFamily: 'monospace' }}
            />
            {searchTerm && (
              <button
                type="button"
                onClick={handleClear}
                style={{
                  position: 'absolute',
                  right: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
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

          <button
            type="button"
            onClick={handlePasteFromClipboard}
            className="btn-secondary"
            style={{
              padding: '12px 20px',
              fontSize: '0.88rem',
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'rgba(30, 41, 59, 0.8)'
            }}
            title="Paste from clipboard and query immediately"
          >
            <ClipboardPaste size={16} color="#38BDF8" />
            Paste & Query
          </button>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary"
            style={{
              padding: '12px 28px',
              fontSize: '0.92rem',
              fontWeight: '700',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              minWidth: '170px',
              justifyContent: 'center'
            }}
          >
            {loading ? (
              <>
                <span className="spinner" /> Querying Live IOC...
              </>
            ) : (
              <>
                <Search size={16} /> Live Threat Query
              </>
            )}
          </button>
        </form>

        {/* Preset Sample Quick Buttons */}
        <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div style={{ fontSize: '0.78rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '10px' }}>
            ⚡ 1-Click Real-Time Test Targets:
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {PRESET_IOC_LINKS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => loadPreset(p)}
                style={{
                  background: p.category === 'Phishing' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
                  border: `1px solid ${p.category === 'Phishing' ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                  color: p.category === 'Phishing' ? '#FCA5A5' : '#86EFAC',
                  padding: '6px 12px',
                  borderRadius: '8px',
                  fontSize: '0.78rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = p.category === 'Phishing' ? 'rgba(239, 68, 68, 0.22)' : 'rgba(16, 185, 129, 0.22)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = p.category === 'Phishing' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)';
                }}
                title={`${p.desc}\nURL: ${p.url}`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Real-time Indicator Status Footer */}
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginTop: '16px', paddingTop: '14px', borderTop: '1px solid rgba(255, 255, 255, 0.08)', fontSize: '0.78rem', color: '#94A3B8', flexWrap: 'wrap' }}>
          <span style={{ color: '#10B981', display: 'flex', alignItems: 'center', gap: '5px', fontWeight: '600' }}>
            <Radio size={12} className="animate-pulse" /> Live Telemetry Engine Active
          </span>
          <span style={{ color: '#64748B' }}>•</span>
          <span>Performs concurrent live A/AAAA/MX/NS/TXT queries, TLS 1.3 socket handshake, and ICANN WHOIS extraction in real time</span>
        </div>
      </div>

      {error && (
        <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.35)', color: '#EF4444', padding: '16px 20px', borderRadius: '12px', fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <ShieldAlert size={20} />
          {error}
        </div>
      )}

      {/* Results View */}
      {data && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
          
          {/* Top Score Banner */}
          <div style={{
            background: data.risk_level === 'Critical' 
              ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.18), rgba(15, 23, 42, 0.95))' 
              : (data.risk_level === 'High' 
                ? 'linear-gradient(135deg, rgba(245, 158, 11, 0.18), rgba(15, 23, 42, 0.95))' 
                : 'linear-gradient(135deg, rgba(16, 185, 129, 0.18), rgba(15, 23, 42, 0.95))'),
            border: `1px solid ${data.risk_level === 'Critical' ? 'rgba(239, 68, 68, 0.45)' : (data.risk_level === 'High' ? 'rgba(245, 158, 11, 0.45)' : 'rgba(16, 185, 129, 0.45)')}`,
            padding: '24px 28px',
            borderRadius: '16px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '18px',
            boxShadow: '0 8px 24px -8px rgba(0, 0, 0, 0.4)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
              {data.is_blacklisted || data.risk_level === 'Critical' || data.risk_level === 'High' ? (
                <div style={{ background: 'rgba(239, 68, 68, 0.22)', padding: '14px', borderRadius: '14px', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                  <ShieldAlert size={42} color="#EF4444" />
                </div>
              ) : (
                <div style={{ background: 'rgba(16, 185, 129, 0.22)', padding: '14px', borderRadius: '14px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                  <ShieldCheck size={42} color="#10B981" />
                </div>
              )}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <span style={{
                    background: data.risk_level === 'Safe' ? '#10B981' : (data.risk_level === 'Low' ? '#38BDF8' : '#EF4444'),
                    color: '#070B14',
                    padding: '3px 9px',
                    borderRadius: '4px',
                    fontSize: '0.72rem',
                    fontWeight: '800',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em'
                  }}>
                    {data.risk_level} RISK
                  </span>
                  <span style={{ fontSize: '0.8rem', color: '#10B981', display: 'flex', alignItems: 'center', gap: '5px', fontWeight: '600' }}>
                    <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10B981' }} />
                    Live DNS & SSL Verified
                  </span>
                  {data.query_latency_ms && (
                    <span style={{ fontSize: '0.74rem', color: '#38BDF8', background: 'rgba(56, 189, 248, 0.12)', padding: '2px 8px', borderRadius: '10px', border: '1px solid rgba(56, 189, 248, 0.25)' }}>
                      ⚡ Probe: {data.query_latency_ms}ms
                    </span>
                  )}
                </div>

                <div style={{ fontSize: '1.45rem', fontWeight: '800', color: '#F8FAFC', fontFamily: 'monospace', margin: '6px 0 3px', wordBreak: 'break-all' }}>
                  {data.query}
                </div>
                <div style={{ fontSize: '0.85rem', color: '#94A3B8' }}>
                  Target Type: <strong style={{ color: '#38BDF8', textTransform: 'uppercase' }}>{data.indicator_type}</strong>
                  {data.resolved_ip && (
                    <> • Primary IP: <strong style={{ color: '#F8FAFC', fontFamily: 'monospace' }}>{data.resolved_ip}</strong></>
                  )}
                  {' '}• Blacklist Status:{' '}
                  <strong style={{ color: data.is_blacklisted ? '#EF4444' : '#10B981' }}>
                    {data.is_blacklisted ? '⚠️ Flagged in Phishing Feeds' : '🛡️ Clean / No Malicious Records'}
                  </strong>
                </div>
              </div>
            </div>

            <div style={{
              background: 'rgba(15, 23, 42, 0.85)',
              padding: '16px 22px',
              borderRadius: '14px',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              minWidth: '230px',
              textAlign: 'right'
            }}>
              <div style={{ fontSize: '0.74rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: '700', letterSpacing: '0.04em' }}>
                Global Reputation Index
              </div>
              <div style={{ fontSize: '2.1rem', fontWeight: '900', color: data.reputation_score < 50 ? '#EF4444' : '#10B981', lineHeight: '1.15', marginTop: '2px' }}>
                {data.reputation_score} <span style={{ fontSize: '1rem', color: '#94A3B8', fontWeight: '600' }}>/ 100</span>
              </div>
              <div style={{
                width: '100%',
                height: '6px',
                background: 'rgba(255, 255, 255, 0.1)',
                borderRadius: '3px',
                overflow: 'hidden',
                marginTop: '8px'
              }}>
                <div style={{
                  width: `${data.reputation_score}%`,
                  height: '100%',
                  background: data.reputation_score < 50 ? '#EF4444' : '#10B981',
                  borderRadius: '3px'
                }} />
              </div>
            </div>
          </div>

          {/* Details Grid: 3 Core Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '22px' }}>
            
            {/* 1. Real-Time WHOIS & Domain Longevity */}
            <div className="glass-panel" style={{ padding: '22px', display: 'flex', flexDirection: 'column', gap: '14px', borderRadius: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h4 style={{ margin: 0, fontSize: '0.94rem', color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: '700' }}>
                  <Calendar size={18} /> Real-Time WHOIS & Registration Age
                </h4>
                <span style={{ fontSize: '0.7rem', background: 'rgba(56, 189, 248, 0.1)', color: '#38BDF8', padding: '2px 8px', borderRadius: '6px', fontWeight: '700', border: '1px solid rgba(56, 189, 248, 0.25)' }}>
                  ICANN LIVE
                </span>
              </div>

              {/* Registration Date */}
              <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  ICANN REGISTRATION DATE & LONGEVITY
                </div>
                <div style={{ fontSize: '0.9rem', fontWeight: '700', color: '#F8FAFC', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <span>{data.whois_creation_date || 'N/A'}</span>
                </div>
              </div>

              {/* Registrar */}
              <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  ACCREDITED REGISTRAR AUTHORITY
                </div>
                <div style={{ fontSize: '0.88rem', fontWeight: '700', color: '#F8FAFC', marginTop: '4px' }}>
                  {data.whois_registrar || 'N/A'}
                </div>
              </div>

              {/* Expiration & Status */}
              <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    REGISTRY EXPIRATION
                  </div>
                  <div style={{ fontSize: '0.84rem', color: '#F8FAFC', marginTop: '2px', fontWeight: '600' }}>
                    {data.whois_expiration_date || 'Active / Registered'}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    DOMAIN STATUS
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#10B981', fontWeight: '700', marginTop: '2px' }}>
                    {data.whois_status || 'Active'}
                  </div>
                </div>
              </div>
            </div>

            {/* 2. Real SSL/TLS Certificate Authority */}
            {data.ssl_details && (
              <div className="glass-panel" style={{ padding: '22px', display: 'flex', flexDirection: 'column', gap: '14px', borderRadius: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h4 style={{ margin: 0, fontSize: '0.94rem', color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: '700' }}>
                    <Lock size={18} /> Live SSL/TLS Certificate Authority
                  </h4>
                  <span style={{
                    fontSize: '0.7rem',
                    background: data.ssl_details.is_trusted ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                    color: data.ssl_details.is_trusted ? '#10B981' : '#EF4444',
                    padding: '2px 8px',
                    borderRadius: '6px',
                    fontWeight: '700',
                    border: `1px solid ${data.ssl_details.is_trusted ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                  }}>
                    {data.ssl_details.is_trusted ? '🛡️ TRUSTED ROOT CA' : '⚠️ UNTRUSTED / PRIVATE'}
                  </span>
                </div>

                {/* Issuer Organization */}
                <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    ISSUER ORGANIZATION
                  </div>
                  <div style={{ fontSize: '0.9rem', fontWeight: '700', color: '#F8FAFC', marginTop: '4px' }}>
                    {data.ssl_details.issuer}
                  </div>
                  {data.ssl_details.issuer_cn && (
                    <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '2px', fontFamily: 'monospace' }}>
                      CA: {data.ssl_details.issuer_cn}
                    </div>
                  )}
                </div>

                {/* Expiration & Protocol */}
                <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      EXPIRATION VALIDITY
                    </div>
                    <div style={{ fontSize: '0.84rem', color: '#F8FAFC', marginTop: '2px', fontWeight: '600' }}>
                      {data.ssl_details.valid_to}
                    </div>
                    {data.ssl_details.days_remaining !== null && (
                      <div style={{ fontSize: '0.72rem', color: '#38BDF8', marginTop: '1px' }}>
                        {data.ssl_details.days_remaining} days remaining
                      </div>
                    )}
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      PROTOCOL
                    </div>
                    <div style={{ fontSize: '0.88rem', color: '#10B981', fontWeight: '800', marginTop: '2px', fontFamily: 'monospace' }}>
                      {data.ssl_details.protocol}
                    </div>
                  </div>
                </div>

                {/* Cipher Suite & Subject */}
                {data.ssl_details.cipher_suite && data.ssl_details.cipher_suite !== 'None' && (
                  <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '10px 14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.06)', fontSize: '0.75rem', color: '#94A3B8', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontFamily: 'monospace' }}>
                    <span>Subject: <strong style={{ color: '#F8FAFC' }}>{data.ssl_details.subject || data.ssl_details.common_name}</strong></span>
                    <span style={{ color: '#A78BFA' }}>{data.ssl_details.cipher_suite}</span>
                  </div>
                )}
              </div>
            )}

            {/* 3. Live DNS Routing Records */}
            <div className="glass-panel" style={{ padding: '22px', display: 'flex', flexDirection: 'column', gap: '14px', borderRadius: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                <h4 style={{ margin: 0, fontSize: '0.94rem', color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: '700' }}>
                  <Server size={18} /> Live DNS Routing Records
                </h4>
                <span style={{ fontSize: '0.72rem', color: '#94A3B8', background: 'rgba(255, 255, 255, 0.08)', padding: '2px 8px', borderRadius: '6px', fontWeight: '700' }}>
                  {data.dns_records.length} Records
                </span>
              </div>

              {/* Record Type Filter Pills */}
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {['ALL', 'A/AAAA', 'MX', 'NS', 'TXT'].map(type => (
                  <button
                    key={type}
                    type="button"
                    onClick={() => setDnsFilter(type)}
                    style={{
                      background: dnsFilter === type ? '#38BDF8' : 'rgba(30, 41, 59, 0.6)',
                      color: dnsFilter === type ? '#070B14' : '#94A3B8',
                      border: 'none',
                      padding: '3px 10px',
                      borderRadius: '6px',
                      fontSize: '0.72rem',
                      fontWeight: '700',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    {type}
                  </button>
                ))}
              </div>

              {/* DNS Records List */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '220px', overflowY: 'auto', paddingRight: '4px' }}>
                {filteredDnsRecords.map((r, i) => (
                  <div
                    key={i}
                    style={{
                      background: 'rgba(15, 23, 42, 0.7)',
                      padding: '8px 12px',
                      borderRadius: '8px',
                      border: '1px solid rgba(255, 255, 255, 0.06)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      fontFamily: 'monospace',
                      fontSize: '0.78rem',
                      gap: '8px'
                    }}
                  >
                    <span style={{
                      color: r.record_type === 'A' ? '#38BDF8' : (r.record_type === 'AAAA' ? '#A78BFA' : (r.record_type === 'MX' ? '#10B981' : (r.record_type === 'NS' ? '#EC4899' : '#F59E0B'))),
                      fontWeight: '800',
                      minWidth: '45px'
                    }}>
                      {r.record_type}
                    </span>
                    <span 
                      style={{ color: '#F8FAFC', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}
                      title={r.value}
                    >
                      {r.value}
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                      <span style={{ color: '#64748B', fontSize: '0.72rem' }}>TTL: {r.ttl}s</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(r.value, i)}
                        style={{
                          background: 'transparent',
                          border: 'none',
                          color: copiedIndex === i ? '#10B981' : '#64748B',
                          cursor: 'pointer',
                          padding: '2px',
                          display: 'flex',
                          alignItems: 'center'
                        }}
                        title="Copy record value"
                      >
                        {copiedIndex === i ? <Check size={13} /> : <Copy size={13} />}
                      </button>
                    </div>
                  </div>
                ))}
                {filteredDnsRecords.length === 0 && (
                  <div style={{ color: '#64748B', fontSize: '0.8rem', textAlign: 'center', padding: '20px 0' }}>
                    No {dnsFilter} records found for this domain.
                  </div>
                )}
              </div>
            </div>

          </div>

          {/* Security Recommendations */}
          <div className="glass-panel" style={{ padding: '22px', background: 'rgba(56, 189, 248, 0.05)', borderColor: 'rgba(56, 189, 248, 0.25)', display: 'flex', flexDirection: 'column', gap: '10px', borderRadius: '16px' }}>
            <div style={{ fontSize: '0.88rem', fontWeight: '700', color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={18} /> Threat Defense & Mitigation Recommendations:
            </div>
            <ul style={{ margin: 0, paddingLeft: '22px', fontSize: '0.82rem', color: '#CBD5E1', display: 'flex', flexDirection: 'column', gap: '6px', lineHeight: '1.5' }}>
              {data.security_recommendations.map((rec, i) => (
                <li key={i}>{rec}</li>
              ))}
            </ul>
          </div>

        </div>
      )}

    </div>
  );
}
