import React, { useState, useEffect } from 'react';
import { Sliders, RefreshCw, Zap, ShieldAlert, CheckCircle2, Info } from 'lucide-react';
import { simulateWhatIf } from '../services/api';

export default function XaiWhatIfSimulator({ initialFeatures, currentModel = 'XGBoost' }) {
  // Initialize state with features
  const [features, setFeatures] = useState({
    subdomain_count: initialFeatures?.subdomain_count || 1,
    url_length: initialFeatures?.url_length || 45,
    https_status: initialFeatures?.https_status ? 1 : 0,
    ip_address: initialFeatures?.ip_address ? 1 : 0,
    has_at_symbol: initialFeatures?.has_at_symbol ? 1 : 0,
    has_prefix_suffix: initialFeatures?.has_prefix_suffix ? 1 : 0,
    is_shortened_url: initialFeatures?.is_shortened_url ? 1 : 0,
    suspicious_keywords: initialFeatures?.suspicious_keywords || 0,
    entropy: initialFeatures?.entropy || 3.8,
    tld_risk_score: initialFeatures?.tld_risk_score || 0.1,
    count_dots: initialFeatures?.count_dots || 2,
    count_hyphens: initialFeatures?.count_hyphens || 0,
    count_slashes: initialFeatures?.count_slashes || 2,
    domain_length: initialFeatures?.domain_length || 18,
    path_length: initialFeatures?.path_length || 15,
    count_digits: initialFeatures?.count_digits || 0
  });

  const [simResult, setSimResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runSimulation = async (updatedFeatures) => {
    setLoading(true);
    try {
      const res = await simulateWhatIf(updatedFeatures, currentModel);
      setSimResult(res);
    } catch (err) {
      console.error('What-If simulation failed:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runSimulation(features);
  }, []);

  const handleSliderChange = (key, value) => {
    const next = { ...features, [key]: parseFloat(value) };
    setFeatures(next);
    runSimulation(next);
  };

  const handleToggleChange = (key) => {
    const next = { ...features, [key]: features[key] === 1 ? 0 : 1 };
    setFeatures(next);
    runSimulation(next);
  };

  const resetFeatures = () => {
    if (initialFeatures) {
      const reset = {
        ...features,
        subdomain_count: initialFeatures.subdomain_count || 1,
        url_length: initialFeatures.url_length || 45,
        https_status: initialFeatures.https_status ? 1 : 0,
        ip_address: initialFeatures.ip_address ? 1 : 0,
        has_at_symbol: initialFeatures.has_at_symbol ? 1 : 0,
        has_prefix_suffix: initialFeatures.has_prefix_suffix ? 1 : 0,
        is_shortened_url: initialFeatures.is_shortened_url ? 1 : 0,
        suspicious_keywords: initialFeatures.suspicious_keywords || 0,
        entropy: initialFeatures.entropy || 3.8,
        tld_risk_score: initialFeatures.tld_risk_score || 0.1
      };
      setFeatures(reset);
      runSimulation(reset);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8))',
        padding: '16px 20px',
        borderRadius: '12px',
        border: '1px solid rgba(56, 189, 248, 0.2)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ background: 'rgba(56, 189, 248, 0.15)', padding: '8px', borderRadius: '8px', color: '#38BDF8' }}>
            <Sliders size={20} />
          </div>
          <div>
            <h4 style={{ margin: 0, fontSize: '0.96rem', color: '#F8FAFC' }}>
              Explainable AI (XAI) Counterfactual "What-If" Simulator
            </h4>
            <p style={{ margin: '2px 0 0', fontSize: '0.78rem', color: '#94A3B8' }}>
              Interactively adjust feature parameters to observe how the AI model and SHAP feature attributions respond in real time.
            </p>
          </div>
        </div>

        <button
          onClick={resetFeatures}
          className="btn-secondary"
          style={{ fontSize: '0.78rem', padding: '6px 14px' }}
        >
          <RefreshCw size={14} />
          Reset Baseline
        </button>
      </div>

      {/* Main Simulation Workspace */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        {/* Left: Interactive Controls */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <h5 style={{ margin: 0, fontSize: '0.88rem', color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={16} /> Feature Sliders & Toggles
            </h5>
            <span style={{ fontSize: '0.72rem', color: '#94A3B8' }}>Instant Recalculation</span>
          </div>

          {/* Toggle Switches */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            {/* HTTPS Toggle */}
            <div
              onClick={() => handleToggleChange('https_status')}
              style={{
                background: features.https_status === 1 ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                border: `1px solid ${features.https_status === 1 ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
                padding: '10px 12px',
                borderRadius: '8px',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
            >
              <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>HTTPS Protocol</div>
              <div style={{ fontSize: '0.85rem', fontWeight: '700', color: features.https_status === 1 ? '#10B981' : '#EF4444' }}>
                {features.https_status === 1 ? '🔒 Enabled (HTTPS)' : '⚠️ Insecure (HTTP)'}
              </div>
            </div>

            {/* Direct IP Toggle */}
            <div
              onClick={() => handleToggleChange('ip_address')}
              style={{
                background: features.ip_address === 1 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                border: `1px solid ${features.ip_address === 1 ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
                padding: '10px 12px',
                borderRadius: '8px',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
            >
              <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>Host Type</div>
              <div style={{ fontSize: '0.85rem', fontWeight: '700', color: features.ip_address === 1 ? '#EF4444' : '#10B981' }}>
                {features.ip_address === 1 ? '⚠️ Raw IP Address' : '🌐 Domain Name'}
              </div>
            </div>

            {/* RFC @ Symbol Toggle */}
            <div
              onClick={() => handleToggleChange('has_at_symbol')}
              style={{
                background: features.has_at_symbol === 1 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(30, 41, 59, 0.5)',
                border: `1px solid ${features.has_at_symbol === 1 ? 'rgba(239, 68, 68, 0.4)' : 'rgba(255, 255, 255, 0.08)'}`,
                padding: '10px 12px',
                borderRadius: '8px',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
            >
              <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>Embedded '@' Symbol</div>
              <div style={{ fontSize: '0.85rem', fontWeight: '700', color: features.has_at_symbol === 1 ? '#EF4444' : '#F8FAFC' }}>
                {features.has_at_symbol === 1 ? '⚠️ Obfuscated (@)' : 'None'}
              </div>
            </div>

            {/* Typosquatted Hyphen Toggle */}
            <div
              onClick={() => handleToggleChange('has_prefix_suffix')}
              style={{
                background: features.has_prefix_suffix === 1 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(30, 41, 59, 0.5)',
                border: `1px solid ${features.has_prefix_suffix === 1 ? 'rgba(239, 68, 68, 0.4)' : 'rgba(255, 255, 255, 0.08)'}`,
                padding: '10px 12px',
                borderRadius: '8px',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
            >
              <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>Brand Typosquatting</div>
              <div style={{ fontSize: '0.85rem', fontWeight: '700', color: features.has_prefix_suffix === 1 ? '#EF4444' : '#F8FAFC' }}>
                {features.has_prefix_suffix === 1 ? '⚠️ Hyphenated Brand' : 'Standard'}
              </div>
            </div>
          </div>

          {/* Sliders */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {/* Subdomain Count Slider */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#F8FAFC', marginBottom: '4px' }}>
                <span>Subdomain Stacking:</span>
                <span style={{ color: '#38BDF8', fontWeight: '700' }}>{features.subdomain_count} nested subdomains</span>
              </div>
              <input
                type="range"
                min="0"
                max="5"
                step="1"
                value={features.subdomain_count}
                onChange={(e) => handleSliderChange('subdomain_count', e.target.value)}
                style={{ width: '100%', accentColor: '#38BDF8', cursor: 'pointer' }}
              />
            </div>

            {/* Suspicious Keywords Count Slider */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#F8FAFC', marginBottom: '4px' }}>
                <span>Suspicious Auth Keywords:</span>
                <span style={{ color: features.suspicious_keywords > 0 ? '#EF4444' : '#10B981', fontWeight: '700' }}>
                  {features.suspicious_keywords} keywords
                </span>
              </div>
              <input
                type="range"
                min="0"
                max="5"
                step="1"
                value={features.suspicious_keywords}
                onChange={(e) => handleSliderChange('suspicious_keywords', e.target.value)}
                style={{ width: '100%', accentColor: '#EF4444', cursor: 'pointer' }}
              />
            </div>

            {/* Shannon Entropy Slider */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#F8FAFC', marginBottom: '4px' }}>
                <span>Shannon Character Entropy:</span>
                <span style={{ color: features.entropy > 4.2 ? '#EF4444' : '#38BDF8', fontWeight: '700' }}>
                  {features.entropy.toFixed(2)} / 6.00
                </span>
              </div>
              <input
                type="range"
                min="2.0"
                max="5.8"
                step="0.1"
                value={features.entropy}
                onChange={(e) => handleSliderChange('entropy', e.target.value)}
                style={{ width: '100%', accentColor: '#818CF8', cursor: 'pointer' }}
              />
            </div>

            {/* TLD Risk Score Slider */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#F8FAFC', marginBottom: '4px' }}>
                <span>TLD Abuse Index (.com vs .xyz/.top/.tk):</span>
                <span style={{ color: features.tld_risk_score > 0.4 ? '#EF4444' : '#10B981', fontWeight: '700' }}>
                  {(features.tld_risk_score * 100).toFixed(0)}% Risk
                </span>
              </div>
              <input
                type="range"
                min="0.0"
                max="0.95"
                step="0.05"
                value={features.tld_risk_score}
                onChange={(e) => handleSliderChange('tld_risk_score', e.target.value)}
                style={{ width: '100%', accentColor: '#F59E0B', cursor: 'pointer' }}
              />
            </div>

            {/* URL Length Slider */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#F8FAFC', marginBottom: '4px' }}>
                <span>URL Length:</span>
                <span style={{ color: '#F8FAFC', fontWeight: '700' }}>{features.url_length} characters</span>
              </div>
              <input
                type="range"
                min="15"
                max="120"
                step="5"
                value={features.url_length}
                onChange={(e) => handleSliderChange('url_length', e.target.value)}
                style={{ width: '100%', accentColor: '#38BDF8', cursor: 'pointer' }}
              />
            </div>
          </div>
        </div>

        {/* Right: Live Simulated Output & SHAP Waterfall */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <h5 style={{ margin: 0, fontSize: '0.88rem', color: '#38BDF8' }}>
              Counterfactual Model Outcome
            </h5>
            <span style={{ fontSize: '0.72rem', color: '#10B981', display: 'flex', alignItems: 'center', gap: '5px' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10B981' }} />
              Live Inference
            </span>
          </div>

          {loading && !simResult ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '200px', color: '#94A3B8', gap: '10px' }}>
              <span className="spinner" /> Calculating counterfactual outcome...
            </div>
          ) : simResult ? (
            <>
              {/* Verdict Summary Box */}
              <div style={{
                background: simResult.prediction === 'Phishing' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
                border: `1px solid ${simResult.prediction === 'Phishing' ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                padding: '16px',
                borderRadius: '10px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  {simResult.prediction === 'Phishing' ? (
                    <ShieldAlert size={32} color="#EF4444" />
                  ) : (
                    <CheckCircle2 size={32} color="#10B981" />
                  )}
                  <div>
                    <div style={{ fontSize: '1.2rem', fontWeight: '800', color: simResult.prediction === 'Phishing' ? '#EF4444' : '#10B981' }}>
                      {simResult.prediction || 'Calculating...'}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: '#94A3B8' }}>
                      Risk Level: <strong style={{ color: '#F8FAFC' }}>{simResult.risk_level || 'Normal'}</strong>
                    </div>
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '1.4rem', fontWeight: '900', color: simResult.prediction === 'Phishing' ? '#EF4444' : '#10B981' }}>
                    {simResult.phishing_probability ?? 0}%
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>Phishing Probability</div>
                </div>
              </div>

              {/* Dynamic SHAP Recalculation Breakdown */}
              <div>
                <div style={{ fontSize: '0.78rem', fontWeight: '700', color: '#F8FAFC', marginBottom: '8px' }}>
                  Recalculated Feature Contributions (Top Drivers):
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '220px', overflowY: 'auto' }}>
                  {Array.isArray(simResult.shap_explanation?.contributions) && simResult.shap_explanation.contributions.length > 0 ? (
                    simResult.shap_explanation.contributions.slice(0, 6).map((c, i) => (
                      <div
                        key={i}
                        style={{
                          background: 'rgba(15, 23, 42, 0.6)',
                          padding: '8px 12px',
                          borderRadius: '6px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          fontSize: '0.78rem',
                          border: '1px solid rgba(255, 255, 255, 0.05)'
                        }}
                      >
                        <div style={{ color: '#F8FAFC', fontWeight: '500' }}>
                          {c.display_name} <span style={{ color: '#64748B' }}>({c.value})</span>
                        </div>
                        <div style={{
                          fontWeight: '700',
                          color: c.contribution > 0 ? '#EF4444' : '#10B981',
                          fontFamily: 'monospace'
                        }}>
                          {c.contribution > 0 ? `+${(c.contribution || 0).toFixed(4)} (Phish)` : `${(c.contribution || 0).toFixed(4)} (Safe)`}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div style={{ color: '#94A3B8', fontSize: '0.78rem' }}>Baseline parameters aligned.</div>
                  )}
                </div>
              </div>

              {/* Explanatory takeaway */}
              <div style={{
                background: 'rgba(56, 189, 248, 0.08)',
                border: '1px solid rgba(56, 189, 248, 0.2)',
                padding: '10px 14px',
                borderRadius: '8px',
                fontSize: '0.76rem',
                color: '#94A3B8',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <Info size={16} color="#38BDF8" style={{ flexShrink: 0 }} />
                <span>
                  Counterfactual explanation demonstrates which specific features flip the prediction boundary from Legitimate to Phishing.
                </span>
              </div>
            </>
          ) : (
            <div style={{ color: '#94A3B8', fontSize: '0.8rem', padding: '20px', textAlign: 'center' }}>
              Adjust sliders to begin counterfactual simulation.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
