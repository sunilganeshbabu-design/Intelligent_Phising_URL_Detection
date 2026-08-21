import React, { useState } from 'react';
import { X, UploadCloud, Layers, Download, RefreshCw, Cpu } from 'lucide-react';
import { predictBulkUrls } from '../services/api';

const BulkScannerModal = ({ isOpen, onClose }) => {
  const [inputText, setInputText] = useState('');
  const [modelName, setModelName] = useState('XGBoost');
  const [loading, setLoading] = useState(false);
  const [bulkResponse, setBulkResponse] = useState(null);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleBulkScan = async () => {
    const urls = inputText
      .split('\n')
      .map((u) => u.trim())
      .filter((u) => u.length > 0);

    if (urls.length === 0) {
      setError('Please paste at least one valid URL.');
      return;
    }

    if (urls.length > 100) {
      setError('Maximum 100 URLs per batch allowed.');
      return;
    }

    setError('');
    setLoading(true);
    try {
      const data = await predictBulkUrls(urls, modelName);
      setBulkResponse(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Bulk scanning failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSampleBatch = () => {
    const samples = [
      'https://www.google.com',
      'http://192.168.1.100/login/bankofamerica-auth.php?token=928103',
      'https://github.com/torvalds/linux',
      'http://paypal-security-update.account-verify.xyz/signin.php',
      'https://en.wikipedia.org/wiki/Computer_security',
      'http://appleid-support-validation.login-portal.top/recover',
      'https://www.microsoft.com',
      'http://netflix-billing-resolve-account.buzz/verify',
      'http://google.com@chase-urgent-alert.tk/auth'
    ];
    setInputText(samples.join('\n'));
  };

  const handleDownloadCsv = () => {
    if (!bulkResponse) return;
    const headers = 'URL,Domain,Prediction,Phishing Probability (%),Risk Level,Key Factors\n';
    const rows = bulkResponse.results
      .map((r) => `"${r.url}","${r.domain}","${r.prediction}",${r.phishing_probability},"${r.risk_level}","${r.key_factors.join('; ')}"`)
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bulk_scan_results_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(3, 7, 18, 0.85)',
      backdropFilter: 'blur(10px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '20px'
    }}>
      <div className="glass-panel" style={{
        width: '100%',
        maxWidth: '850px',
        maxHeight: '90vh',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)'
      }}>
        {/* Modal Header */}
        <div style={{
          padding: '18px 24px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Layers size={22} color="#38BDF8" />
            <h2 style={{ fontSize: '1.2rem', fontWeight: '700', color: '#F8FAFC' }}>
              Bulk Phishing URL Analyzer
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94A3B8',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '6px'
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: '24px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {!bulkResponse ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.86rem', color: '#CBD5E1' }}>
                  Paste multiple URLs (one per line, up to 100 URLs):
                </span>
                <button
                  onClick={handleSampleBatch}
                  className="btn-secondary"
                  style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                >
                  Load Sample Batch
                </button>
              </div>

              <textarea
                rows={8}
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="https://example1.com&#10;http://phishing-site.xyz/login&#10;https://example2.org/secure"
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 20, 0.8)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '10px',
                  padding: '12px',
                  color: '#F8FAFC',
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  resize: 'vertical',
                  outline: 'none'
                }}
              />

              {error && (
                <div style={{ color: '#EF4444', fontSize: '0.85rem' }}>
                  ⚠️ {error}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '0.82rem', color: '#94A3B8' }}>Model:</span>
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                      background: 'rgba(30, 41, 59, 0.8)',
                      color: '#38BDF8',
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                      borderRadius: '6px',
                      padding: '5px 10px',
                      fontSize: '0.82rem',
                      fontWeight: '600'
                    }}
                  >
                    <Cpu size={14} color="#38BDF8" />
                    XGBoost model
                  </span>
                </div>

                <button
                  onClick={handleBulkScan}
                  disabled={loading}
                  className="btn-primary"
                  style={{ minWidth: '160px', justifyContent: 'center' }}
                >
                  {loading ? (
                    <>
                      <RefreshCw size={16} className="animate-spin" />
                      Analyzing Batch...
                    </>
                  ) : (
                    <>
                      <UploadCloud size={16} />
                      Run Bulk Analysis
                    </>
                  )}
                </button>
              </div>
            </>
          ) : (
            /* Results View */
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Metric Highlights */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(4, 1fr)',
                gap: '12px'
              }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.72rem', color: '#94A3B8' }}>TOTAL PROCESSED</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: '800', color: '#38BDF8' }}>{bulkResponse.total_processed}</div>
                </div>
                <div style={{ background: 'rgba(239, 68, 68, 0.1)', padding: '12px', borderRadius: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.72rem', color: '#F87171' }}>PHISHING DETECTED</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: '800', color: '#EF4444' }}>{bulkResponse.phishing_count}</div>
                </div>
                <div style={{ background: 'rgba(16, 185, 129, 0.1)', padding: '12px', borderRadius: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.72rem', color: '#34D399' }}>LEGITIMATE / SAFE</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: '800', color: '#10B981' }}>{bulkResponse.legitimate_count}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.72rem', color: '#94A3B8' }}>AVERAGE RISK</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: '800', color: '#F59E0B' }}>{bulkResponse.average_risk}%</div>
                </div>
              </div>

              {/* Table of Scans */}
              <div style={{
                maxHeight: '340px',
                overflowY: 'auto',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '8px'
              }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                  <thead>
                    <tr style={{ background: '#1E293B', color: '#94A3B8', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                      <th style={{ padding: '10px' }}>Target URL</th>
                      <th style={{ padding: '10px' }}>Verdict</th>
                      <th style={{ padding: '10px' }}>Risk %</th>
                      <th style={{ padding: '10px' }}>Key Risk Factor</th>
                    </tr>
                  </thead>
                  <tbody>
                    {bulkResponse.results.map((r, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)', background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)' }}>
                        <td style={{ padding: '10px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>
                          {r.url}
                        </td>
                        <td style={{ padding: '10px' }}>
                          <span className={r.prediction === 'Phishing' ? 'badge-phishing' : 'badge-legit'}>
                            {r.prediction}
                          </span>
                        </td>
                        <td style={{ padding: '10px', fontWeight: '700', color: r.phishing_probability >= 50 ? '#EF4444' : '#10B981' }}>
                          {r.phishing_probability.toFixed(1)}%
                        </td>
                        <td style={{ padding: '10px', color: '#94A3B8' }}>
                          {r.key_factors.join(', ')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Action Bar */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <button
                  onClick={() => setBulkResponse(null)}
                  className="btn-secondary"
                >
                  Scan Another Batch
                </button>

                <button
                  onClick={handleDownloadCsv}
                  className="btn-primary"
                >
                  <Download size={16} />
                  Export Results CSV
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default BulkScannerModal;
