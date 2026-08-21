import React, { useState, useEffect } from 'react';
import { FileText, Download, ShieldCheck, ShieldAlert, RefreshCw, FileCheck, CheckCircle2, AlertTriangle } from 'lucide-react';
import { getScanHistory, downloadScanPdf, downloadCsvReport } from '../services/api';

const ReportsPage = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);
  const [exportingCsv, setExportingCsv] = useState(false);
  const [notification, setNotification] = useState(null);

  const fetchRecentScans = async () => {
    setLoading(true);
    try {
      const data = await getScanHistory(1, 20);
      setScans(data.items);
    } catch (err) {
      console.error('Failed to load scans for reports:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadRow = async (scanId) => {
    setDownloadingId(scanId);
    setNotification(null);
    try {
      const filename = await downloadScanPdf(scanId);
      setNotification({
        type: 'success',
        message: `PDF Audit Report downloaded: ${filename}`
      });
      setTimeout(() => setNotification(null), 4000);
    } catch (err) {
      console.error('Download error:', err);
      setNotification({
        type: 'error',
        message: 'Failed to download report. Please try again.'
      });
      setTimeout(() => setNotification(null), 5000);
    } finally {
      setDownloadingId(null);
    }
  };

  const handleExportCsv = async () => {
    setExportingCsv(true);
    try {
      await downloadCsvReport();
      setNotification({
        type: 'success',
        message: 'CSV Audit Log exported successfully.'
      });
      setTimeout(() => setNotification(null), 4000);
    } catch (err) {
      console.error('CSV Export error:', err);
      setNotification({
        type: 'error',
        message: 'Failed to export CSV audit log.'
      });
      setTimeout(() => setNotification(null), 5000);
    } finally {
      setExportingCsv(false);
    }
  };

  useEffect(() => {
    fetchRecentScans();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px', maxWidth: '1200px', margin: '0 auto', padding: '10px 20px 60px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
        <div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: '800', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileText size={24} color="#38BDF8" />
            Security Reports & Audit Center
          </h1>
          <p style={{ fontSize: '0.88rem', color: '#94A3B8', marginTop: '4px' }}>
            Generate, download, and export executive-ready PDF cybersecurity audit reports.
          </p>
        </div>

        <button
          onClick={handleExportCsv}
          disabled={exportingCsv}
          className="btn-primary"
          style={{ fontSize: '0.84rem' }}
        >
          <Download size={16} />
          {exportingCsv ? 'Exporting CSV...' : 'Export Complete CSV Audit Log'}
        </button>
      </div>

      {/* Report Info Banner */}
      <div className="glass-panel" style={{
        padding: '24px',
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.7) 100%)',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{
            background: 'rgba(56, 189, 248, 0.15)',
            padding: '14px',
            borderRadius: '14px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <FileCheck size={32} color="#38BDF8" />
          </div>
          <div>
            <h2 style={{ fontSize: '1.15rem', fontWeight: '700', color: '#F8FAFC' }}>
              Automated PDF Audit Report Generator
            </h2>
            <p style={{ fontSize: '0.84rem', color: '#94A3B8', maxWidth: '650px', marginTop: '4px' }}>
              Every scan produces a formal compliance report containing risk badges, SHAP feature importance breakdowns, extracted lexical indicators, SSL certificates, and mitigation recommendations.
            </p>
          </div>
        </div>
      </div>

      {notification && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '12px 18px',
          borderRadius: '10px',
          fontSize: '0.85rem',
          fontWeight: '600',
          background: notification.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          border: `1px solid ${notification.type === 'success' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
          color: notification.type === 'success' ? '#34D399' : '#F87171',
          animation: 'fadeIn 0.2s ease-in-out'
        }}>
          {notification.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{notification.message}</span>
        </div>
      )}

      {/* Available Scan Reports List */}
      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: '0.96rem', fontWeight: '700', color: '#F8FAFC' }}>
            Available PDF Audit Reports for Recent Scans
          </h3>
          <button
            onClick={fetchRecentScans}
            className="btn-secondary"
            style={{ padding: '4px 10px', fontSize: '0.76rem' }}
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>

        {loading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#94A3B8' }}>
            <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 10px' }} />
            <span>Loading available reports...</span>
          </div>
        ) : scans.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#94A3B8' }}>
            No scans available yet. Run a URL scan on the Scanner page to generate reports.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.84rem' }}>
              <thead>
                <tr style={{ background: '#1E293B', color: '#94A3B8', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  <th style={{ padding: '12px 16px' }}>Report Target Domain</th>
                  <th style={{ padding: '12px 16px' }}>Detection Verdict</th>
                  <th style={{ padding: '12px 16px' }}>Risk Score</th>
                  <th style={{ padding: '12px 16px' }}>Scan Date</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>Download Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const isPhish = scan.prediction === 'Phishing';
                  const isDownloading = downloadingId === scan.id;
                  return (
                    <tr key={scan.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                      <td style={{ padding: '12px 16px', maxWidth: '300px' }}>
                        <div style={{ fontWeight: '600', color: '#F8FAFC', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {scan.domain || scan.url}
                        </div>
                        <div style={{ fontSize: '0.74rem', color: '#64748B', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {scan.url}
                        </div>
                      </td>

                      <td style={{ padding: '12px 16px' }}>
                        <span className={isPhish ? 'badge-phishing' : 'badge-legit'}>
                          {isPhish ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />}
                          {scan.prediction}
                        </span>
                      </td>

                      <td style={{ padding: '12px 16px', fontWeight: '700', color: isPhish ? '#EF4444' : '#10B981' }}>
                        {scan.phishing_probability.toFixed(1)}% ({scan.risk_level})
                      </td>

                      <td style={{ padding: '12px 16px', color: '#94A3B8', fontSize: '0.78rem' }}>
                        {new Date(scan.created_at).toLocaleString()}
                      </td>

                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <button
                          type="button"
                          onClick={() => handleDownloadRow(scan.id)}
                          disabled={isDownloading}
                          className="btn-primary"
                          style={{
                            padding: '6px 14px',
                            fontSize: '0.78rem',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '5px',
                            cursor: isDownloading ? 'wait' : 'pointer'
                          }}
                        >
                          {isDownloading ? (
                            <>
                              <RefreshCw size={13} className="animate-spin" />
                              <span>Generating...</span>
                            </>
                          ) : (
                            <>
                              <Download size={13} />
                              <span>Download PDF</span>
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default ReportsPage;
