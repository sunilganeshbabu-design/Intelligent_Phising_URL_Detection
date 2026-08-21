import React, { useState, useEffect } from 'react';
import { 
  History, Search, Trash2, Download, RefreshCw, 
  ShieldCheck, ShieldAlert, Globe, Mail, QrCode, 
  Shield, Layers, ExternalLink
} from 'lucide-react';
import { getScanHistory, deleteScan, clearAllHistory, getCsvExportUrl } from '../services/api';

const MODULE_TABS = [
  { id: 'all', label: 'All Modules', icon: Layers, desc: 'Complete system audit log' },
  { id: 'url', label: 'URL Scanner', icon: Globe, desc: 'Web URL predictions' },
  { id: 'email', label: 'Email Scanner', icon: Mail, desc: 'Email address threat scans' },
  { id: 'qr', label: 'QR Quishing', icon: QrCode, desc: 'QR code image decodes' },
  { id: 'threat_ioc', label: 'Threat IOC', icon: Shield, desc: 'Domain & IOC intelligence' }
];

export default function HistoryPage({ onInspectScan }) {
  const [historyData, setHistoryData] = useState({ total: 0, page: 1, page_size: 15, items: [] });
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [activeModule, setActiveModule] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await getScanHistory(currentPage, 15, search, filterType, activeModule);
      setHistoryData(data);
    } catch (err) {
      console.error('Failed to fetch scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [currentPage, filterType, activeModule]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setCurrentPage(1);
    fetchHistory();
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this scan record?')) return;
    try {
      await deleteScan(id);
      fetchHistory();
    } catch (err) {
      alert('Failed to delete scan: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleClearCategory = async () => {
    const label = activeModule === 'all' ? 'ALL history across all modules' : `all ${MODULE_TABS.find(t => t.id === activeModule)?.label} records`;
    if (!window.confirm(`Are you sure you want to clear ${label}? This action cannot be undone.`)) return;
    try {
      await clearAllHistory(activeModule);
      fetchHistory();
    } catch (err) {
      alert('Failed to clear history: ' + (err.response?.data?.detail || err.message));
    }
  };

  const getModuleIcon = (scanType) => {
    switch (scanType?.toLowerCase()) {
      case 'email':
        return <Mail size={14} color="#38BDF8" />;
      case 'qr':
        return <QrCode size={14} color="#F59E0B" />;
      case 'threat_ioc':
        return <Shield size={14} color="#8B5CF6" />;
      default:
        return <Globe size={14} color="#10B981" />;
    }
  };

  const getModuleBadge = (scanType) => {
    switch (scanType?.toLowerCase()) {
      case 'email':
        return { label: 'EMAIL', bg: 'rgba(56, 189, 248, 0.15)', text: '#38BDF8', border: 'rgba(56, 189, 248, 0.3)' };
      case 'qr':
        return { label: 'QR CODE', bg: 'rgba(245, 158, 11, 0.15)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.3)' };
      case 'threat_ioc':
        return { label: 'THREAT IOC', bg: 'rgba(139, 92, 246, 0.15)', text: '#A78BFA', border: 'rgba(139, 92, 246, 0.3)' };
      default:
        return { label: 'URL SCAN', bg: 'rgba(16, 185, 129, 0.15)', text: '#10B981', border: 'rgba(16, 185, 129, 0.3)' };
    }
  };

  const totalPages = Math.ceil(historyData.total / historyData.page_size) || 1;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1200px', margin: '0 auto', padding: '10px 20px 60px' }}>
      
      {/* Header & Global Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
        <div>
          <h1 style={{ fontSize: '1.65rem', fontWeight: '800', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <History size={26} color="#38BDF8" />
            Security Scan History & Audit Logs
          </h1>
          <p style={{ fontSize: '0.88rem', color: '#94A3B8', marginTop: '4px' }}>
            Search, filter, export, and review previous predictions across URL Scanner, Email Scanner, QR Quishing, and Threat IOC modules.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <a
            href={getCsvExportUrl()}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary"
            style={{ fontSize: '0.82rem', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Download size={15} />
            Export CSV
          </a>

          {historyData.total > 0 && (
            <button
              onClick={handleClearCategory}
              className="btn-danger"
              style={{ fontSize: '0.82rem', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: '6px' }}
              title="Clear scans in this category"
            >
              <Trash2 size={15} />
              {activeModule === 'all' ? 'Clear All History' : `Clear ${MODULE_TABS.find(t => t.id === activeModule)?.label}`}
            </button>
          )}
        </div>
      </div>

      {/* Module Category Filter Tabs */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        {MODULE_TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeModule === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => {
                setActiveModule(tab.id);
                setCurrentPage(1);
              }}
              style={{
                background: isActive ? 'linear-gradient(135deg, rgba(2, 132, 199, 0.25), rgba(56, 189, 248, 0.15))' : 'rgba(15, 23, 42, 0.6)',
                border: isActive ? '1px solid #38BDF8' : '1px solid rgba(255, 255, 255, 0.08)',
                color: isActive ? '#38BDF8' : '#94A3B8',
                padding: '10px 18px',
                borderRadius: '10px',
                fontSize: '0.86rem',
                fontWeight: isActive ? '700' : '500',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                transition: 'all 0.2s ease',
                boxShadow: isActive ? '0 0 15px rgba(56, 189, 248, 0.2)' : 'none'
              }}
            >
              <Icon size={16} color={isActive ? '#38BDF8' : '#94A3B8'} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel" style={{ padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        {/* Search Input */}
        <form onSubmit={handleSearchSubmit} style={{ position: 'relative', flex: 1, minWidth: '260px' }}>
          <Search size={16} color="#64748B" style={{ position: 'absolute', left: '12px', top: '11px' }} />
          <input
            type="text"
            placeholder="Search target email, domain, URL, or IOC indicator..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              background: 'rgba(7, 11, 20, 0.8)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '8px',
              padding: '8px 12px 8px 36px',
              color: '#F8FAFC',
              fontSize: '0.86rem',
              outline: 'none'
            }}
          />
        </form>

        {/* Verdict Filter Buttons */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {['all', 'Phishing', 'Legitimate'].map((type) => (
            <button
              key={type}
              onClick={() => {
                setFilterType(type);
                setCurrentPage(1);
              }}
              style={{
                background: filterType === type ? 'rgba(56, 189, 248, 0.15)' : 'rgba(30, 41, 59, 0.6)',
                border: filterType === type ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid rgba(255, 255, 255, 0.06)',
                color: filterType === type ? '#38BDF8' : '#94A3B8',
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '0.82rem',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              {type === 'all' ? 'All Verdicts' : type}
            </button>
          ))}
        </div>
      </div>

      {/* History Table */}
      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '48px', textAlign: 'center', color: '#94A3B8' }}>
            <RefreshCw size={26} className="animate-spin" style={{ margin: '0 auto 10px' }} />
            <span>Loading {MODULE_TABS.find(t => t.id === activeModule)?.label} records...</span>
          </div>
        ) : historyData.items.length === 0 ? (
          <div style={{ padding: '48px', textAlign: 'center', color: '#94A3B8' }}>
            <div style={{ fontSize: '1.8rem', marginBottom: '8px' }}>📂</div>
            <div style={{ fontWeight: '600', color: '#F8FAFC' }}>No scan records found</div>
            <div style={{ fontSize: '0.82rem', marginTop: '4px' }}>
              No history matching your selected filters for <strong>{MODULE_TABS.find(t => t.id === activeModule)?.label}</strong>.
            </div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.84rem' }}>
              <thead>
                <tr style={{ background: '#1E293B', color: '#94A3B8', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  <th style={{ padding: '12px 16px' }}>Target Artifact</th>
                  <th style={{ padding: '12px 16px' }}>Module Type</th>
                  <th style={{ padding: '12px 16px' }}>Verdict</th>
                  <th style={{ padding: '12px 16px' }}>Risk %</th>
                  <th style={{ padding: '12px 16px' }}>Detection Engine</th>
                  <th style={{ padding: '12px 16px' }}>Timestamp</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {historyData.items.map((scan) => {
                  const isPhish = scan.prediction === 'Phishing';
                  const badge = getModuleBadge(scan.scan_type);
                  return (
                    <tr
                      key={scan.id}
                      style={{
                        borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                        transition: 'background 0.15s ease'
                      }}
                    >
                      {/* Target Artifact */}
                      <td style={{ padding: '12px 16px', maxWidth: '320px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {getModuleIcon(scan.scan_type)}
                          <div style={{ fontWeight: '600', color: '#F8FAFC', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {scan.domain || scan.url}
                          </div>
                        </div>
                        <div style={{ fontSize: '0.74rem', color: '#64748B', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingLeft: '22px' }}>
                          {scan.url}
                        </div>
                      </td>

                      {/* Module Badge */}
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{
                          background: badge.bg,
                          color: badge.text,
                          border: `1px solid ${badge.border}`,
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '0.68rem',
                          fontWeight: '800',
                          letterSpacing: '0.04em'
                        }}>
                          {badge.label}
                        </span>
                      </td>

                      {/* Verdict */}
                      <td style={{ padding: '12px 16px' }}>
                        <span className={isPhish ? 'badge-phishing' : 'badge-legit'}>
                          {isPhish ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />}
                          {scan.prediction}
                        </span>
                      </td>

                      {/* Risk % */}
                      <td style={{ padding: '12px 16px', fontWeight: '700', color: isPhish ? '#EF4444' : '#10B981' }}>
                        {scan.phishing_probability.toFixed(1)}%
                      </td>

                      {/* Classifier Model */}
                      <td style={{ padding: '12px 16px', color: '#CBD5E1', fontSize: '0.8rem' }}>
                        {scan.model_name}
                      </td>

                      {/* Scan Date */}
                      <td style={{ padding: '12px 16px', color: '#94A3B8', fontSize: '0.78rem' }}>
                        {new Date(scan.created_at).toLocaleString()}
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                          <button
                            onClick={() => onInspectScan && onInspectScan(scan.url)}
                            className="btn-secondary"
                            style={{ padding: '5px 10px', fontSize: '0.76rem' }}
                            title="Inspect in scanner"
                          >
                            <ExternalLink size={13} />
                            Inspect
                          </button>

                          <button
                            onClick={() => handleDelete(scan.id)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: '#64748B',
                              cursor: 'pointer',
                              padding: '5px',
                              borderRadius: '4px'
                            }}
                            title="Delete scan"
                          >
                            <Trash2 size={15} color="#EF4444" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div style={{
            padding: '12px 16px',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <span style={{ fontSize: '0.8rem', color: '#94A3B8' }}>
              Showing Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong> ({historyData.total} Total Scans)
            </span>

            <div style={{ display: 'flex', gap: '6px' }}>
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                className="btn-secondary"
                style={{ padding: '4px 10px', fontSize: '0.76rem' }}
              >
                Previous
              </button>

              <button
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage((p) => p + 1)}
                className="btn-secondary"
                style={{ padding: '4px 10px', fontSize: '0.76rem' }}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
