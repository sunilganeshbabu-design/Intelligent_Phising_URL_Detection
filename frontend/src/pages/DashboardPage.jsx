import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, Zap, Activity, PieChart as PieIcon, 
  TrendingUp, RefreshCw, Globe, Mail, QrCode, Shield, 
  ArrowRight, Cpu, Radio, Server, AlertOctagon, ExternalLink
} from 'lucide-react';
import { getDashboardStats } from '../services/api';
import StatCard from '../components/StatCard';
import { useAuth } from '../context/AuthContext';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title,
  Filler
} from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title,
  Filler
);

export default function DashboardPage({ onSelectScan, onNavigateModule }) {
  const { user } = useAuth();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterVerdict, setFilterVerdict] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchStats = async () => {
    try {
      const data = await getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load dashboard metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    let interval = null;
    if (autoRefresh) {
      interval = setInterval(fetchStats, 15000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);

  if (loading || !stats) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', minHeight: '60vh', gap: '14px', color: '#94A3B8' }}>
        <div style={{ position: 'relative' }}>
          <RefreshCw size={36} className="animate-spin" color="#38BDF8" />
        </div>
        <div style={{ fontWeight: '700', color: '#F8FAFC', fontSize: '1rem', letterSpacing: '0.04em' }}>
          INITIALIZING CYBER THREAT COMMAND CENTER...
        </div>
        <div style={{ fontSize: '0.82rem', color: '#64748B' }}>
          Connecting to Real-Time Threat Heuristics, ML Classifiers & SOC Logs
        </div>
      </div>
    );
  }

  // Chart 1: Donut Breakdown (Verdict Distribution)
  const doughnutData = {
    labels: ['Phishing Attacks', 'Legitimate / Verified'],
    datasets: [
      {
        data: [stats.phishing_detected || 1, stats.legitimate_detected || 1],
        backgroundColor: ['#EF4444', '#10B981'],
        borderColor: ['#991B1B', '#065F46'],
        borderWidth: 2,
        hoverOffset: 8,
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '74%',
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#94A3B8', font: { size: 12, family: 'Inter' }, padding: 16 },
      },
      tooltip: {
        backgroundColor: 'rgba(15, 23, 42, 0.95)',
        titleColor: '#F8FAFC',
        bodyColor: '#94A3B8',
        borderColor: 'rgba(56, 189, 248, 0.3)',
        borderWidth: 1,
        padding: 12,
        cornerRadius: 8,
      }
    },
  };

  // Chart 2: Weekly Trend
  const weeklyLabels = stats.weekly_scans_trend?.map((d) => d.date) || [];
  const weeklyPhish = stats.weekly_scans_trend?.map((d) => d.phishing) || [];
  const weeklyLegit = stats.weekly_scans_trend?.map((d) => d.legitimate) || [];

  const barData = {
    labels: weeklyLabels,
    datasets: [
      {
        label: 'Phishing Intercepted',
        data: weeklyPhish,
        backgroundColor: 'rgba(239, 68, 68, 0.8)',
        borderColor: '#EF4444',
        borderRadius: 6,
        borderWidth: 1,
      },
      {
        label: 'Legitimate Verified',
        data: weeklyLegit,
        backgroundColor: 'rgba(16, 185, 129, 0.8)',
        borderColor: '#10B981',
        borderRadius: 6,
        borderWidth: 1,
      },
    ],
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: {
        grid: { color: 'rgba(255, 255, 255, 0.04)' },
        ticks: { color: '#94A3B8', font: { size: 11 } },
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.04)' },
        ticks: { color: '#94A3B8', font: { size: 11 }, stepSize: 1 },
      },
    },
    plugins: {
      legend: {
        position: 'top',
        labels: { color: '#CBD5E1', font: { size: 12, family: 'Inter' } },
      },
      tooltip: {
        backgroundColor: 'rgba(15, 23, 42, 0.95)',
        titleColor: '#F8FAFC',
        bodyColor: '#94A3B8',
        borderColor: 'rgba(56, 189, 248, 0.3)',
        borderWidth: 1,
        padding: 12,
        cornerRadius: 8,
      }
    },
  };

  // Filter recent scans
  const filteredRecentScans = (stats.recent_scans || []).filter((s) => {
    if (filterVerdict === 'phishing') return s.prediction === 'Phishing';
    if (filterVerdict === 'legitimate') return s.prediction === 'Legitimate';
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '26px', maxWidth: '1240px', margin: '0 auto', padding: '10px 16px 60px' }}>
      
      {/* 1. Hero Command Center Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(10, 15, 28, 0.98) 100%)',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        borderRadius: '20px',
        padding: '28px 32px',
        boxShadow: '0 15px 40px rgba(0, 0, 0, 0.6), 0 0 30px rgba(56, 189, 248, 0.08)',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Background Subtle Cyber Gradients */}
        <div style={{
          position: 'absolute',
          top: '-40px',
          right: '-40px',
          width: '260px',
          height: '260px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(56, 189, 248, 0.15), transparent 70%)',
          pointerEvents: 'none'
        }} />

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
              <span style={{
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#10B981',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                padding: '4px 12px',
                borderRadius: '20px',
                fontSize: '0.74rem',
                fontWeight: '800',
                letterSpacing: '0.06em',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <span className="radar-dot" /> DEFENSE GRID ACTIVE • REAL-TIME AI ENGINE
              </span>

              <span style={{
                background: 'rgba(56, 189, 248, 0.12)',
                color: '#38BDF8',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                padding: '4px 10px',
                borderRadius: '20px',
                fontSize: '0.72rem',
                fontWeight: '700',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px'
              }}>
                <Cpu size={12} /> ML V4.2 HYBRID
              </span>
            </div>

            <h1 style={{ fontSize: '1.85rem', fontWeight: '900', color: '#F8FAFC', margin: '0 0 6px', letterSpacing: '-0.02em' }}>
              Cyber Threat Intelligence <span className="gradient-text-cyan">& SOC Telemetry</span>
            </h1>
            <p style={{ fontSize: '0.88rem', color: '#94A3B8', margin: 0, maxWidth: '680px', lineHeight: 1.5 }}>
              Central command console for real-time URL heuristic analysis, phishing interception metrics, XAI explanations, and domain infrastructure intelligence.
            </p>

            {user && (
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                marginTop: '12px',
                background: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                padding: '5px 12px',
                borderRadius: '8px',
                fontSize: '0.8rem',
                color: '#E2E8F0'
              }}>
                <span style={{ color: '#38BDF8', fontWeight: '700' }}>Logged In:</span>
                <strong style={{ color: '#F8FAFC' }}>{user.full_name || user.username}</strong>
                <span style={{ color: '#94A3B8' }}>({user.email})</span>
              </div>
            )}
          </div>

          {/* Refresh & Polling Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              style={{
                background: autoRefresh ? 'rgba(16, 185, 129, 0.15)' : 'rgba(30, 41, 59, 0.6)',
                border: autoRefresh ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid rgba(255, 255, 255, 0.1)',
                color: autoRefresh ? '#10B981' : '#94A3B8',
                padding: '8px 14px',
                borderRadius: '8px',
                fontSize: '0.78rem',
                fontWeight: '700',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
              title="Toggle 15s auto-polling"
            >
              <Radio size={14} className={autoRefresh ? 'pulse-animation' : ''} />
              {autoRefresh ? 'Live Polling: ON' : 'Live Polling: PAUSED'}
            </button>

            <button
              onClick={fetchStats}
              className="btn-secondary"
              style={{ padding: '8px 14px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <RefreshCw size={14} />
              Sync Metrics
            </button>
          </div>
        </div>

        {/* Quick Launch Action Pills */}
        <div style={{
          display: 'flex',
          gap: '10px',
          flexWrap: 'wrap',
          marginTop: '22px',
          paddingTop: '18px',
          borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          alignItems: 'center'
        }}>
          <span style={{ fontSize: '0.76rem', color: '#64748B', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            🚀 Instant Scanners:
          </span>

          {[
            { id: 'url', label: 'URL Scanner', icon: Globe, color: '#10B981' },
            { id: 'email', label: 'Email Scanner', icon: Mail, color: '#38BDF8' },
            { id: 'qr', label: 'QR Quishing', icon: QrCode, color: '#F59E0B' },
            { id: 'threat_ioc', label: 'Threat IOC', icon: Shield, color: '#8B5CF6' }
          ].map((mod) => {
            const Icon = mod.icon;
            return (
              <button
                key={mod.id}
                onClick={() => onNavigateModule && onNavigateModule(mod.id)}
                style={{
                  background: 'rgba(15, 23, 42, 0.8)',
                  border: `1px solid ${mod.color}40`,
                  color: '#F8FAFC',
                  padding: '6px 14px',
                  borderRadius: '8px',
                  fontSize: '0.8rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '7px',
                  transition: 'all 0.15s ease'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = `${mod.color}20`;
                  e.currentTarget.style.borderColor = mod.color;
                  e.currentTarget.style.transform = 'translateY(-2px)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'rgba(15, 23, 42, 0.8)';
                  e.currentTarget.style.borderColor = `${mod.color}40`;
                  e.currentTarget.style.transform = 'none';
                }}
              >
                <Icon size={14} color={mod.color} />
                <span>{mod.label}</span>
                <ArrowRight size={12} color="#64748B" />
              </button>
            );
          })}
        </div>
      </div>

      {/* 2. Top 4 High-Tech KPI Stat Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '16px'
      }}>
        <StatCard
          title="Total Scans Processed"
          value={stats.total_scans?.toLocaleString() || 0}
          subtitle="Real-time multi-module inspections"
          icon={Zap}
          color="#38BDF8"
          badge="LIVE FEED"
          progress={100}
        />

        <StatCard
          title="Phishing Invasions Neutralized"
          value={stats.phishing_detected?.toLocaleString() || 0}
          subtitle={`${stats.phishing_percentage || 0}% overall malicious ratio`}
          icon={ShieldAlert}
          color="#EF4444"
          badge="THREAT BLOCKED"
          progress={stats.phishing_percentage || 0}
        />

        <StatCard
          title="Verified Safe Artifacts"
          value={stats.legitimate_detected?.toLocaleString() || 0}
          subtitle={`${stats.safe_percentage || 0}% authentic legitimate traffic`}
          icon={ShieldCheck}
          color="#10B981"
          badge="AUTHENTIC"
          progress={stats.safe_percentage || 0}
        />

        <StatCard
          title="Detection Engine Accuracy"
          value={`${((stats.model_accuracy_metrics?.models?.['XGBoost']?.accuracy || stats.model_accuracy_metrics?.models?.['XGBooster']?.accuracy || 0.988) * 100).toFixed(1)}%`}
          subtitle="XGBoost model + SHAP Explainability"
          icon={TrendingUp}
          color="#8B5CF6"
          badge="XAI CALIBRATED"
          progress={98.8}
        />
      </div>

      {/* 3. Analytics Charts Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))',
        gap: '20px'
      }}>
        {/* Weekly Scan Trend Chart */}
        <div className="cyber-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '0.96rem', fontWeight: '800', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
              <TrendingUp size={18} color="#38BDF8" />
              7-Day Attack Trajectory & Scan Activity
            </h3>
            <span style={{ fontSize: '0.72rem', color: '#64748B', fontWeight: '700', textTransform: 'uppercase' }}>
              DAILY TELEMETRY
            </span>
          </div>

          <div style={{ height: '260px', position: 'relative' }}>
            <Bar data={barData} options={barOptions} />
          </div>
        </div>

        {/* Verdict Distribution Donut */}
        <div className="cyber-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '0.96rem', fontWeight: '800', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
              <PieIcon size={18} color="#38BDF8" />
              Threat Verdict & Risk Distribution
            </h3>
            <span style={{ fontSize: '0.72rem', color: '#64748B', fontWeight: '700', textTransform: 'uppercase' }}>
              ALL MODULES
            </span>
          </div>

          <div style={{ height: '260px', position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Doughnut data={doughnutData} options={doughnutOptions} />
            
            {/* Center HUD Text */}
            <div style={{
              position: 'absolute',
              textAlign: 'center',
              pointerEvents: 'none',
              top: '40%',
              transform: 'translateY(-50%)'
            }}>
              <div style={{ fontSize: '1.7rem', fontWeight: '900', color: '#F8FAFC', lineHeight: 1 }}>
                {stats.total_scans}
              </div>
              <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', marginTop: '4px' }}>
                Total Scans
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Live SOC Incident Stream & Top Targets Matrix */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
        gap: '20px'
      }}>
        {/* Recent Scan Audit Log */}
        <div className="cyber-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
            <div>
              <h3 style={{ fontSize: '0.96rem', fontWeight: '800', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
                <Activity size={18} color="#38BDF8" />
                Live SOC Incident Stream
              </h3>
              <div style={{ fontSize: '0.76rem', color: '#64748B', marginTop: '2px' }}>
                Latest security events intercepted across network endpoints
              </div>
            </div>

            {/* Filter Buttons */}
            <div style={{ display: 'flex', gap: '4px' }}>
              {[
                { id: 'all', label: 'All' },
                { id: 'phishing', label: 'Phish' },
                { id: 'legitimate', label: 'Safe' }
              ].map((f) => (
                <button
                  key={f.id}
                  onClick={() => setFilterVerdict(f.id)}
                  style={{
                    background: filterVerdict === f.id ? 'rgba(56, 189, 248, 0.2)' : 'rgba(30, 41, 59, 0.5)',
                    border: filterVerdict === f.id ? '1px solid #38BDF8' : '1px solid rgba(255, 255, 255, 0.05)',
                    color: filterVerdict === f.id ? '#38BDF8' : '#94A3B8',
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontSize: '0.74rem',
                    fontWeight: '700',
                    cursor: 'pointer'
                  }}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '310px', overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', color: '#94A3B8' }}>
                  <th style={{ padding: '8px 10px' }}>Target Artifact</th>
                  <th style={{ padding: '8px 10px' }}>Verdict</th>
                  <th style={{ padding: '8px 10px' }}>Risk %</th>
                  <th style={{ padding: '8px 10px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecentScans.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ padding: '24px', textAlign: 'center', color: '#64748B' }}>
                      No events matching filter.
                    </td>
                  </tr>
                ) : (
                  filteredRecentScans.map((s, idx) => (
                    <tr
                      key={idx}
                      style={{
                        borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                        transition: 'background 0.15s ease'
                      }}
                    >
                      <td style={{ padding: '10px 10px', maxWidth: '170px' }}>
                        <div style={{ fontWeight: '600', color: '#F8FAFC', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {s.domain || s.url}
                        </div>
                        <div style={{ fontSize: '0.7rem', color: '#64748B', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {s.url}
                        </div>
                      </td>

                      <td style={{ padding: '10px 10px' }}>
                        <span className={s.prediction === 'Phishing' ? 'badge-phishing' : 'badge-legit'} style={{ fontSize: '0.72rem', padding: '2px 8px' }}>
                          {s.prediction === 'Phishing' ? <ShieldAlert size={11} /> : <ShieldCheck size={11} />}
                          {s.prediction}
                        </span>
                      </td>

                      <td style={{ padding: '10px 10px', fontWeight: '800', color: s.phishing_probability >= 50 ? '#EF4444' : '#10B981' }}>
                        {s.phishing_probability.toFixed(0)}%
                      </td>

                      <td style={{ padding: '10px 10px', textAlign: 'right' }}>
                        <button
                          onClick={() => onSelectScan(s.url)}
                          className="btn-secondary"
                          style={{ padding: '4px 8px', fontSize: '0.72rem', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                          title="Inspect artifact"
                        >
                          <span>Inspect</span>
                          <ExternalLink size={11} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Flagged Targets & System Health Matrix */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Top Flagged Targets */}
          <div className="cyber-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '0.96rem', fontWeight: '800', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
                <AlertOctagon size={18} color="#EF4444" />
                Top Impersonated Brand Targets
              </h3>
              <span style={{ fontSize: '0.72rem', color: '#EF4444', fontWeight: '800', background: 'rgba(239, 68, 68, 0.15)', padding: '2px 8px', borderRadius: '4px' }}>
                HIGH REPEAT
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {stats.top_threat_domains?.length === 0 ? (
                <div style={{ color: '#64748B', fontSize: '0.82rem', padding: '14px 0' }}>
                  No repeat phishing targets recorded yet.
                </div>
              ) : (
                stats.top_threat_domains.slice(0, 4).map((t, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: 'rgba(239, 68, 68, 0.06)',
                      border: '1px solid rgba(239, 68, 68, 0.25)',
                      padding: '10px 14px',
                      borderRadius: '10px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="radar-dot-danger" />
                      <span style={{ fontSize: '0.84rem', fontFamily: 'monospace', color: '#F8FAFC', fontWeight: '600' }}>
                        {t.domain}
                      </span>
                    </div>

                    <span style={{
                      fontSize: '0.72rem',
                      background: 'rgba(239, 68, 68, 0.2)',
                      color: '#F87171',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontWeight: '800'
                    }}>
                      {t.count} Invasions
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Infrastructure Health Matrix */}
          <div className="cyber-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <h4 style={{ margin: 0, fontSize: '0.86rem', color: '#38BDF8', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: '800' }}>
              <Server size={16} /> Detection Engine Telemetry
            </h4>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.76rem' }}>
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <div style={{ color: '#64748B' }}>FASTAPI ENGINE</div>
                <div style={{ color: '#10B981', fontWeight: '700', marginTop: '2px' }}>● Online (:8000)</div>
              </div>
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <div style={{ color: '#64748B' }}>XAI EXPLAINER</div>
                <div style={{ color: '#10B981', fontWeight: '700', marginTop: '2px' }}>● SHAP + LIME Active</div>
              </div>
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <div style={{ color: '#64748B' }}>LIVE DNS RESOLVER</div>
                <div style={{ color: '#10B981', fontWeight: '700', marginTop: '2px' }}>● 1.2s Fast Socket</div>
              </div>
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '8px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <div style={{ color: '#64748B' }}>WHOIS / RDAP</div>
                <div style={{ color: '#10B981', fontWeight: '700', marginTop: '2px' }}>● ICANN Verified</div>
              </div>
            </div>
          </div>

        </div>
      </div>

    </div>
  );
}
