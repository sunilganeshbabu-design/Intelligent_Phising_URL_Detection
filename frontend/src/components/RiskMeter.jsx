import React from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';

const RiskMeter = ({ probability = 0, riskLevel = 'Safe', confidence = 0, prediction = 'Legitimate' }) => {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  // Map 0-100% to strokeDashoffset
  const strokeDashoffset = circumference - (probability / 100) * circumference;

  const getColor = () => {
    if (probability >= 80) return { stroke: '#EF4444', glow: 'rgba(239, 68, 68, 0.4)', text: 'text-red-500' };
    if (probability >= 50) return { stroke: '#F59E0B', glow: 'rgba(245, 158, 11, 0.4)', text: 'text-amber-500' };
    if (probability >= 25) return { stroke: '#38BDF8', glow: 'rgba(56, 189, 248, 0.4)', text: 'text-sky-400' };
    return { stroke: '#10B981', glow: 'rgba(16, 185, 129, 0.4)', text: 'text-emerald-400' };
  };

  const theme = getColor();
  const isPhishing = prediction === 'Phishing';

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px',
      position: 'relative'
    }}>
      <div style={{ position: 'relative', width: '180px', height: '180px' }}>
        <svg width="180" height="180" viewBox="0 0 180 180" style={{ transform: 'rotate(-90deg)' }}>
          {/* Background circle */}
          <circle
            cx="90"
            cy="90"
            r={radius}
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth="12"
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx="90"
            cy="90"
            r={radius}
            stroke={theme.stroke}
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              transition: 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)',
              filter: `drop-shadow(0 0 8px ${theme.glow})`
            }}
          />
        </svg>

        {/* Center Text Readout */}
        <div style={{
          position: 'absolute',
          top: 0, left: 0, right: 0, bottom: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          {isPhishing ? (
            <ShieldAlert size={28} color="#EF4444" style={{ marginBottom: '4px' }} />
          ) : (
            <ShieldCheck size={28} color="#10B981" style={{ marginBottom: '4px' }} />
          )}
          <span style={{ fontSize: '1.85rem', fontWeight: '800', color: theme.stroke, lineHeight: 1 }}>
            {probability.toFixed(1)}%
          </span>
          <span style={{ fontSize: '0.72rem', color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: '4px' }}>
            Phishing Risk
          </span>
        </div>
      </div>

      {/* Status Tags */}
      <div style={{ marginTop: '16px', textAlign: 'center' }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '6px 16px',
          borderRadius: '9999px',
          background: isPhishing ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
          border: `1px solid ${isPhishing ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
          color: isPhishing ? '#F87171' : '#34D399',
          fontWeight: '700',
          fontSize: '0.9rem',
          letterSpacing: '0.05em'
        }}>
          {isPhishing ? '⚠️ PHISHING DETECTED' : '🛡️ LEGITIMATE / SAFE'}
        </div>
        <div style={{ fontSize: '0.8rem', color: '#94A3B8', marginTop: '8px' }}>
          Threat Level: <strong style={{ color: theme.stroke }}>{riskLevel}</strong> • Model Confidence: <strong style={{ color: '#F8FAFC' }}>{confidence.toFixed(1)}%</strong>
        </div>
      </div>
    </div>
  );
};

export default RiskMeter;
