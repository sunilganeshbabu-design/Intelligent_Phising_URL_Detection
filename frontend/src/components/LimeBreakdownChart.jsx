import React from 'react';
import { Cpu, CheckCircle2, XCircle } from 'lucide-react';

const LimeBreakdownChart = ({ limeExplanation }) => {
  if (!limeExplanation || !limeExplanation.contributions || limeExplanation.contributions.length === 0) {
    return (
      <div style={{ padding: '20px', color: '#94A3B8', textAlign: 'center' }}>
        No LIME local surrogate explanation available for this scan.
      </div>
    );
  }

  const { contributions, summary_text } = limeExplanation;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* LIME Banner */}
      <div style={{
        background: 'rgba(139, 92, 246, 0.06)',
        border: '1px solid rgba(139, 92, 246, 0.2)',
        borderRadius: '12px',
        padding: '14px 18px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '12px'
      }}>
        <Cpu size={20} color="#8B5CF6" style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <div style={{ fontSize: '0.86rem', fontWeight: '600', color: '#A78BFA', marginBottom: '2px' }}>
            LIME (Local Interpretable Model-agnostic Explanations)
          </div>
          <div style={{ fontSize: '0.82rem', color: '#CBD5E1', lineHeight: '1.4' }}>
            {summary_text}
          </div>
        </div>
      </div>

      {/* LIME Rules Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '10px' }}>
        {contributions.slice(0, 6).map((c, idx) => {
          const isPhish = c.contribution > 0;
          return (
            <div
              key={idx}
              style={{
                background: 'rgba(15, 23, 42, 0.6)',
                border: `1px solid ${isPhish ? 'rgba(239, 68, 68, 0.25)' : 'rgba(16, 185, 129, 0.25)'}`,
                borderRadius: '10px',
                padding: '12px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {isPhish ? (
                    <XCircle size={16} color="#EF4444" />
                  ) : (
                    <CheckCircle2 size={16} color="#10B981" />
                  )}
                  <span style={{ fontSize: '0.85rem', fontWeight: '600', color: '#F8FAFC' }}>
                    {c.display_name}
                  </span>
                </div>
                <span style={{
                  fontSize: '0.8rem',
                  fontWeight: '700',
                  color: isPhish ? '#EF4444' : '#10B981',
                  fontFamily: 'monospace'
                }}>
                  {c.contribution > 0 ? `+${c.contribution.toFixed(3)}` : c.contribution.toFixed(3)}
                </span>
              </div>
              <div style={{ fontSize: '0.76rem', color: '#94A3B8' }}>
                {c.description}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default LimeBreakdownChart;
