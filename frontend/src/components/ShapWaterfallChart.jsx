import React from 'react';
import { ArrowUpRight, ArrowDownRight, Info } from 'lucide-react';

const ShapWaterfallChart = ({ shapExplanation, shapData }) => {
  const explanation = shapExplanation || shapData;

  if (!explanation || !explanation.contributions || explanation.contributions.length === 0) {
    return (
      <div style={{ padding: '20px', color: '#94A3B8', textAlign: 'center' }}>
        No SHAP feature attribution data available for this scan.
      </div>
    );
  }

  const { base_value, prediction_score, contributions, summary_text } = explanation;
  const maxAbs = Math.max(...contributions.map((c) => Math.abs(c.contribution)), 0.1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* SHAP Explanation Summary Card */}
      <div style={{
        background: 'rgba(56, 189, 248, 0.06)',
        border: '1px solid rgba(56, 189, 248, 0.2)',
        borderRadius: '12px',
        padding: '14px 18px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '12px'
      }}>
        <Info size={20} color="#38BDF8" style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <div style={{ fontSize: '0.86rem', fontWeight: '600', color: '#38BDF8', marginBottom: '2px' }}>
            SHAP (SHapley Additive exPlanations) Decision Logic
          </div>
          <div style={{ fontSize: '0.82rem', color: '#CBD5E1', lineHeight: '1.4' }}>
            {summary_text}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '6px' }}>
            Baseline Expected Value (E[f(x)]): <strong>{(base_value * 100).toFixed(1)}%</strong> ➔ Final Prediction: <strong>{(prediction_score * 100).toFixed(1)}%</strong>
          </div>
        </div>
      </div>

      {/* Feature Contributions List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {contributions.slice(0, 8).map((feat, idx) => {
          const isPhishPush = feat.contribution > 0;
          const barWidth = `${Math.min((Math.abs(feat.contribution) / maxAbs) * 100, 100)}%`;
          const barColor = isPhishPush ? '#EF4444' : '#10B981';

          return (
            <div
              key={idx}
              style={{
                background: 'rgba(15, 23, 42, 0.6)',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                borderRadius: '10px',
                padding: '10px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                transition: 'all 0.2s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {isPhishPush ? (
                    <ArrowUpRight size={16} color="#EF4444" />
                  ) : (
                    <ArrowDownRight size={16} color="#10B981" />
                  )}
                  <span style={{ fontSize: '0.88rem', fontWeight: '600', color: '#F8FAFC' }}>
                    {feat.display_name}
                  </span>
                  <span style={{
                    fontSize: '0.74rem',
                    background: 'rgba(255, 255, 255, 0.08)',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    color: '#94A3B8',
                    fontFamily: 'monospace'
                  }}>
                    val: {String(feat.value)}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{
                    fontSize: '0.85rem',
                    fontWeight: '700',
                    color: barColor,
                    fontFamily: 'monospace'
                  }}>
                    {feat.contribution > 0 ? `+${feat.contribution.toFixed(3)}` : feat.contribution.toFixed(3)}
                  </span>
                </div>
              </div>

              {/* Progress Bar */}
              <div style={{
                height: '6px',
                background: 'rgba(255, 255, 255, 0.05)',
                borderRadius: '3px',
                overflow: 'hidden',
                position: 'relative'
              }}>
                <div
                  style={{
                    height: '100%',
                    width: barWidth,
                    backgroundColor: barColor,
                    borderRadius: '3px',
                    transition: 'width 0.8s ease-in-out'
                  }}
                />
              </div>

              {/* Context description */}
              {feat.description && (
                <div style={{ fontSize: '0.76rem', color: '#94A3B8', fontStyle: 'italic' }}>
                  {feat.description}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ShapWaterfallChart;
