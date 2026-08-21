import React from 'react';

const StatCard = ({ title, value, subtitle, icon: Icon, color = '#38BDF8', trend = null, progress = null, badge = null }) => {
  return (
    <div
      className="cyber-card"
      style={{
        padding: '22px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        position: 'relative',
        minHeight: '150px'
      }}
    >
      {/* Top Accent Neon Glow Line */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: '3px',
        background: `linear-gradient(90deg, transparent, ${color}, transparent)`,
        opacity: 0.85
      }} />

      {/* Radial Background Accent Glow */}
      <div style={{
        position: 'absolute',
        top: '-20px',
        right: '-20px',
        width: '90px',
        height: '90px',
        borderRadius: '50%',
        background: color,
        filter: 'blur(45px)',
        opacity: 0.22,
        pointerEvents: 'none'
      }} />

      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{
              fontSize: '0.74rem',
              color: '#94A3B8',
              fontWeight: '700',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              {title}
            </div>
            <div style={{
              fontSize: '2rem',
              fontWeight: '900',
              color: '#F8FAFC',
              marginTop: '6px',
              lineHeight: 1.1,
              fontFamily: 'Inter, sans-serif'
            }}>
              {value}
            </div>
          </div>

          {Icon && (
            <div style={{
              background: `linear-gradient(135deg, ${color}20, ${color}08)`,
              border: `1px solid ${color}45`,
              padding: '11px',
              borderRadius: '14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: `0 0 15px ${color}20`
            }}>
              <Icon size={22} color={color} />
            </div>
          )}
        </div>
      </div>

      {/* Progress Bar (Optional) */}
      {progress !== null && (
        <div style={{ marginTop: '12px' }}>
          <div style={{ width: '100%', height: '4px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden' }}>
            <div style={{ width: `${Math.min(100, Math.max(0, progress))}%`, height: '100%', background: color, borderRadius: '2px' }} />
          </div>
        </div>
      )}

      {/* Subtitle & Trend */}
      {(subtitle || badge) && (
        <div style={{
          fontSize: '0.76rem',
          color: '#94A3B8',
          marginTop: progress !== null ? '8px' : '14px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '6px'
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {trend && (
              <span style={{ color: color, fontWeight: '800' }}>
                {trend}
              </span>
            )}
            <span style={{ color: '#64748B' }}>{subtitle}</span>
          </span>

          {badge && (
            <span style={{
              background: `${color}18`,
              color: color,
              border: `1px solid ${color}40`,
              padding: '2px 7px',
              borderRadius: '4px',
              fontSize: '0.68rem',
              fontWeight: '800'
            }}>
              {badge}
            </span>
          )}
        </div>
      )}
    </div>
  );
};

export default StatCard;
