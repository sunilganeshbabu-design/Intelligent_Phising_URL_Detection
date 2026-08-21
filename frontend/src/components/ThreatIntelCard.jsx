import React from 'react';
import { ShieldAlert, ShieldCheck, Lock, Globe, AlertCircle, Server, Calendar, Link as LinkIcon, Radio } from 'lucide-react';

const ThreatIntelCard = ({ threatIntel }) => {
  if (!threatIntel) return null;

  const { 
    is_blacklisted, 
    ssl_valid, 
    ssl_issuer, 
    ssl_protocol,
    reputation_score, 
    threat_notes,
    dns_resolved_ip,
    dns_status,
    domain_age,
    registrar,
    realtime_dataset_source,
    is_authentic_authority,
    unshortened_url,
    http_status
  } = threatIntel;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* Real-Time Live Feed Banner if Blacklisted or Authentic */}
      {realtime_dataset_source && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: '10px',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          color: '#FCA5A5',
          fontSize: '0.85rem'
        }}>
          <ShieldAlert size={20} color="#EF4444" />
          <div>
            <strong>Real-Time Threat Feed Match:</strong> Listed in <strong style={{ color: '#F87171' }}>{realtime_dataset_source}</strong>.
          </div>
        </div>
      )}

      {is_authentic_authority && (
        <div style={{
          background: 'rgba(16, 185, 129, 0.12)',
          border: '1px solid rgba(16, 185, 129, 0.35)',
          borderRadius: '10px',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          color: '#86EFAC',
          fontSize: '0.85rem'
        }}>
          <ShieldCheck size={20} color="#10B981" />
          <div>
            <strong>Official Global Authority:</strong> Domain verified on Official Enterprise & Government Registry.
          </div>
        </div>
      )}

      {unshortened_url && (
        <div style={{
          background: 'rgba(56, 189, 248, 0.12)',
          border: '1px solid rgba(56, 189, 248, 0.35)',
          borderRadius: '10px',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          color: '#38BDF8',
          fontSize: '0.84rem'
        }}>
          <LinkIcon size={18} />
          <div>
            <strong>Live HTTP Redirect Unshortened:</strong> Target destination is <code style={{ color: '#F8FAFC' }}>{unshortened_url}</code> (HTTP {http_status || '200'}).
          </div>
        </div>
      )}

      {/* 4 Core Metrics Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '12px'
      }}>
        {/* Blacklist Status */}
        <div style={{
          background: is_blacklisted ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.08)',
          border: `1px solid ${is_blacklisted ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.25)'}`,
          borderRadius: '12px',
          padding: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          {is_blacklisted ? (
            <ShieldAlert size={26} color="#EF4444" />
          ) : (
            <ShieldCheck size={26} color="#10B981" />
          )}
          <div>
            <div style={{ fontSize: '0.72rem', color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Threat Intelligence
            </div>
            <div style={{ fontSize: '0.88rem', fontWeight: '700', color: is_blacklisted ? '#EF4444' : '#10B981' }}>
              {is_blacklisted ? 'CONFIRMED BLACKLISTED' : 'CLEAN / NO THREAT RECORD'}
            </div>
          </div>
        </div>

        {/* Reputation Score */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.6)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <Globe size={26} color="#38BDF8" />
          <div>
            <div style={{ fontSize: '0.72rem', color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Domain Reputation
            </div>
            <div style={{ fontSize: '1.15rem', fontWeight: '800', color: reputation_score >= 70 ? '#10B981' : (reputation_score >= 40 ? '#F59E0B' : '#EF4444') }}>
              {reputation_score.toFixed(0)} <span style={{ fontSize: '0.8rem', color: '#94A3B8' }}>/ 100</span>
            </div>
          </div>
        </div>

        {/* Live SSL Status */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.6)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <Lock size={26} color={ssl_valid ? '#10B981' : '#EF4444'} />
          <div>
            <div style={{ fontSize: '0.72rem', color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              SSL / TLS Encryption
            </div>
            <div style={{ fontSize: '0.84rem', fontWeight: '700', color: ssl_valid ? '#34D399' : '#F87171', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '160px' }} title={ssl_issuer}>
              {ssl_valid ? `${ssl_protocol || 'TLS'} (${ssl_issuer})` : 'Unencrypted / No SSL'}
            </div>
          </div>
        </div>

        {/* Live DNS & IP */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.6)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <Server size={26} color="#A78BFA" />
          <div>
            <div style={{ fontSize: '0.72rem', color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Live DNS Resolution
            </div>
            <div style={{ fontSize: '0.84rem', fontWeight: '700', color: '#F8FAFC', fontFamily: 'monospace' }}>
              {dns_resolved_ip || dns_status || 'Active Host'}
            </div>
          </div>
        </div>
      </div>

      {/* WHOIS Longevity & Registrar */}
      {domain_age && (
        <div style={{
          background: 'rgba(15, 23, 42, 0.6)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          borderRadius: '10px',
          padding: '12px 16px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '10px',
          fontSize: '0.82rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Calendar size={16} color="#38BDF8" />
            <span style={{ color: '#94A3B8' }}>WHOIS Age:</span>
            <strong style={{ color: '#F8FAFC' }}>{domain_age}</strong>
          </div>
          {registrar && (
            <div style={{ color: '#94A3B8' }}>
              Registrar: <strong style={{ color: '#CBD5E1' }}>{registrar}</strong>
            </div>
          )}
        </div>
      )}

      {/* Threat Notes List */}
      {threat_notes && threat_notes.length > 0 && (
        <div style={{
          background: 'rgba(15, 23, 42, 0.5)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          borderRadius: '12px',
          padding: '16px 20px'
        }}>
          <div style={{ fontSize: '0.86rem', fontWeight: '700', color: '#F8FAFC', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Radio size={16} color="#38BDF8" className="animate-pulse" />
            Live Forensic Probing & Threat Telemetry Findings:
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {threat_notes.map((note, idx) => (
              <div key={idx} style={{ fontSize: '0.82rem', color: '#CBD5E1', display: 'flex', alignItems: 'flex-start', gap: '8px', lineHeight: '1.4' }}>
                <span style={{ color: '#38BDF8', fontWeight: 'bold' }}>➔</span>
                <span>{note}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatIntelCard;
