import React, { useState } from 'react';
import { Search } from 'lucide-react';

const FeatureTable = ({ features }) => {
  const [searchTerm, setSearchTerm] = useState('');

  if (!features) {
    return (
      <div style={{ padding: '20px', color: '#94A3B8', textAlign: 'center' }}>
        No feature extraction data available.
      </div>
    );
  }

  const items = [
    { key: 'url_length', label: 'URL Length', value: features.url_length, risk: features.url_length > 75, desc: 'Overall character count. Long URLs (>75 chars) frequently hide spoof parameters.' },
    { key: 'domain_length', label: 'Domain Length', value: features.domain_length, risk: features.domain_length > 25, desc: 'Character length of domain host.' },
    { key: 'path_length', label: 'Path Length', value: features.path_length, risk: features.path_length > 45, desc: 'Length of directory and query string.' },
    { key: 'subdomain_count', label: 'Subdomain Count', value: features.subdomain_count, risk: features.subdomain_count > 1, desc: 'Number of nested subdomains. Stacking (>1) mimics genuine brand domains.' },
    { key: 'https_status', label: 'HTTPS Protocol', value: features.https_status ? 'Active (Encrypted)' : 'Insecure (HTTP)', risk: !features.https_status, desc: 'HTTPS encryption status.' },
    { key: 'ip_address', label: 'Direct IP Host', value: features.ip_address ? 'Yes (Malicious Evasion)' : 'No (Domain Name)', risk: features.ip_address, desc: 'Host addressed via raw IP instead of DNS domain.' },
    { key: 'has_at_symbol', label: 'Contains @ Symbol', value: features.has_at_symbol ? 'Yes (Credential Trick)' : 'No', risk: features.has_at_symbol, desc: 'RFC-1738 user info symbol tricking browsers.' },
    { key: 'has_double_slash_redirect', label: 'Double Slash Redirect', value: features.has_double_slash_redirect ? 'Yes' : 'No', risk: features.has_double_slash_redirect, desc: 'Double slash in path used to redirect victims.' },
    { key: 'has_prefix_suffix', label: 'Prefix/Suffix Hyphen', value: features.has_prefix_suffix ? 'Yes' : 'No', risk: features.has_prefix_suffix, desc: 'Hyphens added to brand names (e.g. paypal-login).' },
    { key: 'is_shortened_url', label: 'URL Shortener Service', value: features.is_shortened_url ? 'Yes (bit.ly/tinyurl)' : 'No', risk: features.is_shortened_url, desc: 'Shortened URL concealing final destination.' },
    { key: 'suspicious_keywords', label: 'Suspicious Keywords Count', value: `${features.suspicious_keywords} found`, risk: features.suspicious_keywords > 0, desc: 'Matches for login, verify, banking, security words.' },
    { key: 'entropy', label: 'Shannon Entropy', value: `${features.entropy.toFixed(2)} bits`, risk: features.entropy > 4.2, desc: 'String randomness measure (>4.2 indicates DGA or obfuscated tokens).' },
    { key: 'tld_risk_score', label: 'TLD Risk Rating', value: `${(features.tld_risk_score * 100).toFixed(0)}%`, risk: features.tld_risk_score > 0.5, desc: 'Top-Level Domain abuse rating from Spamhaus/SURBL.' },
    { key: 'count_dots', label: 'Dot Count', value: features.count_dots, risk: features.count_dots > 3, desc: 'Total occurrences of "."' },
    { key: 'count_hyphens', label: 'Hyphen Count', value: features.count_hyphens, risk: features.count_hyphens > 2, desc: 'Total occurrences of "-"' },
    { key: 'count_slashes', label: 'Slash Count', value: features.count_slashes, risk: features.count_slashes > 4, desc: 'Hierarchy depth in URL path.' },
    { key: 'count_digits', label: 'Numeric Digits', value: features.count_digits, risk: features.count_digits > 10, desc: 'Digit count in URL parameters.' }
  ];

  const filtered = items.filter(
    (item) => item.label.toLowerCase().includes(searchTerm.toLowerCase()) ||
              String(item.value).toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Search Filter Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ fontSize: '0.9rem', color: '#94A3B8' }}>
          Extracted <strong>{items.length}</strong> lexical, structural, and network security metrics
        </div>
        <div style={{ position: 'relative', width: '220px' }}>
          <Search size={16} color="#64748B" style={{ position: 'absolute', left: '10px', top: '10px' }} />
          <input
            type="text"
            placeholder="Search features..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              background: 'rgba(15, 23, 42, 0.7)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '8px',
              padding: '7px 10px 7px 32px',
              color: '#F8FAFC',
              fontSize: '0.84rem',
              outline: 'none'
            }}
          />
        </div>
      </div>

      {/* Feature Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
        gap: '10px',
        maxHeight: '420px',
        overflowY: 'auto',
        paddingRight: '4px'
      }}>
        {filtered.map((item, idx) => (
          <div
            key={idx}
            style={{
              background: item.risk ? 'rgba(239, 68, 68, 0.08)' : 'var(--bg-card)',
              border: `1px solid ${item.risk ? 'rgba(239, 68, 68, 0.3)' : 'var(--border-subtle)'}`,
              borderRadius: '10px',
              padding: '12px',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.84rem', fontWeight: '600', color: 'var(--text-main)' }}>
                {item.label}
              </span>
              {item.risk ? (
                <span style={{
                  fontSize: '0.7rem',
                  background: 'rgba(239, 68, 68, 0.2)',
                  color: '#EF4444',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  fontWeight: '700'
                }}>
                  RISK FLAG
                </span>
              ) : (
                <span style={{
                  fontSize: '0.7rem',
                  background: 'rgba(16, 185, 129, 0.15)',
                  color: 'var(--accent-safe)',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  fontWeight: '600'
                }}>
                  NORMAL
                </span>
              )}
            </div>

            <div style={{
              fontSize: '1rem',
              fontWeight: '700',
              color: item.risk ? '#EF4444' : 'var(--accent-blue)',
              fontFamily: 'monospace'
            }}>
              {String(item.value)}
            </div>

            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px', lineHeight: '1.3' }}>
              {item.desc}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default FeatureTable;
