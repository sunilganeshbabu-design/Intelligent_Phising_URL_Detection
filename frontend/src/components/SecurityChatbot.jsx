import React, { useState, useRef, useEffect } from 'react';
import { 
  X, Send, Bot, User, Sparkles, Maximize2, Minimize2, 
  RotateCcw, Copy, Check, ChevronRight, HelpCircle, ShieldCheck,
  Flame, Lock, Cpu, Globe, AlertTriangle
} from 'lucide-react';
import { querySecurityChatbot } from '../services/api';

const DEFAULT_RECOMMENDATIONS = [
  'What is phishing?',
  'How does phishing URL detection work?',
  'Is my current URL safe?',
  'Why was this URL classified as phishing?',
  'Why was this URL classified as legitimate?',
  'What does the confidence score mean?',
  'What is SHAP?',
  'What is LIME?',
  'Which features made this URL suspicious?',
  'Explain the 10 detection modules.',
  'How can I identify a phishing URL?',
  'What should I do if I clicked a phishing link?',
  'How can I protect myself from phishing?',
  'What is the difference between phishing and malware?',
  'How does machine learning detect phishing URLs?'
];

const CATEGORY_PROMPTS = [
  {
    category: '🔥 Popular',
    icon: Flame,
    prompts: [
      'What is phishing?',
      'How does phishing URL detection work?',
      'Is my current URL safe?',
      'Explain the 10 detection modules.'
    ]
  },
  {
    category: '🧠 XAI & ML',
    icon: Cpu,
    prompts: [
      'What is SHAP?',
      'What is LIME?',
      'What does the confidence score mean?',
      'How does machine learning detect phishing URLs?'
    ]
  },
  {
    category: '🚨 Threats & Attacks',
    icon: AlertTriangle,
    prompts: [
      'What is the difference between phishing and malware?',
      'What is Spear Phishing & Whaling?',
      'What is Smishing & Vishing?',
      'What is Typosquatting & Punycode?'
    ]
  },
  {
    category: '🌐 10-Module Pipeline',
    icon: Globe,
    prompts: [
      'Explain the 10 detection modules.',
      'Explain Module 3 (Feature Extraction)',
      'Explain Module 7 (Explainable AI)',
      'Which features made this URL suspicious?'
    ]
  },
  {
    category: '🛡️ Defense & Playbooks',
    icon: Lock,
    prompts: [
      'What should I do if I clicked a phishing link?',
      'How can I protect myself from phishing?',
      'How can I identify a phishing URL?',
      'Passwords vs 2FA vs Passkeys'
    ]
  }
];

export default function SecurityChatbot({
  currentScanContext = null,
  isOpen: externalIsOpen = undefined,
  onOpen = null,
  onClose = null,
  initialQuery = ''
}) {
  const [internalIsOpen, setInternalIsOpen] = useState(false);
  const isOpen = externalIsOpen !== undefined ? externalIsOpen : internalIsOpen;

  const setChatbotOpenState = (nextOpen) => {
    if (nextOpen) {
      if (onOpen) onOpen();
      else setInternalIsOpen(true);
    } else {
      if (onClose) onClose();
      else setInternalIsOpen(false);
    }
  };

  const [isExpanded, setIsExpanded] = useState(false);
  const [activeCategory, setActiveCategory] = useState(0);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: `### 👋 Welcome to PhishGuard AI Universal Security Copilot!

I am your real-time **Cybersecurity, Machine Learning & Explainable AI Assistant**. You can ask me **any custom question** about cybersecurity threats, phishing detection, our 10-module pipeline, or live forensic analysis of your scanned URLs!

#### 💡 Suggested Questions:
• *"What is phishing?"*
• *"How does phishing URL detection work?"*
• *"Is my current URL safe?"*
• *"Why was this URL classified as phishing?"*
• *"What is SHAP and how is it used here?"*
• *"Explain the 10 detection modules."*
• *"What should I do if I clicked a phishing link?"*`,
      actions: DEFAULT_RECOMMENDATIONS.slice(0, 6)
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);
  const lastInitialQueryRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
      textareaRef.current?.focus();
    }
  }, [messages, isOpen]);

  // Handle explicit initial query trigger when opened by user action
  useEffect(() => {
    if (isOpen && initialQuery && lastInitialQueryRef.current !== initialQuery) {
      lastInitialQueryRef.current = initialQuery;
      handleSendMessage(initialQuery, currentScanContext);
    }
  }, [isOpen, initialQuery, currentScanContext]);

  const handleSendMessage = async (textToSend, customContext = null) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || loading) return;

    const ctx = customContext !== null ? customContext : currentScanContext;

    const newMessages = [...messages, { role: 'user', text }];
    setMessages(newMessages);
    setInputMessage('');
    setLoading(true);

    try {
      const predCtx = ctx ? {
        url: ctx.url,
        domain: ctx.domain,
        prediction: ctx.prediction,
        phishing_probability: ctx.phishing_probability,
        confidence_score: ctx.confidence_score,
        risk_level: ctx.risk_level,
        key_factors: ctx.shap_explanation?.contributions?.slice(0, 5).map((c) => `${c.display_name} (${c.value})`) 
          || (ctx.key_factors || []),
        shap_explanation: ctx.shap_explanation || null,
        lime_explanation: ctx.lime_explanation || null,
        features: ctx.features || null,
        ai_recommendations: ctx.ai_recommendations || null,
        threat_intel: ctx.threat_intel || null,
        id: ctx.id || null
      } : null;

      const recentHistory = messages.slice(-8).map(m => ({
        role: m.role,
        text: m.text
      }));

      const data = await querySecurityChatbot(
        text,
        ctx?.url || '',
        predCtx,
        recentHistory
      );

      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: data.reply,
          actions: data.suggested_actions && data.suggested_actions.length > 0 ? data.suggested_actions : DEFAULT_RECOMMENDATIONS.slice(0, 6)
        }
      ]);
    } catch (err) {
      console.error('Chatbot API error:', err);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: '### ⚠️ Connection Notice\n\nI was unable to connect to the backend AI security engine. Please verify that the FastAPI backend server is running.',
          actions: DEFAULT_RECOMMENDATIONS.slice(0, 6)
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleCopy = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const clearChat = () => {
    setMessages([
      {
        role: 'assistant',
        text: '🧹 Conversation reset. Ask me any question on cybersecurity, phishing detection, machine learning, or our 10-module pipeline!',
        actions: DEFAULT_RECOMMENDATIONS.slice(0, 6)
      }
    ]);
  };

  // Helper to parse and render formatted markdown text, including tables
  const renderFormattedText = (raw) => {
    if (!raw) return null;
    const lines = raw.split('\n');
    const elements = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];

      // Table Detection
      if (line.trim().startsWith('|') && line.trim().endsWith('|')) {
        const tableLines = [];
        while (i < lines.length && lines[i].trim().startsWith('|') && lines[i].trim().endsWith('|')) {
          tableLines.push(lines[i].trim());
          i++;
        }

        if (tableLines.length >= 2) {
          const headerCols = tableLines[0].split('|').slice(1, -1).map(c => c.trim());
          const hasSeparator = tableLines.length > 1 && tableLines[1].includes('---');
          const rowLines = hasSeparator ? tableLines.slice(2) : tableLines.slice(1);

          elements.push(
            <div key={`table-${i}`} style={{ overflowX: 'auto', margin: '10px 0', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.12)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem', background: 'rgba(15, 23, 42, 0.8)' }}>
                <thead>
                  <tr style={{ background: 'rgba(30, 41, 59, 0.9)', borderBottom: '1px solid rgba(56, 189, 248, 0.3)' }}>
                    {headerCols.map((col, cIdx) => (
                      <th key={cIdx} style={{ padding: '8px 10px', textAlign: 'left', fontWeight: '700', color: '#38BDF8' }}>
                        {renderInlineFormatting(col)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rowLines.map((rLine, rIdx) => {
                    const rowCols = rLine.split('|').slice(1, -1).map(c => c.trim());
                    return (
                      <tr key={rIdx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)', background: rIdx % 2 === 1 ? 'rgba(255, 255, 255, 0.02)' : 'transparent' }}>
                        {rowCols.map((cVal, cIdx) => (
                          <td key={cIdx} style={{ padding: '6px 10px', color: '#E2E8F0' }}>
                            {renderInlineFormatting(cVal)}
                          </td>
                        ))}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          );
          continue;
        }
      }

      // Horizontal Rule
      if (line.trim() === '---' || line.trim() === '***') {
        elements.push(<hr key={`hr-${i}`} style={{ borderColor: 'rgba(255, 255, 255, 0.1)', margin: '12px 0' }} />);
        i++;
        continue;
      }

      // Headers
      if (line.startsWith('### ')) {
        elements.push(
          <h4 key={i} style={{ margin: '12px 0 6px', fontSize: '1.02rem', fontWeight: '800', color: '#38BDF8' }}>
            {line.replace('### ', '')}
          </h4>
        );
        i++;
        continue;
      }
      if (line.startsWith('#### ')) {
        elements.push(
          <h5 key={i} style={{ margin: '10px 0 4px', fontSize: '0.9rem', fontWeight: '700', color: '#F8FAFC' }}>
            {line.replace('#### ', '')}
          </h5>
        );
        i++;
        continue;
      }

      // Bullet List
      if (line.startsWith('• ') || line.startsWith('- ')) {
        const itemText = line.replace(/^[•-]\s*/, '');
        elements.push(
          <div key={i} style={{ display: 'flex', gap: '8px', margin: '4px 0', paddingLeft: '4px', fontSize: '0.84rem' }}>
            <span style={{ color: '#38BDF8', flexShrink: 0 }}>•</span>
            <span>{renderInlineFormatting(itemText)}</span>
          </div>
        );
        i++;
        continue;
      }

      // Numbered List
      if (line.match(/^\d+\.\s/)) {
        const numMatch = line.match(/^\d+\./)[0];
        elements.push(
          <div key={i} style={{ display: 'flex', gap: '8px', margin: '4px 0', paddingLeft: '4px', fontSize: '0.84rem' }}>
            <span style={{ color: '#10B981', fontWeight: '700', flexShrink: 0 }}>{numMatch}</span>
            <span>{renderInlineFormatting(line.replace(/^\d+\.\s*/, ''))}</span>
          </div>
        );
        i++;
        continue;
      }

      // Empty Lines
      if (!line.trim()) {
        elements.push(<div key={i} style={{ height: '6px' }} />);
        i++;
        continue;
      }

      // Paragraph
      elements.push(
        <p key={i} style={{ margin: '4px 0', fontSize: '0.84rem', lineHeight: '1.5', color: '#E2E8F0' }}>
          {renderInlineFormatting(line)}
        </p>
      );
      i++;
    }

    return elements;
  };

  const renderInlineFormatting = (text) => {
    if (!text) return '';
    const parts = text.split(/(\*\*.*?\*\*|\*.*?\*|`.*?`)/g);
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i} style={{ color: '#F8FAFC', fontWeight: '700' }}>{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('*') && part.endsWith('*') && !part.startsWith('**')) {
        return <em key={i} style={{ color: '#CBD5E1' }}>{part.slice(1, -1)}</em>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code
            key={i}
            style={{
              background: 'rgba(15, 23, 42, 0.85)',
              color: '#38BDF8',
              padding: '2px 6px',
              borderRadius: '4px',
              fontFamily: 'monospace',
              fontSize: '0.8rem',
              border: '1px solid rgba(255, 255, 255, 0.08)'
            }}
          >
            {part.slice(1, -1)}
          </code>
        );
      }
      return part;
    });
  };

  return (
    <>
      {/* Floating Trigger Widget Button */}
      {!isOpen && (
        <button
          onClick={() => setChatbotOpenState(true)}
          style={{
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            background: 'linear-gradient(135deg, #0284C7 0%, #38BDF8 100%)',
            color: '#FFFFFF',
            border: 'none',
            borderRadius: '9999px',
            padding: '12px 22px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontWeight: '700',
            fontSize: '0.9rem',
            cursor: 'pointer',
            boxShadow: '0 0 25px rgba(56, 189, 248, 0.45)',
            zIndex: 900,
            transition: 'all 0.2s ease'
          }}
        >
          <Sparkles size={18} />
          <span>Ask Security AI</span>
        </button>
      )}

      {/* Floating / Expanded AI Chat Console */}
      {isOpen && (
        <div
          className="glass-panel"
          style={{
            position: 'fixed',
            bottom: isExpanded ? '20px' : '24px',
            right: isExpanded ? '20px' : '24px',
            width: isExpanded ? 'calc(100vw - 40px)' : '460px',
            maxWidth: isExpanded ? '980px' : '460px',
            height: isExpanded ? 'calc(100vh - 40px)' : '650px',
            maxHeight: isExpanded ? '880px' : '650px',
            display: 'flex',
            flexDirection: 'column',
            zIndex: 1000,
            border: '1px solid rgba(56, 189, 248, 0.35)',
            boxShadow: '0 25px 60px rgba(0, 0, 0, 0.8)',
            borderRadius: '16px',
            overflow: 'hidden',
            transition: 'all 0.25s cubic-bezier(0.16, 1, 0.3, 1)'
          }}
        >
          {/* Top Header */}
          <div
            style={{
              background: 'linear-gradient(90deg, #0F172A 0%, #1E293B 100%)',
              padding: '14px 18px',
              borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div
                style={{
                  background: 'rgba(56, 189, 248, 0.15)',
                  padding: '7px',
                  borderRadius: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: '1px solid rgba(56, 189, 248, 0.3)'
                }}
              >
                <Bot size={20} color="#38BDF8" />
              </div>
              <div>
                <div style={{ fontSize: '0.94rem', fontWeight: '800', color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  Cybersecurity AI Copilot
                  <span style={{ fontSize: '0.66rem', background: 'rgba(16, 185, 129, 0.2)', color: '#10B981', padding: '1px 6px', borderRadius: '4px', border: '1px solid rgba(16, 185, 129, 0.4)' }}>
                    INTELLIGENT XAI
                  </span>
                </div>
                <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>
                  Ask ANY cybersecurity, ML, 10-module, or scan question
                </div>
              </div>
            </div>

            {/* Header Control Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                onClick={clearChat}
                title="Reset Conversation"
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: 'none',
                  color: '#94A3B8',
                  padding: '6px',
                  borderRadius: '6px',
                  cursor: 'pointer'
                }}
              >
                <RotateCcw size={15} />
              </button>

              <button
                onClick={() => setIsExpanded(!isExpanded)}
                title={isExpanded ? 'Collapse' : 'Expand Console'}
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: 'none',
                  color: '#94A3B8',
                  padding: '6px',
                  borderRadius: '6px',
                  cursor: 'pointer'
                }}
              >
                {isExpanded ? <Minimize2 size={15} /> : <Maximize2 size={15} />}
              </button>

              <button
                onClick={() => setChatbotOpenState(false)}
                title="Close"
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: 'none',
                  color: '#94A3B8',
                  padding: '6px',
                  borderRadius: '6px',
                  cursor: 'pointer'
                }}
              >
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Active Scan Context Notification Banner */}
          {currentScanContext && (
            <div
              style={{
                background: currentScanContext.prediction === 'Phishing' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                borderBottom: `1px solid ${currentScanContext.prediction === 'Phishing' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                padding: '8px 16px',
                fontSize: '0.74rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                color: '#F8FAFC'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: currentScanContext.prediction === 'Phishing' ? '#EF4444' : '#10B981', display: 'inline-block' }} />
                <span>Active Target:</span>
                <strong style={{ fontFamily: 'monospace', color: '#38BDF8' }}>{currentScanContext.domain || currentScanContext.url}</strong>
              </div>
              <span style={{ fontWeight: '700', color: currentScanContext.prediction === 'Phishing' ? '#EF4444' : '#10B981', flexShrink: 0, marginLeft: '8px' }}>
                {currentScanContext.prediction} ({currentScanContext.phishing_probability}%)
              </span>
            </div>
          )}

          {/* Category Ribbon / Prompt Explorer */}
          <div
            style={{
              display: 'flex',
              gap: '6px',
              padding: '8px 14px',
              background: 'rgba(15, 23, 42, 0.85)',
              borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
              overflowX: 'auto',
              whiteSpace: 'nowrap'
            }}
          >
            {CATEGORY_PROMPTS.map((cat, cIdx) => {
              const Icon = cat.icon;
              const isActive = activeCategory === cIdx;
              return (
                <button
                  key={cIdx}
                  onClick={() => setActiveCategory(cIdx)}
                  style={{
                    background: isActive ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255, 255, 255, 0.03)',
                    border: `1px solid ${isActive ? 'rgba(56, 189, 248, 0.4)' : 'rgba(255, 255, 255, 0.08)'}`,
                    color: isActive ? '#38BDF8' : '#94A3B8',
                    padding: '4px 10px',
                    borderRadius: '20px',
                    fontSize: '0.72rem',
                    fontWeight: isActive ? '700' : '500',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    flexShrink: 0,
                    transition: 'all 0.15s ease'
                  }}
                >
                  <Icon size={12} />
                  <span>{cat.category}</span>
                </button>
              );
            })}
          </div>

          {/* Messages Scroll Area */}
          <div
            style={{
              flex: 1,
              overflowY: 'auto',
              padding: '16px',
              display: 'flex',
              flexDirection: 'column',
              gap: '14px',
              background: 'rgba(7, 11, 20, 0.94)'
            }}
          >
            {messages.map((m, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  gap: '10px',
                  flexDirection: m.role === 'user' ? 'row-reverse' : 'row',
                  alignItems: 'flex-start'
                }}
              >
                {/* Avatar */}
                <div
                  style={{
                    width: '28px',
                    height: '28px',
                    borderRadius: '50%',
                    background: m.role === 'user' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(139, 92, 246, 0.2)',
                    border: `1px solid ${m.role === 'user' ? 'rgba(56, 189, 248, 0.4)' : 'rgba(139, 92, 246, 0.4)'}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    color: m.role === 'user' ? '#38BDF8' : '#C4B5FD'
                  }}
                >
                  {m.role === 'user' ? <User size={15} /> : <Bot size={15} />}
                </div>

                {/* Message Bubble */}
                <div
                  style={{
                    maxWidth: '86%',
                    background: m.role === 'user' ? 'linear-gradient(135deg, #0284C7 0%, #0369A1 100%)' : 'rgba(30, 41, 59, 0.8)',
                    border: `1px solid ${m.role === 'user' ? 'rgba(56, 189, 248, 0.4)' : 'rgba(255, 255, 255, 0.08)'}`,
                    padding: '12px 16px',
                    borderRadius: '12px',
                    color: '#F8FAFC',
                    position: 'relative'
                  }}
                >
                  {renderFormattedText(m.text)}

                  {/* Copy snippet button for assistant responses */}
                  {m.role === 'assistant' && (
                    <button
                      onClick={() => handleCopy(m.text, idx)}
                      title="Copy response"
                      style={{
                        position: 'absolute',
                        top: '8px',
                        right: '8px',
                        background: 'rgba(15, 23, 42, 0.6)',
                        border: '1px solid rgba(255, 255, 255, 0.05)',
                        color: copiedIndex === idx ? '#10B981' : '#64748B',
                        padding: '4px',
                        borderRadius: '4px',
                        cursor: 'pointer'
                      }}
                    >
                      {copiedIndex === idx ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  )}

                  {/* Dynamic Clickable Action Chips */}
                  {m.actions && m.actions.length > 0 && (
                    <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <div style={{ fontSize: '0.7rem', color: '#94A3B8', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        Suggested Follow-ups:
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {m.actions.map((act, aIdx) => (
                          <button
                            key={aIdx}
                            onClick={() => handleSendMessage(act)}
                            style={{
                              background: 'rgba(56, 189, 248, 0.1)',
                              border: '1px solid rgba(56, 189, 248, 0.25)',
                              color: '#38BDF8',
                              padding: '5px 10px',
                              borderRadius: '16px',
                              fontSize: '0.74rem',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px',
                              transition: 'all 0.15s ease'
                            }}
                          >
                            <span>{act}</span>
                            <ChevronRight size={12} />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}

            {/* Loading Indicator */}
            {loading && (
              <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                <div
                  style={{
                    width: '28px',
                    height: '28px',
                    borderRadius: '50%',
                    background: 'rgba(139, 92, 246, 0.2)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#C4B5FD'
                  }}
                >
                  <Bot size={15} />
                </div>
                <div
                  style={{
                    background: 'rgba(30, 41, 59, 0.75)',
                    padding: '10px 16px',
                    borderRadius: '12px',
                    color: '#94A3B8',
                    fontSize: '0.82rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}
                >
                  <span className="spinner" style={{ width: '14px', height: '14px' }} />
                  <span>PhishGuard AI is generating reasoning response...</span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Quick Category Prompts Bar */}
          <div
            style={{
              padding: '6px 14px',
              background: 'rgba(15, 23, 42, 0.95)',
              borderTop: '1px solid rgba(255, 255, 255, 0.05)',
              display: 'flex',
              gap: '6px',
              overflowX: 'auto',
              whiteSpace: 'nowrap'
            }}
          >
            {CATEGORY_PROMPTS[activeCategory]?.prompts.map((p, pIdx) => (
              <button
                key={pIdx}
                onClick={() => handleSendMessage(p)}
                style={{
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  color: '#CBD5E1',
                  padding: '4px 10px',
                  borderRadius: '14px',
                  fontSize: '0.72rem',
                  cursor: 'pointer',
                  flexShrink: 0,
                  transition: 'all 0.15s ease'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.4)';
                  e.currentTarget.style.color = '#38BDF8';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                  e.currentTarget.style.color = '#CBD5E1';
                }}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Bottom Chat Input Form */}
          <div
            style={{
              padding: '10px 14px 12px',
              background: 'rgba(15, 23, 42, 0.98)',
              borderTop: '1px solid rgba(255, 255, 255, 0.08)'
            }}
          >
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendMessage();
              }}
              style={{ display: 'flex', gap: '10px', alignItems: 'center' }}
            >
              <textarea
                ref={textareaRef}
                rows={1}
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask any question (e.g. 'What is SHAP?', 'Explain Module 3', 'Why was this URL flagged?')..."
                style={{
                  flex: 1,
                  background: 'rgba(30, 41, 59, 0.6)',
                  border: '1px solid rgba(255, 255, 255, 0.15)',
                  borderRadius: '10px',
                  padding: '10px 14px',
                  color: '#F8FAFC',
                  fontSize: '0.86rem',
                  resize: 'none',
                  outline: 'none',
                  fontFamily: 'inherit',
                  minHeight: '40px',
                  maxHeight: '100px'
                }}
              />

              <button
                type="submit"
                disabled={!inputMessage.trim() || loading}
                className="btn-primary"
                style={{
                  padding: '10px 16px',
                  borderRadius: '10px',
                  opacity: (!inputMessage.trim() || loading) ? 0.5 : 1,
                  cursor: (!inputMessage.trim() || loading) ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: '40px'
                }}
              >
                <Send size={16} />
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
