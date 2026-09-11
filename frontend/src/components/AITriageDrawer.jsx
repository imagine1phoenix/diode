import React, { useState, useEffect, useRef } from 'react';
import {
  X, Bot, Sparkles, ShieldAlert, Terminal, Copy, Check, ExternalLink,
  Cpu, Lock, ArrowRight, Activity, AlertTriangle, Send, MessageSquare,
  FileText, Download, RefreshCw, Zap, CornerDownLeft
} from 'lucide-react';

export default function AITriageDrawer({ alert, isOpen, onClose }) {
  const [activeTab, setActiveTab] = useState('triage'); // 'triage' | 'chat'
  const [triageData, setTriageData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [copiedAll, setCopiedAll] = useState(false);

  // Chat State
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef(null);

  // Reset or initialize on open
  useEffect(() => {
    if (!isOpen || !alert) {
      setTriageData(null);
      setChatMessages([]);
      return;
    }

    let isMounted = true;
    setLoading(true);

    // Initial greeting in chat
    setChatMessages([
      {
        role: 'assistant',
        content: `### 🛡️ Diode Copilot Initialized\n\nI have loaded telemetry for alert **\`${alert.alert_id}\`** (*${alert.threat_class?.toUpperCase()}* - ${strUpper(alert.severity)}).\n\nAsk me anything about the **mathematical entropy thresholds**, **FFT spectral analysis**, **MITRE ATT&CK vectors**, or click any prompt chip below for instant air-gapped forensic triage.`,
        timestamp: new Date().toLocaleTimeString(),
      }
    ]);

    fetch('/api/triage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    })
      .then((res) => res.json())
      .then((data) => {
        if (isMounted) {
          setTriageData(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        console.error('Triage fetch failed:', err);
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen, alert]);

  // Auto-scroll chat
  useEffect(() => {
    if (activeTab === 'chat' && chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages, activeTab]);

  if (!isOpen || !alert) return null;

  function strUpper(v) {
    return (v || '').toString().toUpperCase();
  }

  const handleCopyCmd = (cmd, index) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyPlaybook = () => {
    if (!triageData) return;
    const text = [
      `=== NET-DRISHTI AI SOC ANALYST INCIDENT PLAYBOOK ===`,
      `Classification: AIR-GAPPED TELEMETRY ENCLAVE (ZERO TX / READ-ONLY)`,
      `Event ID: ${alert.alert_id}`,
      `Threat: ${alert.threat_class} (${strUpper(alert.severity)})`,
      `MITRE: ${triageData.mitre_mapping?.technique} - ${triageData.mitre_mapping?.technique_name}`,
      ``,
      `EXECUTIVE SUMMARY:`,
      triageData.executive_summary,
      ``,
      `FORENSIC PROOF:`,
      ...(triageData.forensic_signals || []).map((s, i) => `• ${s}`),
      ``,
      `RECOMMENDED MITIGATION COMMANDS:`,
      ...(triageData.recommended_mitigation || []).map((m, i) => `${i + 1}. ${m}`),
    ].join('\n');

    navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  const handleExportDossier = () => {
    const dossier = {
      dossier_title: `FORENSIC_TELEMETRY_DOSSIER_${alert.alert_id}`,
      export_timestamp: new Date().toISOString(),
      enclave: "NET-DRISHTI AIR-GAPPED TELEMETRY ENCLAVE",
      tap_mode: "PASSIVE_OPTICAL_DIODE_SIMPLEX_RX",
      hardware_constraint: "ZERO_TX_WRITES_VERIFIED",
      alert,
      ai_triage: triageData,
      recommended_capture_syntax: `tcpdump -nn -s 0 -i eth0 'host ${alert.flow_id?.split('-')[0]?.split(':')[0] || 'any'}' -w /opt/forensics/${alert.alert_id}.pcap`,
    };

    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `NET_DRISHTI_DOSSIER_${alert.alert_id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleSendChat = async (textToSend) => {
    const query = (textToSend || chatInput).trim();
    if (!query || chatLoading) return;

    const userMsg = {
      role: 'user',
      content: query,
      timestamp: new Date().toLocaleTimeString(),
    };

    setChatMessages((prev) => [...prev, userMsg]);
    setChatInput('');
    setChatLoading(true);

    try {
      const historyPayload = chatMessages.slice(-6).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const res = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query,
          alert,
          history: historyPayload,
        }),
      });

      const data = await res.json();
      if (data.status === 'success' && data.answer) {
        setChatMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: data.answer,
            model: data.model,
            latency: data.inference_latency_ms,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      } else {
        throw new Error('Invalid response from copilot');
      }
    } catch (err) {
      console.error('Chat error:', err);
      setChatMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ Communication error with local SLM inference engine. Ensure FastAPI backend is active.`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const mitre = triageData?.mitre_mapping;

  const quickPromptChips = [
    { label: '⚡ Why did entropy trigger this?', query: 'Explain why entropy triggered this alert and how it differs from benign baseline traffic.' },
    { label: '📜 Generate Wireshark & tcpdump filter', query: 'Generate precise BPF tcpdump and Wireshark capture filters for this flow.' },
    { label: '🔒 Verify Diode Isolation', query: 'How does the optical data diode guarantee zero TX writes and prevent reverse C2 exploitation?' },
    { label: '📡 Explain C2 Beaconing FFT', query: 'Explain the mathematical FFT spectral analysis and jitter autocorrelation used to detect this beacon.' },
  ];

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.45)',
        backdropFilter: 'blur(5px)',
        zIndex: 120,
        display: 'flex',
        justifyContent: 'flex-end',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '620px',
          height: '100%',
          background: '#FFFFFF',
          borderLeft: '1px solid #CBD5E1',
          boxShadow: '-10px 0 35px rgba(0, 0, 0, 0.12)',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header Bar */}
        <div style={{
          padding: '20px 24px 16px',
          borderBottom: '1px solid #E2E8F0',
          background: '#F8FAFC',
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '42px',
              height: '42px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, #2563EB, #4F46E5)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 4px 12px rgba(37, 99, 235, 0.25)',
              flexShrink: 0,
            }}>
              <Bot size={22} color="#ffffff" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <h2 style={{ fontSize: '16px', fontWeight: '900', color: '#0F172A', fontFamily: 'var(--font-mono)', letterSpacing: '0.02em' }}>
                  DIODE COPILOT // AIR-GAPPED SLM
                </h2>
                <span style={{
                  fontSize: '10px',
                  fontWeight: '800',
                  padding: '2px 8px',
                  borderRadius: '9999px',
                  background: '#DCFCE7',
                  color: '#15803D',
                  border: '1px solid #BBF7D0',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}>
                  <Lock size={10} />
                  READ-ONLY DIODE TAP
                </span>
              </div>
              <p style={{ fontSize: '11px', color: '#64748B', marginTop: '2px', fontWeight: '500' }}>
                On-Premise Small Language Model • Unidirectional Telemetry Inference (Zero External Egress)
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94A3B8',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'color 0.15s',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Model Sub-Bar & Tab Switcher */}
        <div style={{
          padding: '10px 24px',
          borderBottom: '1px solid #E2E8F0',
          background: '#FFFFFF',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '12px',
          flexWrap: 'wrap',
          gap: '10px',
        }}>
          {/* Tabs */}
          <div style={{
            display: 'inline-flex',
            background: '#F1F5F9',
            padding: '3px',
            borderRadius: '8px',
            gap: '3px',
          }}>
            <button
              onClick={() => setActiveTab('triage')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '5px 12px',
                borderRadius: '6px',
                border: 'none',
                background: activeTab === 'triage' ? '#FFFFFF' : 'transparent',
                color: activeTab === 'triage' ? '#0F172A' : '#64748B',
                fontWeight: '700',
                fontSize: '11px',
                cursor: 'pointer',
                boxShadow: activeTab === 'triage' ? '0 1px 3px rgba(0,0,0,0.08)' : 'none',
                transition: 'all 0.15s',
              }}
            >
              <FileText size={13} />
              <span>Incident Dossier</span>
            </button>

            <button
              onClick={() => setActiveTab('chat')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '5px 12px',
                borderRadius: '6px',
                border: 'none',
                background: activeTab === 'chat' ? '#2563EB' : 'transparent',
                color: activeTab === 'chat' ? '#FFFFFF' : '#64748B',
                fontWeight: '700',
                fontSize: '11px',
                cursor: 'pointer',
                boxShadow: activeTab === 'chat' ? '0 1px 3px rgba(37,99,235,0.25)' : 'none',
                transition: 'all 0.15s',
              }}
            >
              <MessageSquare size={13} />
              <span>Interactive Chat</span>
              <span style={{
                fontSize: '9px',
                padding: '1px 5px',
                borderRadius: '4px',
                background: activeTab === 'chat' ? 'rgba(255,255,255,0.25)' : '#E2E8F0',
                color: activeTab === 'chat' ? '#FFFFFF' : '#475569',
              }}>
                SLM
              </span>
            </button>
          </div>

          {/* Inference Latency Indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
            <span style={{ color: '#64748B' }}>Inference:</span>
            <span style={{
              background: '#EFF6FF',
              color: '#1D4ED8',
              padding: '2px 8px',
              borderRadius: '4px',
              fontWeight: '700',
              border: '1px solid #DBEAFE',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
            }}>
              <Activity size={11} />
              {triageData?.inference_latency_ms || 24} ms
            </span>
          </div>
        </div>

        {/* TAB 1: INCIDENT DOSSIER */}
        {activeTab === 'triage' && (
          <div style={{
            flex: 1,
            overflowY: 'auto',
            padding: '24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
            background: '#F8FAFC',
          }}>
            {/* Quick Actions Bar */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: '#FFFFFF',
              padding: '12px 16px',
              borderRadius: '12px',
              border: '1px solid #E2E8F0',
              boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
            }}>
              <div>
                <span style={{ fontSize: '11px', color: '#64748B', fontWeight: '600' }}>Active Investigation:</span>
                <div style={{ fontSize: '13px', fontWeight: '800', color: '#0F172A', fontFamily: 'var(--font-mono)' }}>
                  {alert.flow_id || alert.alert_id}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={handleExportDossier}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    padding: '6px 12px',
                    borderRadius: '8px',
                    background: '#0F172A',
                    color: '#FFFFFF',
                    border: 'none',
                    fontSize: '11px',
                    fontWeight: '700',
                    cursor: 'pointer',
                    boxShadow: '0 2px 4px rgba(15,23,42,0.15)',
                  }}
                >
                  <Download size={13} />
                  <span>Export Dossier</span>
                </button>

                <button
                  onClick={() => {
                    setActiveTab('chat');
                    handleSendChat('Deep dive on this alert: explain why it triggered and give passive inspection steps.');
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    padding: '6px 12px',
                    borderRadius: '8px',
                    background: '#2563EB',
                    color: '#FFFFFF',
                    border: 'none',
                    fontSize: '11px',
                    fontWeight: '700',
                    cursor: 'pointer',
                  }}
                >
                  <Sparkles size={13} />
                  <span>Ask Copilot</span>
                </button>
              </div>
            </div>

            {loading ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, gap: '14px', padding: '60px 0', color: '#64748B' }}>
                <Sparkles size={32} className="pulse" color="#2563EB" />
                <div style={{ fontSize: '13px', fontWeight: '600' }}>Running on-premise SLM telemetry evaluation...</div>
              </div>
            ) : triageData ? (
              <>
                {/* MITRE ATT&CK Mapping Card */}
                {mitre && (
                  <div style={{
                    background: '#FFFFFF',
                    border: '1px solid #E2E8F0',
                    borderRadius: '12px',
                    padding: '16px',
                    boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '10px', color: '#4F46E5', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        MITRE ATT&CK Matrix Alignment
                      </span>
                      <a
                        href={mitre.url}
                        target="_blank"
                        rel="noreferrer"
                        style={{
                          fontSize: '11px',
                          color: '#2563EB',
                          textDecoration: 'none',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontWeight: '600',
                        }}
                      >
                        <span>KnowledgeBase</span>
                        <ExternalLink size={11} />
                      </a>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{
                        fontSize: '12px',
                        fontWeight: '800',
                        fontFamily: 'var(--font-mono)',
                        color: '#4338CA',
                        background: '#EEF2FF',
                        padding: '3px 8px',
                        borderRadius: '6px',
                        border: '1px solid #C7D2FE',
                      }}>
                        {mitre.technique}
                      </span>
                      <span style={{ fontSize: '13px', fontWeight: '700', color: '#0F172A' }}>
                        {mitre.technique_name}
                      </span>
                      <span style={{ fontSize: '11px', color: '#64748B', fontWeight: '500' }}>
                        • Tactic: {mitre.tactic} ({mitre.tactic_name})
                      </span>
                    </div>
                  </div>
                )}

                {/* Executive Diagnosis */}
                <div style={{
                  background: '#FFFFFF',
                  border: '1px solid #E2E8F0',
                  borderRadius: '12px',
                  padding: '18px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                    <Sparkles size={16} color="#2563EB" />
                    <h3 style={{ fontSize: '13px', fontWeight: '800', color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Executive Incident Assessment
                    </h3>
                  </div>
                  <div style={{
                    fontSize: '13px',
                    color: '#334155',
                    lineHeight: 1.6,
                    fontWeight: '500',
                  }}>
                    {triageData.executive_summary}
                  </div>
                </div>

                {/* Forensic Signals */}
                <div style={{
                  background: '#FFFFFF',
                  border: '1px solid #E2E8F0',
                  borderRadius: '12px',
                  padding: '18px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                    <ShieldAlert size={16} color="#DC2626" />
                    <h3 style={{ fontSize: '13px', fontWeight: '800', color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Passive Optical Forensic Proof
                    </h3>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {(triageData.forensic_signals || []).map((sig, idx) => (
                      <div key={idx} style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '10px',
                        fontSize: '12px',
                        color: '#334155',
                        background: '#F8FAFC',
                        padding: '10px 12px',
                        borderRadius: '8px',
                        border: '1px solid #E2E8F0',
                      }}>
                        <span style={{ color: '#2563EB', fontWeight: '800', marginTop: '1px' }}>•</span>
                        <span style={{ lineHeight: 1.5, fontWeight: '500' }}>{sig}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Actionable Network Mitigation Playbook */}
                <div style={{
                  background: '#FFFFFF',
                  border: '1px solid #E2E8F0',
                  borderRadius: '12px',
                  padding: '18px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Terminal size={16} color="#15803D" />
                      <h3 style={{ fontSize: '13px', fontWeight: '800', color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        Peripheral Remediation Playbook (Manual Run)
                      </h3>
                    </div>
                    <button
                      onClick={handleCopyPlaybook}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: copiedAll ? '#15803D' : '#64748B',
                        fontSize: '11px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        fontWeight: '700',
                      }}
                    >
                      {copiedAll ? <Check size={13} color="#15803D" /> : <Copy size={13} />}
                      <span>{copiedAll ? 'Playbook Copied' : 'Copy All'}</span>
                    </button>
                  </div>

                  <p style={{ fontSize: '11px', color: '#64748B', marginBottom: '12px' }}>
                    ⚠️ Commands must be executed manually at edge routing switches outside the air-gapped diode.
                  </p>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {(triageData.recommended_mitigation || []).map((step, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: '#0F172A',
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          padding: '10px 14px',
                          fontSize: '12px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '10px' }}>
                          <div style={{
                            color: '#F8FAFC',
                            lineHeight: 1.4,
                            flex: 1,
                            fontFamily: step.includes('iptables') || step.includes('sysctl') ? 'var(--font-mono)' : 'var(--font-sans)',
                            fontSize: step.includes('iptables') ? '11px' : '12px',
                          }}>
                            {step}
                          </div>
                          <button
                            onClick={() => handleCopyCmd(step, idx)}
                            title="Copy command"
                            style={{
                              background: 'rgba(255, 255, 255, 0.1)',
                              border: 'none',
                              color: copiedIndex === idx ? '#4ADE80' : '#94A3B8',
                              padding: '5px',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              flexShrink: 0,
                            }}
                          >
                            {copiedIndex === idx ? <Check size={12} /> : <Copy size={12} />}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <div style={{ color: '#64748B', textAlign: 'center', padding: '40px 0' }}>
                No triage data available for this event.
              </div>
            )}
          </div>
        )}

        {/* TAB 2: INTERACTIVE COPILOT CHAT */}
        {activeTab === 'chat' && (
          <div style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            background: '#F8FAFC',
          }}>
            {/* Quick Prompt Chips */}
            <div style={{
              padding: '12px 20px',
              background: '#FFFFFF',
              borderBottom: '1px solid #E2E8F0',
              display: 'flex',
              gap: '8px',
              overflowX: 'auto',
              whiteSpace: 'nowrap',
            }}>
              {quickPromptChips.map((chip, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendChat(chip.query)}
                  style={{
                    background: '#F1F5F9',
                    border: '1px solid #E2E8F0',
                    borderRadius: '9999px',
                    padding: '4px 12px',
                    fontSize: '11px',
                    fontWeight: '600',
                    color: '#334155',
                    cursor: 'pointer',
                    transition: 'all 0.15s',
                    flexShrink: 0,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = '#E0F2FE';
                    e.currentTarget.style.borderColor = '#BAE6FD';
                    e.currentTarget.style.color = '#0369A1';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = '#F1F5F9';
                    e.currentTarget.style.borderColor = '#E2E8F0';
                    e.currentTarget.style.color = '#334155';
                  }}
                >
                  {chip.label}
                </button>
              ))}
            </div>

            {/* Chat Message Stream */}
            <div style={{
              flex: 1,
              overflowY: 'auto',
              padding: '20px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
            }}>
              {chatMessages.map((msg, i) => {
                const isUser = msg.role === 'user';
                return (
                  <div
                    key={i}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: isUser ? 'flex-end' : 'flex-start',
                      width: '100%',
                    }}
                  >
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      marginBottom: '4px',
                      fontSize: '10px',
                      color: '#64748B',
                      fontWeight: '700',
                    }}>
                      <span>{isUser ? 'ANALYST' : 'DIODE COPILOT (SLM)'}</span>
                      <span>•</span>
                      <span>{msg.timestamp}</span>
                    </div>

                    <div style={{
                      maxWidth: '92%',
                      padding: '14px 18px',
                      borderRadius: isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
                      background: isUser ? '#0F172A' : '#FFFFFF',
                      color: isUser ? '#FFFFFF' : '#1E293B',
                      border: isUser ? 'none' : '1px solid #E2E8F0',
                      boxShadow: '0 2px 6px rgba(0, 0, 0, 0.04)',
                      fontSize: '13px',
                      lineHeight: 1.6,
                      wordBreak: 'break-word',
                    }}>
                      <div
                        dangerouslySetInnerHTML={{
                          __html: renderMarkdownSimple(msg.content, isUser)
                        }}
                      />
                    </div>
                  </div>
                );
              })}

              {chatLoading && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#64748B', fontSize: '12px', padding: '10px' }}>
                  <Sparkles size={14} className="pulse" color="#2563EB" />
                  <span>On-premise SLM evaluating telemetry...</span>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Input Bar */}
            <div style={{
              padding: '16px 20px',
              background: '#FFFFFF',
              borderTop: '1px solid #E2E8F0',
            }}>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSendChat();
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: '#F8FAFC',
                  border: '1px solid #CBD5E1',
                  borderRadius: '12px',
                  padding: '6px 10px',
                  boxShadow: 'inset 0 1px 2px rgba(0,0,0,0.03)',
                }}
              >
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder="Ask Diode Copilot (e.g. explain entropy, generate Wireshark filter)..."
                  disabled={chatLoading}
                  style={{
                    flex: 1,
                    border: 'none',
                    background: 'transparent',
                    outline: 'none',
                    fontSize: '13px',
                    color: '#0F172A',
                    padding: '6px 8px',
                  }}
                />
                <button
                  type="submit"
                  disabled={chatLoading || !chatInput.trim()}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '34px',
                    height: '34px',
                    borderRadius: '8px',
                    background: chatInput.trim() ? '#2563EB' : '#94A3B8',
                    color: '#FFFFFF',
                    border: 'none',
                    cursor: chatInput.trim() ? 'pointer' : 'default',
                    transition: 'all 0.15s',
                  }}
                >
                  <Send size={15} />
                </button>
              </form>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px', fontSize: '10px', color: '#94A3B8' }}>
                <span>Physical Unidirectional Optical Tap • Simplex Rx • Zero Socket Outbound</span>
                <span>Press Enter to Submit</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Simple Markdown Parser for Rich Copilot formatting
function renderMarkdownSimple(text, isUser) {
  if (!text) return '';
  let html = text
    // Code blocks with syntax box
    .replace(/```([a-z]*)\n([\s\S]*?)```/g, (match, lang, code) => {
      const escaped = code
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      return `<pre style="background: #0F172A; color: #38BDF8; padding: 12px 14px; border-radius: 8px; font-family: var(--font-mono); font-size: 11px; overflow-x: auto; margin: 10px 0; border: 1px solid #334155; text-align: left;"><code>${escaped}</code></pre>`;
    })
    // Inline code
    .replace(/`([^`]+)`/g, (m, c) => {
      return `<code style="background: ${isUser ? 'rgba(255,255,255,0.2)' : '#F1F5F9'}; color: ${isUser ? '#FFFFFF' : '#0F172A'}; padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; font-weight: 700;">${c}</code>`;
    })
    // Headers
    .replace(/^### (.*$)/gim, '<h4 style="font-size: 13px; font-weight: 800; margin: 8px 0 4px; color: inherit;">$1</h4>')
    .replace(/^## (.*$)/gim, '<h3 style="font-size: 14px; font-weight: 900; margin: 10px 0 6px; color: inherit;">$1</h3>')
    // Bold
    .replace(/\*\*(.*?)\*\*/g, '<strong style="font-weight: 800;">$1</strong>')
    // Bullet lists
    .replace(/^\s*[-•]\s+(.*$)/gim, '<div style="display: flex; gap: 6px; margin: 4px 0;"><span style="color: #2563EB;">•</span><span>$1</span></div>')
    // Line breaks
    .replace(/\n\n/g, '<div style="margin: 8px 0;"></div>');

  return html;
}
