import React, { useState, useEffect, useRef } from 'react';
import {
  X, Bot, Sparkles, ShieldAlert, Terminal, Copy, Check, ExternalLink,
  Cpu, Lock, ArrowRight, Activity, AlertTriangle, Send, MessageSquare,
  FileText, Download, RefreshCw, Zap, CornerDownLeft, Settings, Key,
  Eye, EyeOff, CheckCircle2, AlertCircle, CheckCircle
} from 'lucide-react';
import { getApiUrl } from '../api';

export default function AITriageDrawer({ alert, isOpen, onClose }) {
  const [activeTab, setActiveTab] = useState('triage'); // 'triage' | 'chat'
  const [triageData, setTriageData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [copiedAll, setCopiedAll] = useState(false);

  // Real LLM Provider Configuration State
  const [copilotConfig, setCopilotConfig] = useState({
    provider: 'groq',
    model: 'qwen/qwen3.8-27b',
    has_key: false,
    masked_key: '',
    providers: {},
    mode: 'offline_slm',
  });
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState('groq');
  const [selectedModel, setSelectedModel] = useState('qwen/qwen3.8-27b');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [ollamaUrl, setOllamaUrl] = useState('http://localhost:11434/v1');
  const [testState, setTestState] = useState({ loading: false, result: null, error: null });
  const [saveState, setSaveState] = useState({ loading: false, success: false });

  // Chat State
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef(null);

  const fetchCopilotConfig = async () => {
    try {
      const res = await fetch(getApiUrl('/api/copilot/config'));
      const data = await res.json();
      if (data.status === 'success') {
        setCopilotConfig(data);
        setSelectedProvider(data.provider || 'groq');
        setSelectedModel(data.model || 'qwen/qwen3.8-27b');
        if (data.ollama_base_url) setOllamaUrl(data.ollama_base_url);
      }
    } catch (err) {
      console.warn('Failed to load copilot config:', err);
    }
  };

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

    fetchCopilotConfig();

    fetch(getApiUrl('/api/triage'), {
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

  const handleSelectProvider = (provKey) => {
    setSelectedProvider(provKey);
    const spec = copilotConfig.providers?.[provKey];
    if (spec && spec.default_model) {
      setSelectedModel(spec.default_model);
    }
    setTestState({ loading: false, result: null, error: null });
    setSaveState({ loading: false, success: false });
  };

  const handleTestConnection = async () => {
    setTestState({ loading: true, result: null, error: null });
    try {
      const res = await fetch(getApiUrl('/api/copilot/test'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedProvider,
          api_key: apiKeyInput.trim() || undefined,
          model: selectedModel,
          ollama_base_url: selectedProvider === 'ollama' ? ollamaUrl.trim() : undefined,
        }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setTestState({ loading: false, result: data, error: null });
      } else {
        setTestState({ loading: false, result: null, error: data.message || 'Connection test failed' });
      }
    } catch (err) {
      setTestState({ loading: false, result: null, error: err.message || 'Network error testing connection' });
    }
  };

  const handleSaveConfig = async () => {
    setSaveState({ loading: true, success: false });
    try {
      const res = await fetch(getApiUrl('/api/copilot/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedProvider,
          api_key: apiKeyInput.trim() || undefined,
          model: selectedModel,
          ollama_base_url: selectedProvider === 'ollama' ? ollamaUrl.trim() : undefined,
          persist_to_env: true,
        }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setCopilotConfig(data);
        setSaveState({ loading: false, success: true });
        setTimeout(() => {
          setShowSettingsModal(false);
          setSaveState({ loading: false, success: false });
        }, 800);
      } else {
        throw new Error('Failed to save configuration');
      }
    } catch (err) {
      setSaveState({ loading: false, success: false });
      alert('Error saving configuration: ' + err.message);
    }
  };

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

      const res = await fetch(getApiUrl('/api/copilot/chat'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query,
          alert,
          history: historyPayload,
        }),
      });

      const data = await res.json();
      if ((data.status === 'success' || data.status === 'error') && data.answer) {
        setChatMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: data.answer,
            model: data.model,
            latency: data.inference_latency_ms,
            has_real_model: data.has_real_model,
            mode: data.mode,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      } else {
        throw new Error(data.message || 'Invalid response from copilot');
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
          background: 'var(--bg-card)',
          borderLeft: '1px solid var(--border-subtle)',
          boxShadow: '-10px 0 35px rgba(0, 0, 0, 0.4)',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header Bar */}
        <div style={{
          padding: '20px 24px 16px',
          borderBottom: '1px solid var(--border-subtle)',
          background: 'var(--bg-surface)',
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
                <h2 style={{ fontSize: '16px', fontWeight: '900', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', letterSpacing: '0.02em' }}>
                  DIODE COPILOT // AIR-GAPPED SLM
                </h2>
                <span style={{
                  fontSize: '10px',
                  fontWeight: '800',
                  padding: '2px 8px',
                  borderRadius: '9999px',
                  background: 'var(--live-bg)',
                  color: 'var(--live-text)',
                  border: '1px solid var(--live-border)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}>
                  <Lock size={10} />
                  READ-ONLY DIODE TAP
                </span>
              </div>
              <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px', fontWeight: '500' }}>
                On-Premise Small Language Model • Unidirectional Telemetry Inference (Zero External Egress)
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-secondary)',
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
          borderBottom: '1px solid var(--border-subtle)',
          background: 'var(--bg-surface)',
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
            background: 'var(--bg-card)',
            padding: '3px',
            borderRadius: '8px',
            gap: '3px',
            border: '1px solid var(--border-subtle)',
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
                background: activeTab === 'triage' ? 'var(--bg-surface-hover)' : 'transparent',
                color: activeTab === 'triage' ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: '700',
                fontSize: '11px',
                cursor: 'pointer',
                boxShadow: activeTab === 'triage' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
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
                background: activeTab === 'chat' ? 'var(--accent-blue)' : 'transparent',
                color: activeTab === 'chat' ? '#FFFFFF' : 'var(--text-secondary)',
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
                background: activeTab === 'chat' ? 'rgba(255,255,255,0.25)' : 'var(--bg-surface-hover)',
                color: activeTab === 'chat' ? '#FFFFFF' : 'var(--text-secondary)',
              }}>
                SLM
              </span>
            </button>
          </div>

          {/* Real Model Status & Settings Trigger */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {copilotConfig.has_key ? (
              <button
                onClick={() => setShowSettingsModal(true)}
                title="Active Live Model — Click to configure"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  padding: '3px 10px',
                  borderRadius: '6px',
                  background: 'rgba(16, 185, 129, 0.12)',
                  color: '#10B981',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  fontSize: '11px',
                  fontWeight: '700',
                  cursor: 'pointer',
                  fontFamily: 'var(--font-mono)',
                  transition: 'all 0.15s',
                }}
              >
                <Zap size={11} color="#10B981" />
                <span>{copilotConfig.provider?.toUpperCase()}: {copilotConfig.model}</span>
              </button>
            ) : (
              <button
                onClick={() => setShowSettingsModal(true)}
                title="Click to connect a real model (Groq, Gemini, OpenAI)"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  padding: '3px 10px',
                  borderRadius: '6px',
                  background: 'rgba(234, 179, 8, 0.12)',
                  color: '#EAB308',
                  border: '1px solid rgba(234, 179, 8, 0.3)',
                  fontSize: '11px',
                  fontWeight: '700',
                  cursor: 'pointer',
                  fontFamily: 'var(--font-mono)',
                  transition: 'all 0.15s',
                }}
              >
                <Sparkles size={11} color="#EAB308" />
                <span>Offline SLM (Connect Real LLM)</span>
              </button>
            )}

            <button
              onClick={() => setShowSettingsModal(true)}
              title="Configure AI Models & Keys"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '4px 10px',
                borderRadius: '6px',
                background: 'var(--bg-card)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                fontSize: '11px',
                fontWeight: '700',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <Settings size={12} />
              <span>Model Settings</span>
            </button>
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
            background: 'var(--bg-main)',
          }}>
            {/* Quick Actions Bar */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'var(--bg-card)',
              padding: '12px 16px',
              borderRadius: '12px',
              border: '1px solid var(--border-subtle)',
              boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
            }}>
              <div>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: '600' }}>Active Investigation:</span>
                <div style={{ fontSize: '13px', fontWeight: '800', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
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
                    background: 'var(--bg-surface-hover)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border-input)',
                    fontSize: '11px',
                    fontWeight: '700',
                    cursor: 'pointer',
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
                    background: 'var(--accent-blue)',
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
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, gap: '14px', padding: '60px 0', color: 'var(--text-secondary)' }}>
                <Sparkles size={32} className="pulse" color="#2563EB" />
                <div style={{ fontSize: '13px', fontWeight: '600' }}>Running on-premise SLM telemetry evaluation...</div>
              </div>
            ) : triageData ? (
              <>
                {/* MITRE ATT&CK Mapping Card */}
                {triageData?.mitre_mapping && (
                  <div style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '12px',
                    padding: '16px',
                    boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '10px', color: 'var(--accent-indigo)', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        MITRE ATT&CK Matrix Alignment
                      </span>
                      <a
                        href={triageData.mitre_mapping.url}
                        target="_blank"
                        rel="noreferrer"
                        style={{
                          fontSize: '11px',
                          color: 'var(--accent-blue)',
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
                        color: 'var(--accent-indigo)',
                        background: 'rgba(99, 102, 241, 0.15)',
                        padding: '3px 8px',
                        borderRadius: '6px',
                        border: '1px solid rgba(99, 102, 241, 0.3)',
                      }}>
                        {triageData.mitre_mapping.technique}
                      </span>
                      <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>
                        {triageData.mitre_mapping.technique_name}
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: '500' }}>
                        • Tactic: {triageData.mitre_mapping.tactic} ({triageData.mitre_mapping.tactic_name})
                      </span>
                    </div>
                  </div>
                )}

                {/* Executive Diagnosis */}
                <div style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '12px',
                  padding: '18px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                    <Sparkles size={16} color="#2563EB" />
                    <h3 style={{ fontSize: '13px', fontWeight: '800', color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Executive Incident Assessment
                    </h3>
                  </div>
                  <div style={{
                    fontSize: '13px',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.6,
                    fontWeight: '500',
                  }}>
                    {triageData.executive_summary}
                  </div>
                </div>

                {/* Forensic Signals */}
                <div style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '12px',
                  padding: '18px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                    <ShieldAlert size={16} color="#DC2626" />
                    <h3 style={{ fontSize: '13px', fontWeight: '800', color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
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
                        color: 'var(--text-secondary)',
                        background: 'var(--bg-surface)',
                        padding: '10px 12px',
                        borderRadius: '8px',
                        border: '1px solid var(--border-subtle)',
                      }}>
                        <span style={{ color: 'var(--accent-blue)', fontWeight: '800', marginTop: '1px' }}>•</span>
                        <span style={{ lineHeight: 1.5, fontWeight: '500' }}>{sig}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Actionable Network Mitigation Playbook */}
                <div style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '12px',
                  padding: '18px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Terminal size={16} color="#15803D" />
                      <h3 style={{ fontSize: '13px', fontWeight: '800', color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        Peripheral Remediation Playbook (Manual Run)
                      </h3>
                    </div>
                    <button
                      onClick={handleCopyPlaybook}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: copiedAll ? '#15803D' : 'var(--text-secondary)',
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

                  <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
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
            background: 'var(--bg-main)',
          }}>
            {/* Quick Prompt Chips */}
            <div style={{
              padding: '12px 20px',
              background: 'var(--bg-surface)',
              borderBottom: '1px solid var(--border-subtle)',
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
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '9999px',
                    padding: '4px 12px',
                    fontSize: '11px',
                    fontWeight: '600',
                    color: 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all 0.15s',
                    flexShrink: 0,
                  }}
                >
                  {chip.label}
                </button>
              ))}
            </div>

            {/* Offline SLM Notice Banner (if no live key set) */}
            {!copilotConfig.has_key && (
              <div style={{
                margin: '12px 20px 0',
                padding: '10px 14px',
                borderRadius: '10px',
                background: 'linear-gradient(135deg, rgba(37, 99, 235, 0.12), rgba(79, 70, 229, 0.08))',
                border: '1px solid rgba(37, 99, 235, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '12px',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Sparkles size={18} color="#38BDF8" style={{ flexShrink: 0 }} />
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: '800', color: 'var(--text-primary)' }}>
                      Enable Real AI Model (Groq / Gemini / OpenAI)
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      Answer ANY question beyond fixed keywords. Paste a free key in 10 seconds.
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setShowSettingsModal(true)}
                  style={{
                    padding: '5px 12px',
                    borderRadius: '6px',
                    background: '#2563EB',
                    color: '#FFFFFF',
                    border: 'none',
                    fontSize: '11px',
                    fontWeight: '700',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                    boxShadow: '0 2px 6px rgba(37, 99, 235, 0.3)',
                  }}
                >
                  Connect Model
                </button>
              </div>
            )}

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
                      color: 'var(--text-secondary)',
                      fontWeight: '700',
                    }}>
                      <span>{isUser ? 'ANALYST' : (msg.model ? msg.model.toUpperCase() : (copilotConfig.has_key ? `${copilotConfig.provider.toUpperCase()} (${copilotConfig.model})` : 'DIODE COPILOT (SLM)'))}</span>
                      <span>•</span>
                      <span>{msg.timestamp}</span>
                      {!isUser && msg.latency && (
                        <>
                          <span>•</span>
                          <span style={{ color: 'var(--accent-blue)' }}>{msg.latency} ms</span>
                        </>
                      )}
                    </div>

                    <div style={{
                      maxWidth: '92%',
                      padding: '14px 18px',
                      borderRadius: isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
                      background: isUser ? 'var(--accent-blue)' : 'var(--bg-card)',
                      color: isUser ? '#FFFFFF' : 'var(--text-primary)',
                      border: isUser ? 'none' : '1px solid var(--border-subtle)',
                      boxShadow: '0 2px 6px rgba(0, 0, 0, 0.1)',
                      fontSize: '13px',
                      lineHeight: 1.6,
                      wordBreak: 'break-word',
                    }}>
                      <div
                        dangerouslySetInnerHTML={{
                          __html: renderMarkdownSimple(msg.content, isUser)
                        }}
                      />

                      {/* Prompt button to connect real model if triggered offline notice */}
                      {!isUser && msg.has_real_model === false && msg.content?.includes('Connect Real Model') && (
                        <div style={{ marginTop: '12px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                          <button
                            onClick={() => setShowSettingsModal(true)}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '6px',
                              padding: '6px 14px',
                              borderRadius: '6px',
                              background: '#2563EB',
                              color: '#FFFFFF',
                              border: 'none',
                              fontSize: '11px',
                              fontWeight: '700',
                              cursor: 'pointer',
                              boxShadow: '0 2px 6px rgba(37, 99, 235, 0.3)',
                            }}
                          >
                            <Settings size={13} />
                            <span>Open Model Settings & Add Free API Key</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}

              {chatLoading && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)', fontSize: '12px', padding: '10px' }}>
                  <Sparkles size={14} className="pulse" color="#2563EB" />
                  <span>{copilotConfig.has_key ? `${copilotConfig.provider.toUpperCase()} evaluating telemetry...` : 'On-premise SLM evaluating telemetry...'}</span>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Input Bar */}
            <div style={{
              padding: '16px 20px',
              background: 'var(--bg-surface)',
              borderTop: '1px solid var(--border-subtle)',
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
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-input)',
                  borderRadius: '12px',
                  padding: '6px 10px',
                  boxShadow: 'inset 0 1px 2px rgba(0,0,0,0.05)',
                }}
              >
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder={copilotConfig.has_key ? `Ask Diode Copilot (${copilotConfig.provider.toUpperCase()}) anything...` : "Ask Diode Copilot (e.g. explain entropy, generate Wireshark filter)..."}
                  disabled={chatLoading}
                  style={{
                    flex: 1,
                    border: 'none',
                    background: 'transparent',
                    outline: 'none',
                    fontSize: '13px',
                    color: 'var(--text-primary)',
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
                    background: chatInput.trim() ? '#2563EB' : 'var(--border-input)',
                    color: '#FFFFFF',
                    border: 'none',
                    cursor: chatInput.trim() ? 'pointer' : 'default',
                    transition: 'all 0.15s',
                  }}
                >
                  <Send size={15} />
                </button>
              </form>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px', fontSize: '10px', color: 'var(--text-muted)' }}>
                <span>Physical Unidirectional Optical Tap • Simplex Rx • Zero Socket Outbound</span>
                <span>Press Enter to Submit</span>
              </div>
            </div>
          </div>
        )}

        {/* MODEL SETTINGS MODAL */}
        {showSettingsModal && (
          <div
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(15, 23, 42, 0.75)',
              backdropFilter: 'blur(8px)',
              zIndex: 200,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '20px',
            }}
            onClick={() => setShowSettingsModal(false)}
          >
            <div
              style={{
                width: '100%',
                maxWidth: '540px',
                background: 'var(--bg-card)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '16px',
                boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
                overflow: 'hidden',
                display: 'flex',
                flexDirection: 'column',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div style={{
                padding: '18px 24px',
                borderBottom: '1px solid var(--border-subtle)',
                background: 'var(--bg-surface)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '10px',
                    background: 'linear-gradient(135deg, #2563EB, #4F46E5)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}>
                    <Bot size={20} color="#FFFFFF" />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '15px', fontWeight: '800', color: 'var(--text-primary)', margin: 0 }}>
                      COPILOT MODEL CONFIGURATION
                    </h3>
                    <p style={{ fontSize: '11px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                      Connect a real AI model to answer ANY question beyond fixed patterns
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setShowSettingsModal(false)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-secondary)',
                    cursor: 'pointer',
                    padding: '6px',
                    borderRadius: '6px',
                  }}
                >
                  <X size={18} />
                </button>
              </div>

              {/* Modal Body */}
              <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* Provider Selector Tabs */}
                <div>
                  <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Select AI Provider
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '6px', marginTop: '6px' }}>
                    {[
                      { id: 'groq', name: 'Groq', badge: 'Free / Fast' },
                      { id: 'gemini', name: 'Gemini', badge: 'Free Tier' },
                      { id: 'openai', name: 'OpenAI', badge: 'GPT-4o' },
                      { id: 'ollama', name: 'Ollama', badge: 'Local' },
                    ].map((p) => {
                      const isSel = selectedProvider === p.id;
                      return (
                        <button
                          key={p.id}
                          type="button"
                          onClick={() => handleSelectProvider(p.id)}
                          style={{
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            gap: '2px',
                            padding: '10px 6px',
                            borderRadius: '10px',
                            border: isSel ? '2px solid var(--accent-blue)' : '1px solid var(--border-subtle)',
                            background: isSel ? 'rgba(37, 99, 235, 0.1)' : 'var(--bg-surface)',
                            color: isSel ? 'var(--text-primary)' : 'var(--text-secondary)',
                            fontWeight: isSel ? '800' : '600',
                            fontSize: '12px',
                            cursor: 'pointer',
                            transition: 'all 0.15s',
                          }}
                        >
                          <span>{p.name}</span>
                          <span style={{
                            fontSize: '9px',
                            color: isSel ? 'var(--accent-blue)' : 'var(--text-muted)',
                            fontWeight: '700',
                          }}>
                            {p.badge}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Provider Info & Direct Key Link */}
                {selectedProvider === 'groq' && (
                  <div style={{
                    padding: '10px 14px',
                    borderRadius: '8px',
                    background: 'rgba(37, 99, 235, 0.08)',
                    border: '1px solid rgba(37, 99, 235, 0.2)',
                    fontSize: '11px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}>
                    <span style={{ color: 'var(--text-secondary)' }}>
                      ⚡ <strong>Groq Cloud</strong> provides ultra-fast (~400 t/s) free inference on LLaMA 3.3.
                    </span>
                    <a
                      href="https://console.groq.com/keys"
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        color: '#38BDF8',
                        fontWeight: '700',
                        textDecoration: 'none',
                        flexShrink: 0,
                        marginLeft: '8px',
                      }}
                    >
                      <span>Get Free Key</span>
                      <ExternalLink size={12} />
                    </a>
                  </div>
                )}

                {selectedProvider === 'gemini' && (
                  <div style={{
                    padding: '10px 14px',
                    borderRadius: '8px',
                    background: 'rgba(16, 185, 129, 0.08)',
                    border: '1px solid rgba(16, 185, 129, 0.2)',
                    fontSize: '11px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}>
                    <span style={{ color: 'var(--text-secondary)' }}>
                      ✨ <strong>Google Gemini</strong> offers a generous free tier on Gemini 2.0 Flash.
                    </span>
                    <a
                      href="https://aistudio.google.com/app/apikey"
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        color: '#10B981',
                        fontWeight: '700',
                        textDecoration: 'none',
                        flexShrink: 0,
                        marginLeft: '8px',
                      }}
                    >
                      <span>Get Free Key</span>
                      <ExternalLink size={12} />
                    </a>
                  </div>
                )}

                {/* Model Selector */}
                <div>
                  <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Model Version
                  </label>
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    style={{
                      width: '100%',
                      marginTop: '6px',
                      padding: '9px 12px',
                      background: 'var(--bg-surface)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-input)',
                      borderRadius: '8px',
                      fontSize: '13px',
                      outline: 'none',
                    }}
                  >
                    {(copilotConfig.providers?.[selectedProvider]?.models || [
                      { id: selectedModel, name: selectedModel }
                    ]).map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.name || m.id} {m.desc ? `— ${m.desc}` : ''}
                      </option>
                    ))}
                  </select>
                </div>

                {/* API Key Input */}
                {selectedProvider !== 'ollama' ? (
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                      <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        API Key
                      </label>
                      {copilotConfig.has_key && copilotConfig.provider === selectedProvider && (
                        <span style={{ fontSize: '10px', color: '#10B981', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '3px' }}>
                          <Check size={11} />
                          Active ({copilotConfig.masked_key})
                        </span>
                      )}
                    </div>
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showApiKey ? 'text' : 'password'}
                        value={apiKeyInput}
                        onChange={(e) => setApiKeyInput(e.target.value)}
                        placeholder={copilotConfig.has_key && copilotConfig.provider === selectedProvider ? 'Leave empty to keep current active key' : `Paste your ${selectedProvider.toUpperCase()} key`}
                        style={{
                          width: '100%',
                          padding: '9px 40px 9px 12px',
                          background: 'var(--bg-surface)',
                          color: 'var(--text-primary)',
                          border: '1px solid var(--border-input)',
                          borderRadius: '8px',
                          fontSize: '13px',
                          outline: 'none',
                          boxSizing: 'border-box',
                        }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowApiKey(!showApiKey)}
                        style={{
                          position: 'absolute',
                          right: '10px',
                          top: '50%',
                          transform: 'translateY(-50%)',
                          background: 'transparent',
                          border: 'none',
                          color: 'var(--text-secondary)',
                          cursor: 'pointer',
                          padding: '4px',
                        }}
                      >
                        {showApiKey ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div>
                    <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Ollama Endpoint URL
                    </label>
                    <input
                      type="text"
                      value={ollamaUrl}
                      onChange={(e) => setOllamaUrl(e.target.value)}
                      placeholder="http://localhost:11434/v1"
                      style={{
                        width: '100%',
                        marginTop: '6px',
                        padding: '9px 12px',
                        background: 'var(--bg-surface)',
                        color: 'var(--text-primary)',
                        border: '1px solid var(--border-input)',
                        borderRadius: '8px',
                        fontSize: '13px',
                        outline: 'none',
                        boxSizing: 'border-box',
                      }}
                    />
                  </div>
                )}

                {/* Feedback Alerts */}
                {testState.loading && (
                  <div style={{ padding: '8px 12px', borderRadius: '8px', background: 'rgba(37, 99, 235, 0.1)', color: 'var(--accent-blue)', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <RefreshCw size={13} className="spin" />
                    <span>Pinging {selectedProvider.toUpperCase()} model {selectedModel}...</span>
                  </div>
                )}
                {testState.result && (
                  <div style={{ padding: '8px 12px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#10B981', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckCircle2 size={14} />
                    <span>Connected! Latency: {testState.result.latency_ms} ms — Model: {testState.result.model}</span>
                  </div>
                )}
                {testState.error && (
                  <div style={{ padding: '8px 12px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#EF4444', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <AlertCircle size={14} />
                    <span>{testState.error}</span>
                  </div>
                )}
                {saveState.success && (
                  <div style={{ padding: '8px 12px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.15)', color: '#10B981', fontSize: '11px', fontWeight: '700' }}>
                    ✅ Configuration saved & active! Ready for open-ended chat.
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div style={{
                padding: '14px 24px',
                borderTop: '1px solid var(--border-subtle)',
                background: 'var(--bg-surface)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}>
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={testState.loading || (selectedProvider !== 'ollama' && !apiKeyInput && !copilotConfig.has_key)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '8px 14px',
                    borderRadius: '8px',
                    border: '1px solid var(--border-subtle)',
                    background: 'var(--bg-card)',
                    color: 'var(--text-secondary)',
                    fontSize: '12px',
                    fontWeight: '700',
                    cursor: 'pointer',
                  }}
                >
                  <Activity size={13} />
                  <span>Test Connection</span>
                </button>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    type="button"
                    onClick={() => setShowSettingsModal(false)}
                    style={{
                      padding: '8px 14px',
                      borderRadius: '8px',
                      border: 'none',
                      background: 'transparent',
                      color: 'var(--text-secondary)',
                      fontSize: '12px',
                      fontWeight: '600',
                      cursor: 'pointer',
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={handleSaveConfig}
                    disabled={saveState.loading}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      padding: '8px 16px',
                      borderRadius: '8px',
                      border: 'none',
                      background: 'var(--accent-blue)',
                      color: '#FFFFFF',
                      fontSize: '12px',
                      fontWeight: '800',
                      cursor: 'pointer',
                      boxShadow: '0 2px 8px rgba(37, 99, 235, 0.3)',
                    }}
                  >
                    {saveState.loading ? <RefreshCw size={13} className="spin" /> : <Check size={13} />}
                    <span>Save & Activate</span>
                  </button>
                </div>
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
      return `<code style="background: ${isUser ? 'rgba(255,255,255,0.2)' : 'var(--bg-surface)'}; color: ${isUser ? '#FFFFFF' : 'var(--text-primary)'}; padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; font-weight: 700;">${c}</code>`;
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
