import React, { useState, useEffect } from 'react';
import {
  X, Bot, Sparkles, ShieldAlert, Terminal, Copy, Check, ExternalLink,
  Cpu, Lock, ArrowRight, Activity, AlertTriangle
} from 'lucide-react';

export default function AITriageDrawer({ alert, isOpen, onClose }) {
  const [triageData, setTriageData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [copiedAll, setCopiedAll] = useState(false);

  useEffect(() => {
    if (!isOpen || !alert) {
      setTriageData(null);
      return;
    }

    let isMounted = true;
    setLoading(true);

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

  if (!isOpen || !alert) return null;

  const handleCopyCmd = (cmd, index) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyPlaybook = () => {
    if (!triageData) return;
    const text = [
      `=== AI SOC ANALYST INCIDENT PLAYBOOK ===`,
      `Event ID: ${alert.alert_id}`,
      `Threat: ${alert.threat_class} (${alert.severity.toUpperCase()})`,
      `MITRE: ${triageData.mitre_mapping?.technique} - ${triageData.mitre_mapping?.technique_name}`,
      ``,
      `EXECUTIVE SUMMARY:`,
      triageData.executive_summary,
      ``,
      `RECOMMENDED MITIGATION COMMANDS:`,
      ...(triageData.recommended_mitigation || []).map((m, i) => `${i + 1}. ${m}`),
    ].join('\n');

    navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  const mitre = triageData?.mitre_mapping;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.7)',
        backdropFilter: 'blur(6px)',
        zIndex: 120,
        display: 'flex',
        justifyContent: 'flex-end',
      }}
      onClick={onClose}
    >
      <div
        className="glass-panel accordion-content"
        style={{
          width: '100%',
          maxWidth: '560px',
          height: '100%',
          background: '#090d18',
          borderLeft: '1px solid rgba(99, 102, 241, 0.3)',
          boxShadow: '-10px 0 40px rgba(0, 0, 0, 0.8)',
          padding: '28px 24px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header with Close */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '42px',
              height: '42px',
              borderRadius: 'var(--radius-md)',
              background: 'linear-gradient(135deg, #6366f1, #a855f7)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 16px rgba(99, 102, 241, 0.4)',
            }}>
              <Bot size={22} color="#ffffff" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 style={{ fontSize: '17px', fontWeight: '700', color: '#ffffff' }}>
                  AI SOC Analyst
                </h2>
                <span style={{
                  fontSize: '10px',
                  fontWeight: '700',
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-full)',
                  background: 'rgba(16, 185, 129, 0.15)',
                  color: 'var(--accent-emerald)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}>
                  <Lock size={10} />
                  AIR-GAPPED SLM
                </span>
              </div>
              <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                On-Premise Small Language Model • Local Diode Enclave Execution
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '4px',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Enclave Execution Pill */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.65)',
          borderRadius: 'var(--radius-md)',
          padding: '10px 14px',
          border: '1px solid var(--bg-card-border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
          fontSize: '11px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cpu size={14} color="var(--accent-indigo)" />
            <span style={{ color: 'var(--text-secondary)' }}>Model:</span>
            <span style={{ color: '#ffffff', fontWeight: '600' }}>
              {triageData?.model || 'Llama-3-8B-Instruct (On-Prem)'}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
            <Activity size={13} />
            <span>{triageData?.inference_latency_ms || 24} ms</span>
          </div>
        </div>

        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, gap: '14px', color: 'var(--text-secondary)' }}>
            <Sparkles size={28} className="pulse" color="var(--accent-indigo)" />
            <div style={{ fontSize: '13px', fontWeight: '500' }}>Evaluating passive telemetry via on-premise SLM...</div>
          </div>
        ) : triageData ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', flex: 1 }}>
            {/* MITRE ATT&CK Mapping Card */}
            {mitre && (
              <div style={{
                background: 'rgba(99, 102, 241, 0.08)',
                border: '1px solid rgba(99, 102, 241, 0.25)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 16px',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '10px', color: 'var(--accent-indigo)', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    MITRE ATT&CK Matrix Alignment
                  </span>
                  <a
                    href={mitre.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      fontSize: '10px',
                      color: 'var(--accent-cyan)',
                      textDecoration: 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '3px',
                    }}
                  >
                    <span>KnowledgeBase</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <span style={{
                    fontSize: '12px',
                    fontWeight: '700',
                    fontFamily: 'var(--font-mono)',
                    color: '#ffffff',
                    background: 'rgba(99, 102, 241, 0.2)',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    border: '1px solid rgba(99, 102, 241, 0.4)',
                  }}>
                    {mitre.technique}
                  </span>
                  <span style={{ fontSize: '13px', fontWeight: '600', color: '#f8fafc' }}>
                    {mitre.technique_name}
                  </span>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    • Tactic: {mitre.tactic} ({mitre.tactic_name})
                  </span>
                </div>
              </div>
            )}

            {/* Executive Diagnosis */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                <Sparkles size={14} color="var(--accent-indigo)" />
                <h3 style={{ fontSize: '12px', fontWeight: '700', color: '#ffffff', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Executive Incident Assessment
                </h3>
              </div>
              <div style={{
                background: 'rgba(15, 23, 42, 0.6)',
                border: '1px solid var(--bg-card-border)',
                borderRadius: 'var(--radius-md)',
                padding: '14px 16px',
                fontSize: '13px',
                color: '#e2e8f0',
                lineHeight: 1.6,
              }}>
                {triageData.executive_summary}
              </div>
            </div>

            {/* Forensic Signals */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                <ShieldAlert size={14} color="var(--sev-high)" />
                <h3 style={{ fontSize: '12px', fontWeight: '700', color: '#ffffff', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Passive Optical Forensic Proof
                </h3>
              </div>
              <div style={{
                background: 'rgba(15, 23, 42, 0.6)',
                border: '1px solid var(--bg-card-border)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}>
                {(triageData.forensic_signals || []).map((sig, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '12px', color: '#cbd5e1' }}>
                    <span style={{ color: 'var(--accent-cyan)', marginTop: '2px' }}>•</span>
                    <span>{sig}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Actionable Network Mitigation Playbook */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Terminal size={14} color="var(--accent-emerald)" />
                  <h3 style={{ fontSize: '12px', fontWeight: '700', color: '#ffffff', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Remediation Playbook (Manual Steps)
                  </h3>
                </div>
                <button
                  onClick={handleCopyPlaybook}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: copiedAll ? 'var(--accent-emerald)' : 'var(--text-secondary)',
                    fontSize: '11px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  {copiedAll ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copiedAll ? 'Playbook Copied' : 'Copy All'}</span>
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {(triageData.recommended_mitigation || []).map((step, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: 'rgba(15, 23, 42, 0.8)',
                      border: '1px solid rgba(148, 163, 184, 0.15)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px 14px',
                      fontSize: '12px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '10px' }}>
                      <div style={{ color: '#f1f5f9', lineHeight: 1.4, flex: 1, fontFamily: step.includes('iptables') || step.includes('sysctl') ? 'var(--font-mono)' : 'var(--font-sans)', fontSize: step.includes('iptables') ? '11px' : '12px' }}>
                        {step}
                      </div>
                      <button
                        onClick={() => handleCopyCmd(step, idx)}
                        title="Copy command"
                        style={{
                          background: 'rgba(255, 255, 255, 0.06)',
                          border: 'none',
                          color: copiedIndex === idx ? 'var(--accent-emerald)' : 'var(--text-muted)',
                          padding: '4px',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                        }}
                      >
                        {copiedIndex === idx ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '40px 0' }}>
            No triage data available
          </div>
        )}
      </div>
    </div>
  );
}
