import React, { useState } from 'react';
import { X, Copy, Check, ShieldAlert, FileCode, CheckCircle2 } from 'lucide-react';

export default function EvidenceModal({ alert, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!alert) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const evidence = alert.evidence || {};
  const stats = evidence.supporting_stats || {};
  const triggered = evidence.features_triggered || [];

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 100,
      padding: '20px',
    }}
      onClick={onClose}
    >
      <div
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: '680px',
          maxHeight: '85vh',
          overflowY: 'auto',
          padding: '28px',
          background: '#0d1322',
          border: '1px solid rgba(99, 102, 241, 0.3)',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8)',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Close Button */}
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
          }}
        >
          <X size={20} />
        </button>

        {/* Modal Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(239, 68, 68, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <ShieldAlert size={22} color="var(--sev-critical)" />
          </div>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#ffffff' }}>
              Alert Forensics & Evidence Drill-Down
            </h2>
            <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              ID: {alert.alert_id}
            </div>
          </div>
        </div>

        {/* Key Attributes Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '12px',
          marginBottom: '20px',
        }}>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Class</div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: '#ffffff' }}>{alert.threat_class}</div>
          </div>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Severity</div>
            <div style={{ fontSize: '13px', fontWeight: '700', textTransform: 'uppercase', color: alert.severity === 'critical' ? 'var(--sev-critical)' : 'var(--sev-high)' }}>
              {alert.severity}
            </div>
          </div>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Confidence</div>
            <div style={{ fontSize: '13px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
              {Math.round((alert.confidence || 0) * 100)}%
            </div>
          </div>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Detected At</div>
            <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              {new Date(alert.timestamp).toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* 5-Tuple Flow Identification */}
        <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)', marginBottom: '20px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
            Flow 5-Tuple Specification
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--accent-cyan)' }}>
            {alert.flow_id}
          </div>
        </div>

        {/* Features Triggered */}
        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '8px', textTransform: 'uppercase' }}>
            Triggered Heuristic Features
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {triggered.map((feat, i) => (
              <span key={i} style={{
                background: 'rgba(99, 102, 241, 0.15)',
                color: 'var(--accent-indigo)',
                border: '1px solid rgba(99, 102, 241, 0.3)',
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '12px',
                fontWeight: '500',
                fontFamily: 'var(--font-mono)',
              }}>
                {feat}
              </span>
            ))}
          </div>
        </div>

        {/* Supporting Statistics Table */}
        <div style={{ marginBottom: '24px' }}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '8px', textTransform: 'uppercase' }}>
            Telemetry Supporting Statistics
          </div>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
              <tbody>
                {Object.entries(stats).map(([k, v], idx) => (
                  <tr key={k} style={{ borderBottom: idx !== Object.keys(stats).length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none' }}>
                    <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{k}</td>
                    <td style={{ padding: '8px 14px', color: '#ffffff', fontFamily: 'var(--font-mono)', fontWeight: '600', textAlign: 'right' }}>
                      {typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(3)) : String(v)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* JSON Copy & Raw View */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
              Standardized Alert Payload (PRD §6)
            </span>
            <button
              onClick={handleCopyJson}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: 'rgba(30, 41, 59, 0.8)',
                border: '1px solid var(--bg-card-border)',
                color: copied ? 'var(--accent-emerald)' : 'var(--text-secondary)',
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '11px',
                cursor: 'pointer',
              }}
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? 'Copied' : 'Copy JSON'}
            </button>
          </div>
          <pre style={{
            background: '#070a12',
            padding: '14px',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--bg-card-border)',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            color: '#a5b4fc',
            overflowX: 'auto',
            maxHeight: '160px',
          }}>
            {JSON.stringify(alert, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}
