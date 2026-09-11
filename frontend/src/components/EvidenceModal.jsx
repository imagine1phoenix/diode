import React, { useState } from 'react';
import { X, Copy, Check, ShieldAlert, Sparkles, FileText, Activity } from 'lucide-react';
import { THREAT_CONFIG } from './ThreatDonutChart';

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
  const threatMeta = THREAT_CONFIG[alert.threat_class] || { label: alert.threat_class, color: '#6366f1' };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.78)',
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
          padding: '26px',
          background: '#0d1322',
          border: '1px solid rgba(99, 102, 241, 0.3)',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.85)',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Close Button */}
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '18px',
            right: '18px',
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
          }}
        >
          <X size={20} />
        </button>

        {/* Modal Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '18px' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <ShieldAlert size={22} color="var(--sev-critical)" />
          </div>
          <div>
            <h2 style={{ fontSize: '17px', fontWeight: '700', color: '#ffffff' }}>
              Incident Forensics & Telemetry Evidence
            </h2>
            <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              Event ID: {alert.alert_id}
            </div>
          </div>
        </div>

        {/* Key Attributes Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: '10px',
          marginBottom: '18px',
        }}>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Category</div>
            <div style={{ fontSize: '13px', fontWeight: '600', color: threatMeta.color }}>{threatMeta.label}</div>
          </div>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Severity Tier</div>
            <div style={{ fontSize: '13px', fontWeight: '700', textTransform: 'uppercase', color: alert.severity === 'critical' ? 'var(--sev-critical)' : alert.severity === 'high' ? 'var(--sev-high)' : 'var(--sev-medium)' }}>
              {alert.severity}
            </div>
          </div>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Model Confidence</div>
            <div style={{ fontSize: '13px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
              {Math.round((alert.confidence || 0) * 100)}%
            </div>
          </div>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Ingest Time</div>
            <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              {new Date(alert.timestamp).toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* Network Connection Path */}
        <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px 14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)', marginBottom: '18px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
            Network Connection & Target Flow
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--accent-cyan)' }}>
            {alert.flow_id}
          </div>
        </div>

        {/* Features Triggered */}
        <div style={{ marginBottom: '18px' }}>
          <div style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '6px', textTransform: 'uppercase' }}>
            Activated Detection Signals
          </div>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {triggered.map((feat, i) => (
              <span key={i} style={{
                background: 'rgba(99, 102, 241, 0.12)',
                color: 'var(--accent-indigo)',
                border: '1px solid rgba(99, 102, 241, 0.25)',
                padding: '3px 8px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
              }}>
                {feat.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>

        {/* Supporting Statistics Table */}
        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '6px', textTransform: 'uppercase' }}>
            Telemetry Measurements & Metrics
          </div>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--bg-card-border)', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
              <tbody>
                {Object.entries(stats).map(([k, v], idx) => (
                  <tr key={k} style={{ borderBottom: idx !== Object.keys(stats).length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none' }}>
                    <td style={{ padding: '7px 12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                      {k.replace(/_/g, ' ')}
                    </td>
                    <td style={{ padding: '7px 12px', color: '#ffffff', fontFamily: 'var(--font-mono)', fontWeight: '600', textAlign: 'right', fontSize: '11px' }}>
                      {typeof v === 'number' ? (Number.isInteger(v) ? v.toLocaleString() : v.toFixed(3)) : String(v)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Standardized JSON Record */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
              Standardized Detection JSON Record
            </span>
            <button
              onClick={handleCopyJson}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                background: 'rgba(30, 41, 59, 0.8)',
                border: '1px solid var(--bg-card-border)',
                color: copied ? 'var(--accent-emerald)' : 'var(--text-secondary)',
                padding: '3px 8px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '11px',
                cursor: 'pointer',
              }}
            >
              {copied ? <Check size={11} /> : <Copy size={11} />}
              {copied ? 'Copied' : 'Copy JSON'}
            </button>
          </div>
          <pre style={{
            background: '#070a12',
            padding: '12px',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--bg-card-border)',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            color: '#a5b4fc',
            overflowX: 'auto',
            maxHeight: '150px',
          }}>
            {JSON.stringify(alert, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}
