import React, { useState } from 'react';
import { X, Copy, Check, ShieldAlert, Sparkles, FileText, Activity, Download } from 'lucide-react';
import { THREAT_CONFIG } from './ThreatDonutChart';

export default function EvidenceModal({ alert, onClose }) {
  const [copied, setCopied] = useState(false);
  const [dossierDownloaded, setDossierDownloaded] = useState(false);

  if (!alert) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadDossier = () => {
    const dossier = {
      dossier_title: `FORENSIC_TELEMETRY_DOSSIER_${alert.alert_id}`,
      export_timestamp: new Date().toISOString(),
      enclave: "NET-DRISHTI AIR-GAPPED TELEMETRY ENCLAVE",
      tap_mode: "PASSIVE_OPTICAL_DIODE_SIMPLEX_RX",
      hardware_constraint: "ZERO_TX_WRITES_VERIFIED",
      alert,
      recommended_capture_syntax: `tcpdump -nn -s 0 -i eth0 'host ${alert.flow_id?.split('-')[0]?.split(':')[0] || 'any'}' -w /opt/forensics/${alert.alert_id}.pcap`,
    };

    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `NET_DRISHTI_${alert.alert_id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setDossierDownloaded(true);
    setTimeout(() => setDossierDownloaded(false), 2000);
  };

  const evidence = alert.evidence || {};
  const stats = evidence.supporting_stats || {};
  const triggered = evidence.features_triggered || [];
  const threatMeta = THREAT_CONFIG[alert.threat_class] || { label: alert.threat_class, color: '#2563EB' };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(15, 23, 42, 0.5)',
      backdropFilter: 'blur(6px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 100,
      padding: '20px',
    }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '680px',
          maxHeight: '85vh',
          overflowY: 'auto',
          padding: '26px',
          background: 'var(--bg-card)',
          borderRadius: '16px',
          border: '1px solid var(--border-subtle)',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.35)',
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
            background: 'var(--bg-surface-hover)',
            border: 'none',
            color: 'var(--text-secondary)',
            borderRadius: '50%',
            width: '28px',
            height: '28px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
          }}
        >
          <X size={16} />
        </button>

        {/* Modal Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '18px' }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'var(--critical-bg)',
            border: '1px solid var(--critical-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <ShieldAlert size={22} color="#DC2626" />
          </div>
          <div>
            <h2 style={{ fontSize: '17px', fontWeight: '800', color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              Incident Forensics & Telemetry Evidence
            </h2>
            <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
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
          <div style={{ background: 'var(--bg-surface)', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Threat Category</div>
            <div style={{ fontSize: '13px', fontWeight: '700', color: threatMeta.color }}>{threatMeta.label}</div>
          </div>
          <div style={{ background: 'var(--bg-surface)', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Severity Tier</div>
            <div style={{
              fontSize: '13px',
              fontWeight: '800',
              textTransform: 'uppercase',
              color: alert.severity === 'critical' ? '#DC2626' : alert.severity === 'high' ? '#D97706' : '#2563EB'
            }}>
              {alert.severity}
            </div>
          </div>
          <div style={{ background: 'var(--bg-surface)', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Model Confidence</div>
            <div style={{ fontSize: '13px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#2563EB' }}>
              {Math.round((alert.confidence || 0) * 100)}%
            </div>
          </div>
          <div style={{ background: 'var(--bg-surface)', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: '600' }}>Ingest Time</div>
            <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontWeight: '600' }}>
              {new Date(alert.timestamp).toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* Network Connection Path */}
        <div style={{ background: 'var(--bg-surface)', padding: '12px 14px', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '18px' }}>
          <div style={{ fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '4px', fontWeight: '700' }}>
            Unidirectional Optical Tap Flow Record
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-primary)', fontWeight: '700' }}>
            {alert.flow_id}
          </div>
        </div>

        {/* Features Triggered */}
        <div style={{ marginBottom: '18px' }}>
          <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '6px', textTransform: 'uppercase' }}>
            Activated Detection Heuristics
          </div>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {triggered.map((feat, i) => (
              <span key={i} style={{
                background: 'rgba(99, 102, 241, 0.15)',
                color: 'var(--accent-indigo)',
                border: '1px solid rgba(99, 102, 241, 0.3)',
                padding: '3px 8px',
                borderRadius: '6px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                fontWeight: '600',
              }}>
                {feat.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>

        {/* Supporting Statistics Table */}
        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '6px', textTransform: 'uppercase' }}>
            Telemetry Measurements & Metrics
          </div>
          <div style={{ background: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
              <tbody>
                {Object.entries(stats).map(([k, v], idx) => (
                  <tr key={k} style={{ borderBottom: idx !== Object.keys(stats).length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
                    <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: '600' }}>
                      {k.replace(/_/g, ' ')}
                    </td>
                    <td style={{ padding: '8px 12px', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: '700', textAlign: 'right', fontSize: '11px' }}>
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
            <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
              Standardized Threat JSON Record
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={handleDownloadDossier}
                style={{
                  background: 'var(--accent-blue)',
                  border: 'none',
                  color: '#FFFFFF',
                  fontSize: '11px',
                  fontWeight: '700',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                {dossierDownloaded ? <Check size={11} color="#4ADE80" /> : <Download size={11} />}
                <span>{dossierDownloaded ? 'Dossier Saved' : 'Export Dossier'}</span>
              </button>

              <button
                onClick={handleCopyJson}
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-input)',
                  color: 'var(--text-primary)',
                  fontSize: '11px',
                  fontWeight: '600',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                {copied ? <Check size={11} color="#15803D" /> : <Copy size={11} />}
                <span>{copied ? 'Copied' : 'Copy JSON'}</span>
              </button>
            </div>
          </div>
          <pre style={{
            background: '#0F172A',
            color: '#38BDF8',
            padding: '12px',
            borderRadius: '8px',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            maxHeight: '140px',
            overflow: 'auto',
            border: '1px solid #334155',
          }}>
            {JSON.stringify(alert, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}
