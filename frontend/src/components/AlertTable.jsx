import React, { useState, useMemo } from 'react';
import {
  Search, Filter, Download, ExternalLink, ChevronDown, ChevronRight,
  Shield, Radio, Globe, ShieldAlert, Cpu, ArrowUpRight, CheckCircle2,
  AlertTriangle, Sparkles, Clock, Eye, Bot, Lock
} from 'lucide-react';
import { THREAT_CONFIG } from './ThreatDonutChart';

const SEVERITY_CONFIG = {
  critical: {
    label: 'Critical',
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.14)',
    border: 'rgba(239, 68, 68, 0.35)',
    glow: '0 0 10px rgba(239, 68, 68, 0.25)',
  },
  high: {
    label: 'High',
    color: '#f97316',
    bg: 'rgba(249, 115, 22, 0.14)',
    border: 'rgba(249, 115, 22, 0.35)',
    glow: 'none',
  },
  medium: {
    label: 'Medium',
    color: '#eab308',
    bg: 'rgba(234, 179, 8, 0.14)',
    border: 'rgba(234, 179, 8, 0.35)',
    glow: 'none',
  },
  low: {
    label: 'Low',
    color: '#06b6d4',
    bg: 'rgba(6, 182, 212, 0.14)',
    border: 'rgba(6, 182, 212, 0.35)',
    glow: 'none',
  },
};

const THREAT_ICONS = {
  ddos: ShieldAlert,
  recon_scan: Cpu,
  c2_beaconing: Radio,
  dga_dns: Globe,
  encrypted_malware: Shield,
  exfiltration: ArrowUpRight,
};

const MITRE_TABLE = {
  ddos: { technique: 'T1498', tactic: 'TA0040', name: 'Network Denial of Service' },
  recon_scan: { technique: 'T1595', tactic: 'TA0043', name: 'Active Scanning' },
  c2_beaconing: { technique: 'T1071', tactic: 'TA0011', name: 'App Layer Protocol' },
  dga_dns: { technique: 'T1568', tactic: 'TA0011', name: 'Dynamic Resolution' },
  encrypted_malware: { technique: 'T1573', tactic: 'TA0005', name: 'Encrypted Channel' },
  exfiltration: { technique: 'T1048', tactic: 'TA0010', name: 'Exfiltration Over Alt Protocol' },
};

// Common port mapping helper
function getPortService(port, proto = 'TCP') {
  const p = parseInt(port, 10);
  if (p === 443) return 'HTTPS';
  if (p === 80) return 'HTTP';
  if (p === 53) return 'DNS';
  if (p === 22) return 'SSH';
  if (p === 8080) return 'HTTP-Alt';
  if (p === 8443) return 'HTTPS-Alt';
  if (p === 3389) return 'RDP';
  if (p === 445) return 'SMB';
  return `${proto} :${p}`;
}

// Parse 5-tuple into plain-language connection route
function parseFlowId(flowId) {
  if (!flowId) return { src: '—', dst: '—', service: '', isAggregate: false };

  // Aggregate / Sweep flows
  if (flowId.includes('0.0.0.0:0') || flowId.includes(':0-')) {
    const parts = flowId.split('-');
    if (parts.length >= 2) {
      const [s, d] = parts;
      const sIp = s.split(':')[0];
      const dIp = d.split(':')[0];
      if (sIp === '0.0.0.0') {
        return {
          src: 'Distributed Sources',
          dst: dIp,
          service: 'Volumetric Flood',
          isAggregate: true,
        };
      }
      if (dIp === '0.0.0.0') {
        return {
          src: sIp,
          dst: 'Subnet Targets',
          service: 'Port Sweep',
          isAggregate: true,
        };
      }
    }
  }

  // Standard 5-tuple
  const match = flowId.match(/^([0-9.]+):([0-9]+)-([0-9.]+):([0-9]+)-([a-z0-9]+)$/i);
  if (match) {
    const [, srcIp, srcPort, dstIp, dstPort, proto] = match;
    return {
      src: srcIp,
      srcPort,
      dst: dstIp,
      dstPort,
      service: getPortService(dstPort, proto.toUpperCase()),
      proto: proto.toUpperCase(),
      isAggregate: false,
    };
  }

  return { src: flowId, dst: '', service: '', isAggregate: false };
}

// Plain-English explanation generator
function generatePlainEnglishWhy(alert) {
  const tc = alert.threat_class || '';
  const evidence = alert.evidence || {};
  const stats = evidence.supporting_stats || {};
  const triggered = evidence.features_triggered || [];

  switch (tc) {
    case 'ddos': {
      const rate = stats.flow_rate_per_sec || stats.arrival_rate;
      return rate
        ? `Abnormal packet burst (${Math.round(rate).toLocaleString()} packets/sec) detected overwhelming the destination host.`
        : 'High-volume packet flood detected saturating receiver bandwidth beyond baseline threshold.';
    }
    case 'dga_dns': {
      const mlProb = stats.ml_dga_probability;
      const domain = stats.domain || stats.queried_domain || 'randomized query';
      if (mlProb) {
        return `AI Random Forest model flagged query '${domain}' as ${Math.round(mlProb * 100)}% likely machine-generated (high lexical entropy).`;
      }
      return `Algorithmic domain name '${domain}' detected with anomalous character randomness and non-human bigram distribution.`;
    }
    case 'recon_scan': {
      const ports = stats.distinct_dst_ports || stats.scanned_ports_count;
      return ports
        ? `Single source host systematically probed ${ports} distinct destination ports in rapid succession.`
        : 'Sequential port probing pattern detected attempting to map open network services.';
    }
    case 'c2_beaconing': {
      const conns = stats.host_pair_connections;
      return `Periodic heartbeat connections (${conns || 'multi-session'} pulses) identified with strict timing regularity (FFT spectral peak confirmed).`;
    }
    case 'exfiltration': {
      return 'Large sustained outbound payload transfer detected exceeding the physical one-way egress policy.';
    }
    case 'encrypted_malware': {
      return 'Encrypted TLS handshake fingerprint matches known malicious payload profile (JA3 signature correlation).';
    }
    default:
      return triggered.length > 0
        ? `Flagged due to behavioral anomalies: ${triggered.slice(0, 3).map(t => t.replace(/_/g, ' ')).join(', ')}.`
        : 'Statistical deviation detected in flow arrival pattern.';
  }
}

export default function AlertTable({ alerts = [], onSelectAlert, onOpenTriage }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [threatFilter, setThreatFilter] = useState('all');
  const [expandedAlertId, setExpandedAlertId] = useState(null);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      if (severityFilter !== 'all' && alert.severity !== severityFilter) return false;
      if (threatFilter !== 'all' && alert.threat_class !== threatFilter) return false;
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const flow = (alert.flow_id || '').toLowerCase();
        const threat = (alert.threat_class || '').toLowerCase();
        const id = (alert.alert_id || '').toLowerCase();
        const mitre = (alert.mitre_technique || '').toLowerCase();
        return flow.includes(term) || threat.includes(term) || id.includes(term) || mitre.includes(term);
      }
      return true;
    });
  }, [alerts, severityFilter, threatFilter, searchTerm]);

  // Export CSV
  const exportCSV = () => {
    if (filteredAlerts.length === 0) return;
    const headers = ['alert_id', 'timestamp', 'threat_class', 'mitre_technique', 'severity', 'confidence', 'flow_id'];
    const rows = filteredAlerts.map((a) => [
      a.alert_id,
      a.timestamp,
      a.threat_class,
      a.mitre_technique || (MITRE_TABLE[a.threat_class]?.technique || 'T1498'),
      a.severity,
      a.confidence,
      `"${a.flow_id}"`,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `threat_alerts_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const toggleExpand = (alertId, e) => {
    e.stopPropagation();
    setExpandedAlertId(expandedAlertId === alertId ? null : alertId);
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
      {/* Table Header & Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: '700', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>Live Security Alert Feed</span>
            </h2>
            <span style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              padding: '2px 8px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(99, 102, 241, 0.15)',
              color: 'var(--accent-indigo)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
            }}>
              {filteredAlerts.length} Active Events
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Real-time normalized security events with MITRE ATT&CK mapping & AI auto-triage
          </p>
        </div>

        {/* Filter Toolbar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Search Box */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid var(--bg-card-border)',
            borderRadius: 'var(--radius-md)',
            padding: '6px 10px',
          }}>
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search IP, MITRE, domain..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: '#ffffff',
                fontSize: '12px',
                width: '160px',
              }}
            />
          </div>

          {/* Threat Class Dropdown */}
          <select
            value={threatFilter}
            onChange={(e) => setThreatFilter(e.target.value)}
            style={{
              background: 'rgba(15, 23, 42, 0.6)',
              border: '1px solid var(--bg-card-border)',
              borderRadius: 'var(--radius-md)',
              padding: '6px 10px',
              color: 'var(--text-secondary)',
              fontSize: '12px',
              outline: 'none',
              cursor: 'pointer',
            }}
          >
            <option value="all">All Threat Types</option>
            <option value="ddos">DDoS Flooding (T1498)</option>
            <option value="recon_scan">Recon & Scan (T1595)</option>
            <option value="c2_beaconing">Botnet C2 (T1071)</option>
            <option value="dga_dns">DGA / DNS Tunnel (T1568)</option>
            <option value="encrypted_malware">Encrypted Malware (T1573)</option>
            <option value="exfiltration">Data Exfiltration (T1048)</option>
          </select>

          {/* Severity Buttons */}
          <div style={{ display: 'flex', gap: '3px', background: 'rgba(15, 23, 42, 0.6)', padding: '2px', borderRadius: 'var(--radius-md)', border: '1px solid var(--bg-card-border)' }}>
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  background: severityFilter === sev ? 'var(--accent-indigo)' : 'transparent',
                  color: severityFilter === sev ? '#ffffff' : 'var(--text-muted)',
                  border: 'none',
                  padding: '4px 8px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '11px',
                  fontWeight: '600',
                  textTransform: 'capitalize',
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* CSV Export */}
          <button
            onClick={exportCSV}
            title="Export CSV Report"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              background: 'rgba(30, 41, 59, 0.6)',
              border: '1px solid var(--bg-card-border)',
              color: 'var(--text-secondary)',
              padding: '6px 10px',
              borderRadius: 'var(--radius-md)',
              fontSize: '11px',
              fontWeight: '500',
              cursor: 'pointer',
            }}
          >
            <Download size={13} />
            <span>CSV</span>
          </button>
        </div>
      </div>

      {/* Feed Table View */}
      <div style={{ overflowX: 'auto', maxHeight: '580px' }}>
        <table style={{ width: '100%', minWidth: '780px', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{
              borderBottom: '1px solid var(--bg-card-border)',
              color: 'var(--text-muted)',
              fontSize: '11px',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
            }}>
              <th style={{ padding: '8px 8px', width: '78px' }}>Time</th>
              <th style={{ padding: '8px 8px', width: '150px' }}>Threat & MITRE</th>
              <th style={{ padding: '8px 6px', width: '72px' }}>Severity</th>
              <th style={{ padding: '8px 6px', width: '95px' }}>Confidence</th>
              <th style={{ padding: '8px 8px', width: '160px' }}>Connection Path</th>
              <th style={{ padding: '8px 8px' }}>Key Evidence</th>
              <th style={{ padding: '8px 8px', textAlign: 'right', width: '135px', whiteSpace: 'nowrap' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)' }}>
                  No security alerts matching current filters
                </td>
              </tr>
            ) : (
              filteredAlerts.slice(0, 100).map((alert, index) => {
                const sevConfig = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.low;
                const threatConfig = THREAT_CONFIG[alert.threat_class] || { label: alert.threat_class, color: '#94a3b8' };
                const ThreatIcon = THREAT_ICONS[alert.threat_class] || AlertTriangle;
                const mitre = MITRE_TABLE[alert.threat_class] || { technique: alert.mitre_technique || 'T1498', tactic: 'TA0040', name: 'Network Threat' };

                // Smart timestamp formatting
                const alertDate = alert.timestamp ? new Date(alert.timestamp) : new Date();
                const timeStr = alertDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

                const prevAlert = index > 0 ? filteredAlerts[index - 1] : null;
                const isSameSecond = prevAlert && prevAlert.timestamp &&
                  new Date(prevAlert.timestamp).getSeconds() === alertDate.getSeconds() &&
                  new Date(prevAlert.timestamp).getMinutes() === alertDate.getMinutes();

                const confPercent = Math.round((alert.confidence || 0) * 100);

                let confLevelLabel = 'Signal';
                let confLevelColor = '#06b6d4';
                let filledBars = 1;
                if (confPercent >= 88) {
                  confLevelLabel = 'Confirmed';
                  confLevelColor = '#10b981';
                  filledBars = 4;
                } else if (confPercent >= 72) {
                  confLevelLabel = 'High';
                  confLevelColor = '#f97316';
                  filledBars = 3;
                } else if (confPercent >= 55) {
                  confLevelLabel = 'Probable';
                  confLevelColor = '#eab308';
                  filledBars = 2;
                } else {
                  confLevelLabel = 'Early Signal';
                  confLevelColor = '#06b6d4';
                  filledBars = 1;
                }

                const flow = parseFlowId(alert.flow_id);
                const isExpanded = expandedAlertId === alert.alert_id;
                const plainWhy = generatePlainEnglishWhy(alert);

                return (
                  <React.Fragment key={alert.alert_id}>
                    <tr
                      onClick={(e) => toggleExpand(alert.alert_id, e)}
                      style={{
                        borderBottom: isExpanded ? 'none' : '1px solid rgba(148, 163, 184, 0.06)',
                        background: isExpanded ? 'rgba(99, 102, 241, 0.06)' : 'transparent',
                        transition: 'background-color 0.15s',
                        cursor: 'pointer',
                      }}
                      onMouseEnter={(e) => {
                        if (!isExpanded) e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)';
                      }}
                      onMouseLeave={(e) => {
                        if (!isExpanded) e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      {/* Time Column with burst offset */}
                      <td style={{ padding: '8px 8px', fontSize: '11px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{timeStr}</span>
                          {isSameSecond && (
                            <span
                              className="has-tooltip"
                              style={{
                                fontSize: '9px',
                                color: 'var(--accent-cyan)',
                                background: 'rgba(6, 182, 212, 0.12)',
                                padding: '1px 4px',
                                borderRadius: '3px',
                                fontFamily: 'var(--font-mono)',
                                cursor: 'help',
                              }}
                            >
                              burst
                              <div className="tooltip">High-speed burst packet ingestion</div>
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Threat Type & MITRE Badge */}
                      <td style={{ padding: '8px 8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                          <div style={{
                            width: '22px',
                            height: '22px',
                            borderRadius: 'var(--radius-sm)',
                            background: `rgba(255, 255, 255, 0.06)`,
                            border: `1px solid rgba(255, 255, 255, 0.12)`,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0,
                          }}>
                            <ThreatIcon size={12} color={threatConfig.color} />
                          </div>
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                              <span style={{ fontWeight: '600', color: '#f8fafc', fontSize: '12px', whiteSpace: 'nowrap' }}>
                                {threatConfig.label}
                              </span>
                              <span
                                className="has-tooltip"
                                style={{
                                  fontSize: '9px',
                                  fontFamily: 'var(--font-mono)',
                                  fontWeight: '700',
                                  padding: '1px 4px',
                                  borderRadius: '3px',
                                  background: 'rgba(99, 102, 241, 0.15)',
                                  color: 'var(--accent-indigo)',
                                  border: '1px solid rgba(99, 102, 241, 0.3)',
                                  cursor: 'help',
                                  whiteSpace: 'nowrap',
                                }}
                              >
                                {alert.mitre_technique || mitre.technique}
                                <div className="tooltip">
                                  MITRE ATT&CK: {mitre.name} ({alert.mitre_tactic || mitre.tactic})
                                </div>
                              </span>
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Severity Badge */}
                      <td style={{ padding: '8px 6px' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          padding: '2px 6px',
                          borderRadius: 'var(--radius-sm)',
                          fontSize: '10px',
                          fontWeight: '700',
                          textTransform: 'uppercase',
                          letterSpacing: '0.04em',
                          color: sevConfig.color,
                          background: sevConfig.bg,
                          border: `1px solid ${sevConfig.border}`,
                          boxShadow: sevConfig.glow,
                          whiteSpace: 'nowrap',
                        }}>
                          {alert.severity}
                        </span>
                      </td>

                      {/* Calibrated Confidence Meter */}
                      <td style={{ padding: '8px 6px' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                            <div style={{ display: 'flex', gap: '2px' }}>
                              {[1, 2, 3, 4].map((barIdx) => (
                                <div
                                  key={barIdx}
                                  style={{
                                    width: '7px',
                                    height: '7px',
                                    borderRadius: '2px',
                                    background: barIdx <= filledBars ? confLevelColor : 'rgba(255, 255, 255, 0.1)',
                                  }}
                                />
                              ))}
                            </div>
                            <span style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '11px',
                              fontWeight: '700',
                              color: confLevelColor,
                            }}>
                              {confPercent}%
                            </span>
                          </div>
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', lineHeight: 1, whiteSpace: 'nowrap' }}>
                            {confLevelLabel}
                          </span>
                        </div>
                      </td>

                      {/* Connection Path */}
                      <td style={{ padding: '8px 8px' }}>
                        <div className="has-tooltip" style={{ cursor: 'help' }}>
                          <div style={{ fontSize: '11.5px', fontWeight: '500', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '4px', whiteSpace: 'nowrap' }}>
                            <span>{flow.src}</span>
                            <span style={{ color: 'var(--text-muted)' }}>→</span>
                            <span style={{ color: flow.isAggregate ? 'var(--accent-cyan)' : '#ffffff' }}>{flow.dst}</span>
                          </div>
                          {flow.service && (
                            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '1px' }}>
                              {flow.service}
                            </div>
                          )}
                          <div className="tooltip">
                            Raw 5-Tuple: {alert.flow_id}
                          </div>
                        </div>
                      </td>

                      {/* Key Evidence */}
                      <td style={{ padding: '8px 8px', maxWidth: '190px' }}>
                        <div style={{
                          fontSize: '11px',
                          color: 'var(--text-secondary)',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}>
                          {plainWhy}
                        </div>
                      </td>

                      {/* Actions: AI Triage + Inspect */}
                      <td style={{ padding: '8px 8px', textAlign: 'right', whiteSpace: 'nowrap', width: '135px' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', justifyContent: 'flex-end' }}>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (onOpenTriage) onOpenTriage(alert);
                            }}
                            title="Run Air-Gapped GenAI SOC Analyst"
                            style={{
                              background: 'rgba(168, 85, 247, 0.15)',
                              border: '1px solid rgba(168, 85, 247, 0.35)',
                              color: '#d8b4fe',
                              padding: '3px 7px',
                              borderRadius: 'var(--radius-sm)',
                              fontSize: '10.5px',
                              fontWeight: '600',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '3px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <Bot size={11} color="#c084fc" />
                            <span>AI Triage</span>
                          </button>

                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectAlert(alert);
                            }}
                            title="Inspect full forensic record"
                            style={{
                              background: 'rgba(99, 102, 241, 0.12)',
                              border: '1px solid rgba(99, 102, 241, 0.25)',
                              color: 'var(--accent-indigo)',
                              padding: '3px 6px',
                              borderRadius: 'var(--radius-sm)',
                              fontSize: '10.5px',
                              fontWeight: '600',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '2px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <span>Inspect</span>
                            <ExternalLink size={10} />
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* Expandable Forensic Drawer */}
                    {isExpanded && (
                      <tr style={{
                        borderBottom: '1px solid rgba(148, 163, 184, 0.12)',
                        background: 'rgba(99, 102, 241, 0.04)',
                      }}>
                        <td colSpan={7} style={{ padding: '12px 18px 16px 18px' }}>
                          <div className="accordion-content" style={{
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px',
                            background: 'rgba(15, 23, 42, 0.65)',
                            padding: '14px 18px',
                            borderRadius: 'var(--radius-md)',
                            border: '1px solid rgba(99, 102, 241, 0.2)',
                          }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <Sparkles size={15} color="var(--accent-indigo)" />
                                <span style={{ fontSize: '12px', fontWeight: '700', color: '#f8fafc', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                                  Why This Was Flagged
                                </span>
                              </div>
                              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                Event ID: {alert.alert_id}
                              </span>
                            </div>

                            {/* Natural Language Explanation */}
                            <p style={{ fontSize: '13px', color: '#e2e8f0', lineHeight: 1.5 }}>
                              {plainWhy}
                            </p>

                            {/* Actions & Triggered Features */}
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', paddingTop: '6px', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Triggered Signals:</span>
                                {(alert.evidence?.features_triggered || []).map((feat, idx) => (
                                  <span
                                    key={idx}
                                    style={{
                                      fontSize: '10px',
                                      fontFamily: 'var(--font-mono)',
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      background: 'rgba(255, 255, 255, 0.08)',
                                      color: 'var(--text-secondary)',
                                    }}
                                  >
                                    {feat.replace(/_/g, ' ')}
                                  </span>
                                ))}
                              </div>

                              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                <button
                                  onClick={() => onOpenTriage && onOpenTriage(alert)}
                                  style={{
                                    background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(168, 85, 247, 0.25))',
                                    border: '1px solid rgba(168, 85, 247, 0.4)',
                                    color: '#f8fafc',
                                    fontSize: '11px',
                                    fontWeight: '600',
                                    padding: '4px 10px',
                                    borderRadius: 'var(--radius-sm)',
                                    cursor: 'pointer',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '5px',
                                  }}
                                >
                                  <Bot size={12} color="#c084fc" />
                                  <span>Air-Gapped SLM Triage Playbook</span>
                                </button>

                                <button
                                  onClick={() => onSelectAlert(alert)}
                                  style={{
                                    background: 'transparent',
                                    border: 'none',
                                    color: 'var(--accent-cyan)',
                                    fontSize: '11px',
                                    fontWeight: '600',
                                    cursor: 'pointer',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                  }}
                                >
                                  <span>Raw Telemetry JSON</span>
                                  <ExternalLink size={11} />
                                </button>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
