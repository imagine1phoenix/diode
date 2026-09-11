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
    color: '#DC2626',
    bg: '#FEE2E2',
    border: '#FECACA',
    glow: 'none',
  },
  high: {
    label: 'High',
    color: '#D97706',
    bg: '#FEF3C7',
    border: '#FDE68A',
    glow: 'none',
  },
  medium: {
    label: 'Medium',
    color: '#CA8A04',
    bg: '#FEF9C3',
    border: '#FEF08A',
    glow: 'none',
  },
  low: {
    label: 'Low',
    color: '#0284C7',
    bg: '#E0F2FE',
    border: '#BAE6FD',
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
    const seen = new Set();
    return alerts.filter((alert) => {
      // Defensive deduplication key
      const key = alert.alert_id || `${alert.flow_id}-${alert.threat_class}-${alert.timestamp}`;
      if (seen.has(key)) return false;
      seen.add(key);

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

  const downloadDossier = (alert, e) => {
    e.stopPropagation();
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
  };

  const toggleExpand = (alertId, e) => {
    e.stopPropagation();
    setExpandedAlertId(expandedAlertId === alertId ? null : alertId);
  };

  return (
    <div style={{
      background: '#FFFFFF',
      border: '1px solid #E2E8F0',
      borderRadius: '16px',
      boxShadow: '0 1px 3px 0 rgb(0 0 0 / 0.05)',
      padding: '20px',
      display: 'flex',
      flexDirection: 'column',
    }}>
      {/* Table Header & Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h2 style={{
              fontSize: '16px',
              fontWeight: '900',
              color: '#0F172A',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '-0.01em',
            }}>
              <span>Normalized Live Threat Intelligence Stream</span>
            </h2>
            <span style={{
              fontSize: '10.5px',
              fontFamily: 'var(--font-mono)',
              fontWeight: '700',
              padding: '2px 8px',
              borderRadius: '6px',
              background: '#F1F5F9',
              color: '#334155',
              border: '1px solid #CBD5E1',
            }}>
              {filteredAlerts.length} Events
            </span>
          </div>
          <p style={{ fontSize: '11.5px', color: '#64748B', marginTop: '2px', fontWeight: '500' }}>
            Real-time normalized security events with MITRE ATT&CK mapping & passive explainability
          </p>
        </div>

        {/* Filter Toolbar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          {/* Search Box */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: '#F8FAFC',
            border: '1px solid #CBD5E1',
            borderRadius: '8px',
            padding: '6px 12px',
          }}>
            <Search size={14} color="#64748B" />
            <input
              type="text"
              placeholder="Search Flow 5-Tuple, IP, JA3, DNS Query..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: '#0F172A',
                fontSize: '11.5px',
                width: '260px',
                fontWeight: '500',
              }}
            />
          </div>

          {/* Threat Class Dropdown */}
          <select
            value={threatFilter}
            onChange={(e) => setThreatFilter(e.target.value)}
            style={{
              background: '#F8FAFC',
              border: '1px solid #CBD5E1',
              borderRadius: '8px',
              padding: '6px 10px',
              color: '#0F172A',
              fontSize: '11.5px',
              fontWeight: '600',
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
          <div style={{ display: 'flex', gap: '2px', background: '#F1F5F9', padding: '2px', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  background: severityFilter === sev ? '#0F172A' : 'transparent',
                  color: severityFilter === sev ? '#FFFFFF' : '#64748B',
                  border: 'none',
                  padding: '4px 8px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: '700',
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
            title="Export CSV Forensic Report"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              background: '#FFFFFF',
              border: '1px solid #CBD5E1',
              color: '#1E293B',
              padding: '6px 10px',
              borderRadius: '8px',
              fontSize: '11px',
              fontWeight: '600',
              cursor: 'pointer',
            }}
          >
            <Download size={13} />
            <span>CSV</span>
          </button>
        </div>
      </div>

      {/* Feed Table View */}
      <div style={{ overflowX: 'auto', maxHeight: '580px', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
        <table style={{ width: '100%', minWidth: '780px', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{
              borderBottom: '1px solid #E2E8F0',
              background: '#F8FAFC',
              color: '#64748B',
              fontSize: '10.5px',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              fontWeight: '700',
            }}>
              <th style={{ padding: '9px 10px', width: '80px' }}>Time</th>
              <th style={{ padding: '9px 10px', width: '155px' }}>Threat & MITRE</th>
              <th style={{ padding: '9px 8px', width: '76px' }}>Severity</th>
              <th style={{ padding: '9px 8px', width: '98px' }}>Confidence</th>
              <th style={{ padding: '9px 10px', width: '165px' }}>Connection Path</th>
              <th style={{ padding: '9px 10px' }}>Key Evidence</th>
              <th style={{ padding: '9px 10px', textAlign: 'right', width: '200px', whiteSpace: 'nowrap' }}>Actions</th>
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
                        borderBottom: isExpanded ? 'none' : '1px solid #F1F5F9',
                        background: isExpanded ? '#F8FAFC' : 'transparent',
                        transition: 'background-color 0.15s',
                        cursor: 'pointer',
                      }}
                      onMouseEnter={(e) => {
                        if (!isExpanded) e.currentTarget.style.backgroundColor = '#F8FAFC';
                      }}
                      onMouseLeave={(e) => {
                        if (!isExpanded) e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      {/* Time Column with burst offset */}
                      <td style={{ padding: '8px 10px', fontSize: '11px', color: '#64748B', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600' }}>{timeStr}</span>
                          {isSameSecond && (
                            <span
                              className="has-tooltip"
                              style={{
                                fontSize: '9px',
                                color: '#0284C7',
                                background: '#E0F2FE',
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
                      <td style={{ padding: '8px 10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{
                            width: '24px',
                            height: '24px',
                            borderRadius: '6px',
                            background: `${threatConfig.color}15`,
                            border: `1px solid ${threatConfig.color}30`,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0,
                          }}>
                            <ThreatIcon size={13} color={threatConfig.color} />
                          </div>
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                              <span style={{ fontWeight: '700', color: '#0F172A', fontSize: '12px', whiteSpace: 'nowrap' }}>
                                {threatConfig.label}
                              </span>
                              <span
                                className="has-tooltip"
                                style={{
                                  fontSize: '9px',
                                  fontFamily: 'var(--font-mono)',
                                  fontWeight: '700',
                                  padding: '1px 5px',
                                  borderRadius: '3px',
                                  background: '#EEF2FF',
                                  color: '#4338CA',
                                  border: '1px solid #C7D2FE',
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
                      <td style={{ padding: '8px 8px' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          padding: '2px 7px',
                          borderRadius: '4px',
                          fontSize: '10px',
                          fontWeight: '800',
                          textTransform: 'uppercase',
                          letterSpacing: '0.04em',
                          color: sevConfig.color,
                          background: sevConfig.bg,
                          border: `1px solid ${sevConfig.border}`,
                          whiteSpace: 'nowrap',
                        }}>
                          {alert.severity}
                        </span>
                      </td>

                      {/* Calibrated Confidence Meter */}
                      <td style={{ padding: '8px 8px' }}>
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
                                    background: barIdx <= filledBars ? confLevelColor : '#E2E8F0',
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
                          <span style={{ fontSize: '10px', color: '#64748B', lineHeight: 1, whiteSpace: 'nowrap' }}>
                            {confLevelLabel}
                          </span>
                        </div>
                      </td>

                      {/* Connection Path */}
                      <td style={{ padding: '8px 10px' }}>
                        <div className="has-tooltip" style={{ cursor: 'help' }}>
                          <div style={{ fontSize: '11.5px', fontWeight: '600', color: '#0F172A', display: 'flex', alignItems: 'center', gap: '4px', whiteSpace: 'nowrap' }}>
                            <span>{flow.src}</span>
                            <span style={{ color: '#94A3B8' }}>→</span>
                            <span style={{ color: flow.isAggregate ? '#2563EB' : '#0F172A' }}>{flow.dst}</span>
                          </div>
                          {flow.service && (
                            <div style={{ fontSize: '10px', color: '#64748B', marginTop: '1px' }}>
                              {flow.service}
                            </div>
                          )}
                          <div className="tooltip">
                            Raw 5-Tuple: {alert.flow_id}
                          </div>
                        </div>
                      </td>

                      {/* Key Evidence (Un-truncated Explainability Column) */}
                      <td style={{ padding: '8px 10px', minWidth: '260px' }}>
                        <div style={{
                          fontSize: '11.5px',
                          lineHeight: '1.45',
                          color: '#334155',
                          wordBreak: 'break-word',
                          fontWeight: '500',
                        }}>
                          {plainWhy}
                        </div>
                      </td>

                      {/* Actions: Copilot + Inspect + PCAP Dossier */}
                      <td style={{ padding: '8px 10px', textAlign: 'right', whiteSpace: 'nowrap', width: '200px' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', justifyContent: 'flex-end' }}>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (onOpenTriage) onOpenTriage(alert);
                            }}
                            title="Open Diode Copilot (Air-Gapped SLM)"
                            style={{
                              background: '#EFF6FF',
                              border: '1px solid #BFDBFE',
                              color: '#1D4ED8',
                              padding: '3px 8px',
                              borderRadius: '6px',
                              fontSize: '10.5px',
                              fontWeight: '700',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '3px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <Sparkles size={11} color="#2563EB" />
                            <span>Copilot</span>
                          </button>

                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectAlert(alert);
                            }}
                            title="Inspect full telemetry & heuristics"
                            style={{
                              background: '#F1F5F9',
                              border: '1px solid #CBD5E1',
                              color: '#0F172A',
                              padding: '3px 8px',
                              borderRadius: '6px',
                              fontSize: '10.5px',
                              fontWeight: '700',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '3px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <span>Inspect</span>
                            <ExternalLink size={10} />
                          </button>

                          <button
                            onClick={(e) => downloadDossier(alert, e)}
                            title="Export Forensic PCAP Dossier"
                            style={{
                              background: '#0F172A',
                              border: 'none',
                              color: '#FFFFFF',
                              padding: '3px 8px',
                              borderRadius: '6px',
                              fontSize: '10.5px',
                              fontWeight: '700',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '3px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <Download size={10} />
                            <span>Dossier</span>
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* Expandable Forensic Drawer */}
                    {isExpanded && (
                      <tr style={{
                        borderBottom: '1px solid #E2E8F0',
                        background: '#F8FAFC',
                      }}>
                        <td colSpan={7} style={{ padding: '12px 18px 16px 18px' }}>
                          <div className="accordion-content" style={{
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px',
                            background: '#FFFFFF',
                            padding: '14px 18px',
                            borderRadius: '10px',
                            border: '1px solid #E2E8F0',
                            boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
                          }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <Sparkles size={15} color="#2563EB" />
                                <span style={{ fontSize: '11.5px', fontWeight: '800', color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                                  Telemetry Explainability Record
                                </span>
                              </div>
                              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#64748B' }}>
                                Event ID: {alert.alert_id}
                              </span>
                            </div>

                            {/* Natural Language Explanation */}
                            <p style={{ fontSize: '12.5px', color: '#334155', lineHeight: 1.5, margin: 0 }}>
                              {plainWhy}
                            </p>

                            {/* Actions & Triggered Features */}
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', paddingTop: '8px', borderTop: '1px solid #F1F5F9' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                <span style={{ fontSize: '11px', color: '#64748B', fontWeight: '600' }}>Triggered Signals:</span>
                                {(alert.evidence?.features_triggered || []).map((feat, idx) => (
                                  <span
                                    key={idx}
                                    style={{
                                      fontSize: '10px',
                                      fontFamily: 'var(--font-mono)',
                                      fontWeight: '600',
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      background: '#F1F5F9',
                                      color: '#334155',
                                      border: '1px solid #E2E8F0',
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
                                    background: 'linear-gradient(135deg, #4F46E5, #7C3AED)',
                                    border: 'none',
                                    color: '#FFFFFF',
                                    fontSize: '11px',
                                    fontWeight: '700',
                                    padding: '5px 12px',
                                    borderRadius: '6px',
                                    cursor: 'pointer',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '5px',
                                  }}
                                >
                                  <Bot size={12} color="#FFFFFF" />
                                  <span>Air-Gapped SLM Triage Playbook</span>
                                </button>

                                <button
                                  onClick={() => onSelectAlert(alert)}
                                  style={{
                                    background: 'transparent',
                                    border: 'none',
                                    color: '#2563EB',
                                    fontSize: '11px',
                                    fontWeight: '700',
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
