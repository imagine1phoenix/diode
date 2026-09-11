import React, { useState, useMemo } from 'react';
import { Search, Filter, Download, ExternalLink, ShieldCheck } from 'lucide-react';

const SEVERITY_BADGES = {
  critical: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.3)' },
  high: { color: '#f97316', bg: 'rgba(249, 115, 22, 0.15)', border: 'rgba(249, 115, 22, 0.3)' },
  medium: { color: '#eab308', bg: 'rgba(234, 179, 8, 0.15)', border: 'rgba(234, 179, 8, 0.3)' },
  low: { color: '#06b6d4', bg: 'rgba(6, 182, 212, 0.15)', border: 'rgba(6, 182, 212, 0.3)' },
};

export default function AlertTable({ alerts = [], onSelectAlert }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [threatFilter, setThreatFilter] = useState('all');

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      if (severityFilter !== 'all' && alert.severity !== severityFilter) return false;
      if (threatFilter !== 'all' && alert.threat_class !== threatFilter) return false;
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const flow = (alert.flow_id || '').toLowerCase();
        const threat = (alert.threat_class || '').toLowerCase();
        const id = (alert.alert_id || '').toLowerCase();
        return flow.includes(term) || threat.includes(term) || id.includes(term);
      }
      return true;
    });
  }, [alerts, severityFilter, threatFilter, searchTerm]);

  // Export CSV
  const exportCSV = () => {
    if (filteredAlerts.length === 0) return;
    const headers = ['alert_id', 'timestamp', 'flow_id', 'threat_class', 'severity', 'confidence'];
    const rows = filteredAlerts.map((a) => [
      a.alert_id,
      a.timestamp,
      `"${a.flow_id}"`,
      a.threat_class,
      a.severity,
      a.confidence,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `sih_threat_alerts_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="glass-panel" style={{ padding: '24px', marginTop: '24px' }}>
      {/* Table Header & Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '17px', fontWeight: '700', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>Live Security Alert Feed</span>
            <span style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              padding: '2px 8px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(99, 102, 241, 0.15)',
              color: 'var(--accent-indigo)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
            }}>
              {filteredAlerts.length} Matching
            </span>
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Real-time normalized stream from per-flow detection engines
          </p>
        </div>

        {/* Filter Toolbar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          {/* Search Box */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid var(--bg-card-border)',
            borderRadius: 'var(--radius-md)',
            padding: '7px 12px',
          }}>
            <Search size={15} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search IP, port, or flow..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: '#ffffff',
                fontSize: '13px',
                width: '180px',
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
              padding: '7px 12px',
              color: 'var(--text-secondary)',
              fontSize: '13px',
              outline: 'none',
              cursor: 'pointer',
            }}
          >
            <option value="all">All Threat Classes</option>
            <option value="ddos">DDoS / Flooding</option>
            <option value="recon_scan">Recon & Port Scan</option>
            <option value="c2_beaconing">Botnet C2 Beaconing</option>
            <option value="dga_dns">DGA / DNS Tunnel</option>
            <option value="encrypted_malware">Encrypted Malware</option>
            <option value="exfiltration">Data Exfiltration</option>
          </select>

          {/* Severity Buttons */}
          <div style={{ display: 'flex', gap: '4px', background: 'rgba(15, 23, 42, 0.6)', padding: '3px', borderRadius: 'var(--radius-md)', border: '1px solid var(--bg-card-border)' }}>
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  background: severityFilter === sev ? 'var(--accent-indigo)' : 'transparent',
                  color: severityFilter === sev ? '#ffffff' : 'var(--text-muted)',
                  border: 'none',
                  padding: '5px 10px',
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
            title="Download CSV Incident Report"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'rgba(30, 41, 59, 0.6)',
              border: '1px solid var(--bg-card-border)',
              color: 'var(--text-secondary)',
              padding: '7px 12px',
              borderRadius: 'var(--radius-md)',
              fontSize: '12px',
              fontWeight: '500',
              cursor: 'pointer',
            }}
          >
            <Download size={14} />
            CSV
          </button>
        </div>
      </div>

      {/* Alert Feed Table */}
      <div style={{ overflowX: 'auto', maxHeight: '520px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--bg-card-border)', color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              <th style={{ padding: '12px 14px' }}>Timestamp</th>
              <th style={{ padding: '12px 14px' }}>Threat Class</th>
              <th style={{ padding: '12px 14px' }}>Severity</th>
              <th style={{ padding: '12px 14px' }}>Confidence</th>
              <th style={{ padding: '12px 14px' }}>Flow Identifier (5-Tuple)</th>
              <th style={{ padding: '12px 14px', textAlign: 'right' }}>Forensics</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
                  No threat alerts matching current filters
                </td>
              </tr>
            ) : (
              filteredAlerts.slice(0, 100).map((alert) => {
                const sevBadge = SEVERITY_BADGES[alert.severity] || SEVERITY_BADGES.low;
                const timeStr = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—';
                const confPercent = Math.round((alert.confidence || 0) * 100);

                return (
                  <tr
                    key={alert.alert_id}
                    onClick={() => onSelectAlert(alert)}
                    style={{
                      borderBottom: '1px solid rgba(148, 163, 184, 0.06)',
                      transition: 'background-color 0.15s',
                      cursor: 'pointer',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)')}
                    onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {timeStr}
                    </td>
                    <td style={{ padding: '12px 14px', fontWeight: '600', color: '#f8fafc' }}>
                      {alert.threat_class}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <span style={{
                        display: 'inline-block',
                        padding: '3px 8px',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '11px',
                        fontWeight: '700',
                        textTransform: 'uppercase',
                        color: sevBadge.color,
                        background: sevBadge.bg,
                        border: `1px solid ${sevBadge.border}`,
                      }}>
                        {alert.severity}
                      </span>
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div style={{
                          width: '60px',
                          height: '6px',
                          borderRadius: 'var(--radius-full)',
                          background: 'rgba(255, 255, 255, 0.1)',
                          overflow: 'hidden',
                        }}>
                          <div style={{
                            width: `${confPercent}%`,
                            height: '100%',
                            background: confPercent > 80 ? 'var(--sev-critical)' : confPercent > 50 ? 'var(--sev-high)' : 'var(--accent-cyan)',
                          }} />
                        </div>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-secondary)' }}>
                          {confPercent}%
                        </span>
                      </div>
                    </td>
                    <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-cyan)' }}>
                      {alert.flow_id}
                    </td>
                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert);
                        }}
                        style={{
                          background: 'rgba(99, 102, 241, 0.15)',
                          border: '1px solid rgba(99, 102, 241, 0.3)',
                          color: 'var(--accent-indigo)',
                          padding: '4px 10px',
                          borderRadius: 'var(--radius-sm)',
                          fontSize: '11px',
                          fontWeight: '600',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                        }}
                      >
                        Inspect
                        <ExternalLink size={11} />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
