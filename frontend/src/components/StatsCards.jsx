import React from 'react';
import { AlertOctagon, Flame, ShieldAlert, Layers } from 'lucide-react';

export default function StatsCards({ stats }) {
  const total = stats.total_alerts || 0;
  const critical = stats.by_severity?.critical || 0;
  const high = stats.by_severity?.high || 0;
  const medium = stats.by_severity?.medium || 0;
  const low = stats.by_severity?.low || 0;

  const activeThreatClasses = Object.keys(stats.by_threat_class || {}).filter(
    (k) => (stats.by_threat_class[k] || 0) > 0
  ).length;

  const cards = [
    {
      title: 'Total Detected Threats',
      value: total.toLocaleString(),
      subtext: 'Normalized security events',
      icon: ShieldAlert,
      color: 'var(--accent-cyan)',
      bg: 'rgba(6, 182, 212, 0.08)',
      border: 'rgba(6, 182, 212, 0.2)',
    },
    {
      title: 'Critical Incidents',
      value: critical.toLocaleString(),
      subtext: 'Multi-feature confirmed',
      icon: AlertOctagon,
      color: 'var(--sev-critical)',
      bg: 'var(--sev-critical-bg)',
      border: 'rgba(239, 68, 68, 0.3)',
      isCritical: critical > 0,
    },
    {
      title: 'High & Medium Alerts',
      value: (high + medium).toLocaleString(),
      subtext: `High: ${high} • Medium: ${medium}`,
      icon: Flame,
      color: 'var(--sev-high)',
      bg: 'var(--sev-high-bg)',
      border: 'rgba(249, 115, 22, 0.2)',
    },
    {
      title: 'Active Threat Vectors',
      value: `${activeThreatClasses} / 6`,
      subtext: 'Classes detected in stream',
      icon: Layers,
      color: 'var(--accent-indigo)',
      bg: 'rgba(99, 102, 241, 0.08)',
      border: 'rgba(99, 102, 241, 0.2)',
    },
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
      gap: '14px',
      marginBottom: '18px',
    }}>
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className="glass-panel"
            style={{
              padding: '14px 18px',
              border: `1px solid ${card.border}`,
              background: `linear-gradient(180deg, ${card.bg} 0%, rgba(15, 23, 42, 0.7) 100%)`,
              position: 'relative',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
            }}
          >
            {card.isCritical && (
              <span style={{
                position: 'absolute',
                top: '10px',
                right: '10px',
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                background: 'var(--sev-critical)',
                boxShadow: '0 0 8px var(--sev-critical)',
              }} className="pulse" />
            )}
            <div>
              <div style={{ fontSize: '11px', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '3px' }}>
                {card.title}
              </div>
              <div style={{
                fontSize: '22px',
                fontWeight: '800',
                color: '#ffffff',
                fontFamily: 'var(--font-mono)',
                letterSpacing: '-0.02em',
                lineHeight: 1.1,
              }}>
                {card.value}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                {card.subtext}
              </div>
            </div>
            <div style={{
              width: '38px',
              height: '38px',
              borderRadius: 'var(--radius-md)',
              background: card.bg,
              border: `1px solid ${card.border}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}>
              <Icon size={19} color={card.color} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
