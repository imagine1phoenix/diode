import React from 'react';
import { AlertOctagon, Flame, ShieldAlert, Cpu } from 'lucide-react';

export default function StatsCards({ stats }) {
  const total = stats.total_alerts || 0;
  const critical = stats.by_severity?.critical || 0;
  const high = stats.by_severity?.high || 0;
  const medium = stats.by_severity?.medium || 0;
  const low = stats.by_severity?.low || 0;

  const cards = [
    {
      title: 'Total Alerts',
      value: total.toLocaleString(),
      subtext: 'Ingested across sliding windows',
      icon: ShieldAlert,
      color: 'var(--accent-cyan)',
      bg: 'rgba(6, 182, 212, 0.1)',
      border: 'rgba(6, 182, 212, 0.25)',
    },
    {
      title: 'Critical Threats',
      value: critical.toLocaleString(),
      subtext: 'Requires immediate SOC escalation',
      icon: AlertOctagon,
      color: 'var(--sev-critical)',
      bg: 'var(--sev-critical-bg)',
      border: 'rgba(239, 68, 68, 0.35)',
      isCritical: critical > 0,
    },
    {
      title: 'High Severity',
      value: high.toLocaleString(),
      subtext: 'Recon sweeps & high-vol DDoS',
      icon: Flame,
      color: 'var(--sev-high)',
      bg: 'var(--sev-high-bg)',
      border: 'rgba(249, 115, 22, 0.25)',
    },
    {
      title: 'Medium & Low',
      value: (medium + low).toLocaleString(),
      subtext: `Med: ${medium} • Low: ${low}`,
      icon: Cpu,
      color: 'var(--accent-indigo)',
      bg: 'rgba(99, 102, 241, 0.1)',
      border: 'rgba(99, 102, 241, 0.25)',
    },
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
      gap: '20px',
      margin: '24px 0',
    }}>
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className="glass-panel"
            style={{
              padding: '20px 24px',
              border: `1px solid ${card.border}`,
              background: `linear-gradient(180deg, ${card.bg} 0%, rgba(15, 23, 42, 0.75) 100%)`,
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            {card.isCritical && (
              <span style={{
                position: 'absolute',
                top: '12px',
                right: '12px',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: 'var(--sev-critical)',
                boxShadow: '0 0 10px var(--sev-critical)',
              }} className="pulse" />
            )}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
              <span style={{ fontSize: '13px', fontWeight: '500', color: 'var(--text-secondary)' }}>
                {card.title}
              </span>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: 'var(--radius-sm)',
                background: card.bg,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <Icon size={20} color={card.color} />
              </div>
            </div>
            <div style={{
              fontSize: '28px',
              fontWeight: '800',
              color: '#ffffff',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '-0.02em',
              lineHeight: 1.1,
            }}>
              {card.value}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>
              {card.subtext}
            </div>
          </div>
        );
      })}
    </div>
  );
}
