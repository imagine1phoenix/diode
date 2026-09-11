import React from 'react';
import ThreatDonutChart from './ThreatDonutChart';
import SeverityBarChart from './SeverityBarChart';
import TimelineAreaChart from './TimelineAreaChart';
import { BarChart3 } from 'lucide-react';

export default function ThreatRadarPanel({ stats, timeline }) {
  return (
    <aside style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <BarChart3 size={16} color="var(--accent-indigo)" />
          <h2 style={{ fontSize: '14px', fontWeight: '700', color: '#f8fafc', letterSpacing: '-0.01em' }}>
            Telemetry & Pattern Radar
          </h2>
        </div>
        <span style={{
          fontSize: '10px',
          fontWeight: '600',
          padding: '2px 8px',
          borderRadius: 'var(--radius-full)',
          background: 'rgba(99, 102, 241, 0.12)',
          color: 'var(--accent-indigo)',
          border: '1px solid rgba(99, 102, 241, 0.25)',
        }}>
          PASSIVE INGEST
        </span>
      </div>

      {/* 3 Compact Analytical Views */}
      <ThreatDonutChart threatStats={stats.by_threat_class} />
      <SeverityBarChart severityStats={stats.by_severity} />
      <TimelineAreaChart timeline={timeline} />
    </aside>
  );
}
