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
          <BarChart3 size={16} color="#2563EB" />
          <h2 style={{ fontSize: '14px', fontWeight: '800', color: '#0F172A', letterSpacing: '-0.01em', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
            Telemetry & Pattern Radar
          </h2>
        </div>
        <span style={{
          fontSize: '10px',
          fontWeight: '700',
          padding: '2px 8px',
          borderRadius: '4px',
          background: '#EEF2FF',
          color: '#4338CA',
          border: '1px solid #C7D2FE',
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
