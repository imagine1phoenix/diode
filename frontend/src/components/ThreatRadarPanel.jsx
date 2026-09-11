import React, { useMemo } from 'react';
import ThreatDonutChart from './ThreatDonutChart';
import SeverityBarChart from './SeverityBarChart';
import TimelineAreaChart from './TimelineAreaChart';
import { BarChart3 } from 'lucide-react';

export default function ThreatRadarPanel({ stats = {}, timeline = [], alerts = [] }) {
  // Compute synchronized distribution directly from alerts if available
  const activeThreatStats = useMemo(() => {
    if (alerts && alerts.length > 0) {
      const counts = {};
      alerts.forEach((a) => {
        const tc = a.threat_class || 'unknown';
        counts[tc] = (counts[tc] || 0) + 1;
      });
      return counts;
    }
    return stats?.by_threat_class || {};
  }, [alerts, stats?.by_threat_class]);

  const activeSeverityStats = useMemo(() => {
    if (alerts && alerts.length > 0) {
      const counts = {};
      alerts.forEach((a) => {
        const sev = a.severity || 'low';
        counts[sev] = (counts[sev] || 0) + 1;
      });
      return counts;
    }
    return stats?.by_severity || {};
  }, [alerts, stats?.by_severity]);

  return (
    <aside style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <BarChart3 size={16} color="#2563EB" />
          <h2 style={{ fontSize: '14px', fontWeight: '800', color: 'var(--text-primary)', letterSpacing: '-0.01em', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
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
      <ThreatDonutChart threatStats={activeThreatStats} />
      <SeverityBarChart severityStats={activeSeverityStats} />
      <TimelineAreaChart timeline={timeline} />
    </aside>
  );
}
