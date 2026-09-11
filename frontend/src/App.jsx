import React, { useState } from 'react';
import Header from './components/Header';
import StatsCards from './components/StatsCards';
import ThreatDonutChart from './components/ThreatDonutChart';
import SeverityBarChart from './components/SeverityBarChart';
import TimelineAreaChart from './components/TimelineAreaChart';
import AlertTable from './components/AlertTable';
import EvidenceModal from './components/EvidenceModal';
import SimulateModal from './components/SimulateModal';
import { useAlertStream } from './hooks/useAlertStream';

export default function App() {
  const {
    alerts,
    stats,
    timeline,
    connected,
    isSimulating,
    simulateAttack,
    refresh,
  } = useAlertStream();

  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isSimulateOpen, setIsSimulateOpen] = useState(false);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Navigation Header */}
      <Header
        connected={connected}
        throughput={stats.throughput}
        totalAlerts={stats.total_alerts}
        onOpenSimulate={() => setIsSimulateOpen(true)}
        onRefresh={refresh}
      />

      {/* Main SOC Dashboard Viewport */}
      <main style={{ flex: 1, padding: '24px 28px', maxWidth: '1600px', width: '100%', margin: '0 auto' }}>
        {/* Metric Summary Cards */}
        <StatsCards stats={stats} />

        {/* Analytics Charts Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
          gap: '20px',
        }}>
          <ThreatDonutChart threatStats={stats.by_threat_class} />
          <SeverityBarChart severityStats={stats.by_severity} />
          <TimelineAreaChart timeline={timeline} />
        </div>

        {/* Live Streaming Alert Table */}
        <AlertTable alerts={alerts} onSelectAlert={(a) => setSelectedAlert(a)} />
      </main>

      {/* Footer */}
      <footer style={{
        padding: '20px 28px',
        borderTop: '1px solid var(--bg-card-border)',
        textAlign: 'center',
        fontSize: '12px',
        color: 'var(--text-muted)',
      }}>
        Smart India Hackathon • Unidirectional Data Diode AI Threat Detection Architecture (PRD §5 Compliant)
      </footer>

      {/* Forensics Drill-down Modal */}
      <EvidenceModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />

      {/* Attack Injection Console */}
      <SimulateModal
        isOpen={isSimulateOpen}
        onClose={() => setIsSimulateOpen(false)}
        onSimulate={simulateAttack}
        isSimulating={isSimulating}
      />
    </div>
  );
}
