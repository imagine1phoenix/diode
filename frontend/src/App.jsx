import React, { useState } from 'react';
import Header from './components/Header';
import StatsCards from './components/StatsCards';
import AlertTable from './components/AlertTable';
import ThreatRadarPanel from './components/ThreatRadarPanel';
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
      <main style={{ flex: 1, padding: '18px 24px', maxWidth: '1680px', width: '100%', margin: '0 auto' }}>
        {/* Executive Metric Summary Strip */}
        <StatsCards stats={stats} />

        {/* Primary Workspace: Alert Feed (Hero) + Threat Radar Panel */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1fr) 380px',
          gap: '20px',
          alignItems: 'start',
        }} className="soc-grid">
          {/* Hero Focal Point: Live Streaming Alert Feed */}
          <section style={{ minWidth: 0 }}>
            <AlertTable alerts={alerts} onSelectAlert={(a) => setSelectedAlert(a)} />
          </section>

          {/* Secondary Telemetry: Threat Vector & Velocity Radar */}
          <section style={{ minWidth: 0 }}>
            <ThreatRadarPanel stats={stats} timeline={timeline} />
          </section>
        </div>
      </main>

      {/* Footer */}
      <footer style={{
        padding: '16px 24px',
        borderTop: '1px solid var(--bg-card-border)',
        textAlign: 'center',
        fontSize: '11px',
        color: 'var(--text-muted)',
      }}>
        Smart India Hackathon • Unidirectional Physical Data Diode Tap • AI Threat Classification Pipeline
      </footer>

      {/* Forensics Drill-down Modal */}
      <EvidenceModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />

      {/* Safe Demo Attack Simulation Console */}
      <SimulateModal
        isOpen={isSimulateOpen}
        onClose={() => setIsSimulateOpen(false)}
        onSimulate={simulateAttack}
        isSimulating={isSimulating}
      />
    </div>
  );
}
