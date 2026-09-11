import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import StatsCards from './components/StatsCards';
import AlertTable from './components/AlertTable';
import ThreatGeoMap from './components/ThreatGeoMap';
import ThreatRadarPanel from './components/ThreatRadarPanel';
import EvidenceModal from './components/EvidenceModal';
import SimulateModal from './components/SimulateModal';
import AITriageDrawer from './components/AITriageDrawer';
import PipelineInspectorModal from './components/PipelineInspectorModal';
import { useAlertStream } from './hooks/useAlertStream';
import { List, Globe2, Bot, Activity, Zap, Sparkles } from 'lucide-react';

export default function App() {
  const {
    alerts,
    stats,
    timeline,
    connected,
    isSimulating,
    isRefreshing,
    simulateAttack,
    lastSimulationResult,
    refresh,
  } = useAlertStream();

  const [selectedAlert, setSelectedAlert] = useState(null);
  const [triageAlert, setTriageAlert] = useState(null);
  const [isSimulateOpen, setIsSimulateOpen] = useState(false);
  const [isInspectorOpen, setIsInspectorOpen] = useState(false);
  const [inspectorScenario, setInspectorScenario] = useState('all');
  const [inspectorResult, setInspectorResult] = useState(null);

  // Tab persistence: Remember user's tab choice across page reloads and refreshes
  const getInitialTab = () => {
    try {
      const hash = window.location.hash.replace('#', '');
      if (hash === 'map' || hash === 'feed') return hash;
      const stored = localStorage.getItem('sih_soc_active_tab');
      if (stored === 'map' || stored === 'feed') return stored;
    } catch (e) {}
    return 'feed';
  };

  const [activeTab, setActiveTab] = useState(getInitialTab);

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    try {
      localStorage.setItem('sih_soc_active_tab', tab);
      window.location.hash = tab;
    } catch (e) {}
  };

  // Sync with browser back/forward or manual hash changes
  useEffect(() => {
    const onHashChange = () => {
      const hash = window.location.hash.replace('#', '');
      if (hash === 'map' || hash === 'feed') {
        setActiveTab(hash);
      }
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const handleOpenInspectorWithScenario = (scenario, result = null) => {
    setInspectorScenario(scenario || 'all');
    setInspectorResult(result || lastSimulationResult);
    setIsInspectorOpen(true);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Navigation Header */}
      <Header
        connected={connected}
        throughput={stats.throughput}
        totalAlerts={stats.total_alerts}
        onOpenSimulate={() => setIsSimulateOpen(true)}
        onOpenInspector={() => handleOpenInspectorWithScenario('all')}
        onRefresh={refresh}
        isRefreshing={isRefreshing}
        isSimulating={isSimulating}
      />

      {/* Main SOC Dashboard Viewport */}
      <main style={{ flex: 1, padding: '18px 24px', maxWidth: '1680px', width: '100%', margin: '0 auto' }}>
        {/* Executive Metric Summary Strip */}
        <StatsCards stats={stats} />

        {/* Interactive Data Diode Pipeline Topology Banner (Jury Focus) */}
        <div style={{
          margin: '14px 0 16px',
          padding: '8px 16px',
          borderRadius: 'var(--radius-md)',
          background: isSimulating ? 'rgba(99, 102, 241, 0.16)' : 'rgba(15, 23, 42, 0.65)',
          border: isSimulating ? '1px solid rgba(99, 102, 241, 0.5)' : '1px solid var(--bg-card-border)',
          boxShadow: isSimulating ? '0 0 25px rgba(99, 102, 241, 0.25)' : 'none',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '10px',
          transition: 'all 0.3s ease',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
              <span style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: isSimulating ? 'var(--accent-cyan)' : 'var(--accent-emerald)',
              }} className={isSimulating ? 'pulse' : ''} />
              <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
                {isSimulating ? 'Active Ingest Stream' : 'Pipeline Topology'}
              </span>
            </div>

            {/* 5 Sequential Micro-Stages */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', flexWrap: 'wrap' }}>
              <span style={{
                padding: '2px 7px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(6, 182, 212, 0.12)',
                color: 'var(--accent-cyan)',
                border: '1px solid rgba(6, 182, 212, 0.3)',
                fontWeight: '600',
                whiteSpace: 'nowrap',
              }}>
                1. Optical Tap (Rx)
              </span>
              <span style={{ color: 'var(--text-muted)' }}>➔</span>
              <span style={{
                padding: '2px 7px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(99, 102, 241, 0.12)',
                color: '#a5b4fc',
                border: '1px solid rgba(99, 102, 241, 0.3)',
                fontWeight: '600',
                whiteSpace: 'nowrap',
              }}>
                2. 5-Tuple Assembler
              </span>
              <span style={{ color: 'var(--text-muted)' }}>➔</span>
              <span style={{
                padding: '2px 7px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(168, 85, 247, 0.12)',
                color: '#d8b4fe',
                border: '1px solid rgba(168, 85, 247, 0.3)',
                fontWeight: '600',
                whiteSpace: 'nowrap',
              }}>
                3. Feature Math (Entropy/FFT)
              </span>
              <span style={{ color: 'var(--text-muted)' }}>➔</span>
              <span style={{
                padding: '2px 7px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(236, 72, 153, 0.12)',
                color: '#f472b6',
                border: '1px solid rgba(236, 72, 153, 0.3)',
                fontWeight: '600',
                whiteSpace: 'nowrap',
              }}>
                4. Multi-Threat AI (RF & IF)
              </span>
              <span style={{ color: 'var(--text-muted)' }}>➔</span>
              <span style={{
                padding: '2px 7px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(16, 185, 129, 0.12)',
                color: 'var(--accent-emerald)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                fontWeight: '600',
                whiteSpace: 'nowrap',
              }}>
                5. SOC Dispatch
              </span>
            </div>
          </div>

          <button
            onClick={() => handleOpenInspectorWithScenario('all')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 12px',
              borderRadius: 'var(--radius-sm)',
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.25), rgba(6, 182, 212, 0.25))',
              border: '1px solid rgba(99, 102, 241, 0.4)',
              color: '#ffffff',
              fontSize: '11px',
              fontWeight: '600',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              flexShrink: 0,
              transition: 'all 0.15s',
            }}
          >
            <Activity size={13} color="var(--accent-cyan)" />
            <span>Open Interactive Pipeline Inspector</span>
            <span style={{
              fontSize: '9px',
              padding: '1px 5px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(255, 255, 255, 0.2)',
              fontWeight: '700',
            }}>
              JURY VIEW
            </span>
          </button>
        </div>

        {/* View Switcher Tabs: Alert Feed vs. Global Threat Map */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '14px',
        }}>
          <div style={{
            display: 'inline-flex',
            gap: '4px',
            background: 'rgba(15, 23, 42, 0.7)',
            padding: '4px',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--bg-card-border)',
          }}>
            <button
              onClick={() => handleTabChange('feed')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                borderRadius: 'var(--radius-sm)',
                border: 'none',
                background: activeTab === 'feed' ? 'var(--accent-indigo)' : 'transparent',
                color: activeTab === 'feed' ? '#ffffff' : 'var(--text-secondary)',
                fontWeight: '600',
                fontSize: '12px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <List size={14} />
              <span>Live Security Alert Feed</span>
            </button>

            <button
              onClick={() => handleTabChange('map')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                borderRadius: 'var(--radius-sm)',
                border: 'none',
                background: activeTab === 'map' ? 'var(--accent-cyan)' : 'transparent',
                color: activeTab === 'map' ? '#041017' : 'var(--text-secondary)',
                fontWeight: '600',
                fontSize: '12px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <Globe2 size={14} />
              <span>Global Threat Map (Dark Mode)</span>
            </button>
          </div>

          <div style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>Air-Gapped SLM Auto-Triage Enabled</span>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--accent-emerald)' }} />
          </div>
        </div>

        {/* Primary Workspace: Alert Feed / Threat Map (Hero) + Threat Radar Panel */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1fr) 350px',
          gap: '16px',
          alignItems: 'start',
        }} className="soc-grid">
          {/* Hero Focal Point: Active Tab View */}
          <section style={{ minWidth: 0 }}>
            {activeTab === 'feed' ? (
              <AlertTable
                alerts={alerts}
                onSelectAlert={(a) => setSelectedAlert(a)}
                onOpenTriage={(a) => setTriageAlert(a)}
              />
            ) : (
              <ThreatGeoMap alerts={alerts} />
            )}
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
        Smart India Hackathon • Unidirectional Physical Data Diode Tap • AI Threat Classification Pipeline • MITRE ATT&CK Mapped
      </footer>

      {/* Forensics Drill-down Modal */}
      <EvidenceModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />

      {/* Air-Gapped GenAI SOC Analyst Drawer */}
      <AITriageDrawer
        alert={triageAlert}
        isOpen={!!triageAlert}
        onClose={() => setTriageAlert(null)}
      />

      {/* Safe Demo Attack Simulation Console */}
      <SimulateModal
        isOpen={isSimulateOpen}
        onClose={() => setIsSimulateOpen(false)}
        onSimulate={simulateAttack}
        isSimulating={isSimulating}
        onOpenInspector={(sc, res) => handleOpenInspectorWithScenario(sc, res)}
      />

      {/* Live Pipeline Inspector & Jury Walkthrough Modal */}
      <PipelineInspectorModal
        isOpen={isInspectorOpen}
        onClose={() => setIsInspectorOpen(false)}
        scenario={inspectorScenario}
        simulationResult={inspectorResult || lastSimulationResult}
        onRunSimulation={simulateAttack}
        onInspectAlert={(alert) => setSelectedAlert(alert)}
      />
    </div>
  );
}
