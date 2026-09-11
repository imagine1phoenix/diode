import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import TacticalOverviewCards from './components/TacticalOverviewCards';
import AlertTable from './components/AlertTable';
import ThreatGeoMap from './components/ThreatGeoMap';
import ThreatRadarPanel from './components/ThreatRadarPanel';
import EvidenceModal from './components/EvidenceModal';
import SimulateModal from './components/SimulateModal';
import AITriageDrawer from './components/AITriageDrawer';
import PipelineInspectorModal from './components/PipelineInspectorModal';
import NotificationModal from './components/NotificationModal';
import { useAlertStream } from './hooks/useAlertStream';
import { List, Globe2, Bot, Activity, Zap, Sparkles, ChevronDown, ChevronUp, BarChart3 } from 'lucide-react';

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
  const [isNotificationOpen, setIsNotificationOpen] = useState(false);
  const [inspectorScenario, setInspectorScenario] = useState('all');
  const [inspectorResult, setInspectorResult] = useState(null);
  const [inspectorStage, setInspectorStage] = useState(1);

  // Secondary panel states: Kept collapsed/toggleable so Live Alert Feed remains the primary focal element
  const [showTopology, setShowTopology] = useState(false);
  const [showRadar, setShowRadar] = useState(false);

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

  const handleOpenInspectorWithScenario = (scenario, result = null, stage = 1) => {
    setInspectorScenario(scenario || 'all');
    setInspectorResult(result || lastSimulationResult);
    setInspectorStage(stage || 1);
    setIsInspectorOpen(true);
  };

  const handleOpenCopilot = () => {
    const target = alerts[0] || {
      alert_id: 'drishti-core-01',
      threat_class: 'ddos',
      severity: 'critical',
      flow_id: '33.34.239.181:21476-10.0.0.1:80-tcp',
      confidence: 0.96,
      evidence: { features_triggered: ['high_flow_rate', 'packet_size_uniformity'] }
    };
    setTriageAlert(target);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-main)' }}>
      {/* Navigation Header */}
      <Header
        connected={connected}
        throughput={stats.throughput}
        totalAlerts={stats.total_alerts}
        onOpenSimulate={() => setIsSimulateOpen(true)}
        onOpenInspector={() => handleOpenInspectorWithScenario('all')}
        onOpenCopilot={handleOpenCopilot}
        onOpenNotifications={() => setIsNotificationOpen(true)}
        onRefresh={refresh}
        isRefreshing={isRefreshing}
        isSimulating={isSimulating}
      />

      {/* Main SOC Dashboard Viewport */}
      <main style={{ flex: 1, padding: '20px 28px', maxWidth: '1720px', width: '100%', margin: '0 auto' }}>
        {/* Tactical Overview Cards (Command Center Corridors) */}
        <TacticalOverviewCards
          stats={stats}
          alerts={alerts}
          onInspectTarget={(a) => {
            if (a) setSelectedAlert(a);
            else if (alerts[0]) setSelectedAlert(alerts[0]);
          }}
          onAnalyzeMetrics={() => handleOpenInspectorWithScenario('all')}
          onExportPcap={() => {
            const targetAlert = alerts.find((a) => a.threat_class === 'c2_beaconing') || alerts[0] || {
              alert_id: 'NET-DRISHTI-C2-01',
              threat_class: 'c2_beaconing',
              severity: 'critical',
              flow_id: '192.168.1.30:49210-203.0.113.42:443-tcp',
              confidence: 0.94,
              evidence: { features_triggered: ['fft_spectral_peak', 'low_jitter'] },
            };
            const dossier = {
              dossier_title: `FORENSIC_TELEMETRY_DOSSIER_${targetAlert.alert_id}`,
              export_timestamp: new Date().toISOString(),
              enclave: 'NET-DRISHTI AIR-GAPPED TELEMETRY ENCLAVE',
              tap_mode: 'PASSIVE_OPTICAL_DIODE_SIMPLEX_RX',
              hardware_constraint: 'ZERO_TX_WRITES_VERIFIED',
              alert: targetAlert,
              recommended_capture_syntax: `tcpdump -nn -s 0 -i eth0 'host 192.168.1.30 and host 203.0.113.42' -w /opt/forensics/c2_beacon_${Date.now()}.pcap`,
            };
            const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `FORENSIC_DOSSIER_${targetAlert.alert_id}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          }}
          onLiveStream={() => {
            const el = document.getElementById('live-threat-feed');
            if (el) el.scrollIntoView({ behavior: 'smooth' });
          }}
        />

        {/* Collapsible Pipeline Topology Bar (Tactical White Card) */}
        <div style={{
          margin: '0 0 18px',
          borderRadius: '14px',
          background: '#FFFFFF',
          border: '1px solid #E2E8F0',
          boxShadow: '0 1px 3px 0 rgb(0 0 0 / 0.04)',
          overflow: 'hidden',
          transition: 'all 0.2s ease',
        }}>
          {/* Summary Strip */}
          <div
            style={{
              padding: '8px 16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              cursor: 'pointer',
              userSelect: 'none',
              gap: '10px',
              flexWrap: 'wrap',
            }}
            onClick={() => setShowTopology(!showTopology)}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
              <span style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                background: isSimulating ? '#0284C7' : '#15803D',
                flexShrink: 0,
              }} className={isSimulating ? 'pulse' : ''} />
              <span style={{ fontSize: '11px', fontWeight: '800', color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                Pipeline Architecture:
              </span>
              <span style={{ fontSize: '11px', color: '#64748B', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: '500' }}>
                Optical Tap (Rx) ➔ 5-Tuple Assembler ➔ Feature Math ➔ Multi-Threat AI ➔ SOC Dispatch
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleOpenInspectorWithScenario('all');
                }}
                title="Open interactive step-by-step pipeline inspector"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  background: '#EFF6FF',
                  border: '1px solid #DBEAFE',
                  color: '#1D4ED8',
                  fontSize: '11px',
                  fontWeight: '700',
                  cursor: 'pointer',
                }}
              >
                <Activity size={12} color="#2563EB" />
                <span>Pipeline Inspector</span>
              </button>
              <button
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#64748B',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '3px',
                  fontSize: '11px',
                  fontWeight: '600',
                  cursor: 'pointer',
                }}
              >
                {showTopology ? (
                  <><span>Hide Stages</span><ChevronUp size={13} /></>
                ) : (
                  <><span>Show Stages</span><ChevronDown size={13} /></>
                )}
              </button>
            </div>
          </div>

          {/* Expanded 5 Micro-Stages */}
          {showTopology && (
            <div style={{
              padding: '12px 16px',
              borderTop: '1px solid #E2E8F0',
              background: '#F8FAFC',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '11px',
              flexWrap: 'wrap',
            }}>
              <span
                onClick={() => handleOpenInspectorWithScenario('all', null, 1)}
                title="Inspect Stage 1: Optical Diode Ingest"
                style={{
                  padding: '4px 9px',
                  borderRadius: '6px',
                  background: '#E0F2FE',
                  color: '#0369A1',
                  border: '1px solid #BAE6FD',
                  fontWeight: '700',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease',
                }}
              >
                1. Optical Tap (Rx-Only Physical Diode)
              </span>
              <span style={{ color: '#94A3B8' }}>➔</span>
              <span
                onClick={() => handleOpenInspectorWithScenario('all', null, 2)}
                title="Inspect Stage 2: 5-Tuple Assembler"
                style={{
                  padding: '4px 9px',
                  borderRadius: '6px',
                  background: '#EEF2FF',
                  color: '#4338CA',
                  border: '1px solid #C7D2FE',
                  fontWeight: '700',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease',
                }}
              >
                2. 5-Tuple Assembler & Sliding Window
              </span>
              <span style={{ color: '#94A3B8' }}>➔</span>
              <span
                onClick={() => handleOpenInspectorWithScenario('all', null, 3)}
                title="Inspect Stage 3: Feature Extraction Math"
                style={{
                  padding: '4px 9px',
                  borderRadius: '6px',
                  background: '#F5F3FF',
                  color: '#6D28D9',
                  border: '1px solid #DDD6FE',
                  fontWeight: '700',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease',
                }}
              >
                3. Feature Math (Entropy, FFT, Inter-Arrival)
              </span>
              <span style={{ color: '#94A3B8' }}>➔</span>
              <span
                onClick={() => handleOpenInspectorWithScenario('all', null, 4)}
                title="Inspect Stage 4: Multi-Threat AI Classifiers"
                style={{
                  padding: '4px 9px',
                  borderRadius: '6px',
                  background: '#FDF2F8',
                  color: '#BE185D',
                  border: '1px solid #FBCFE8',
                  fontWeight: '700',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease',
                }}
              >
                4. Multi-Threat AI Classifiers (RF, IF & Signatures)
              </span>
              <span style={{ color: '#94A3B8' }}>➔</span>
              <span
                onClick={() => handleOpenInspectorWithScenario('all', null, 5)}
                title="Inspect Stage 5: SOC Dispatch & Alert Store"
                style={{
                  padding: '4px 9px',
                  borderRadius: '6px',
                  background: '#DCFCE7',
                  color: '#15803D',
                  border: '1px solid #BBF7D0',
                  fontWeight: '700',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease',
                }}
              >
                5. SOC Dispatch & Alert Store
              </span>
            </div>
          )}
        </div>

        {/* View Switcher & Analytics Controls */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '16px',
          gap: '12px',
          flexWrap: 'wrap',
        }}>
          {/* Feed vs Map View Switcher */}
          <div style={{
            display: 'inline-flex',
            gap: '4px',
            background: '#FFFFFF',
            padding: '4px',
            borderRadius: '10px',
            border: '1px solid #CBD5E1',
            boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
          }}>
            <button
              onClick={() => handleTabChange('feed')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                background: activeTab === 'feed' ? '#0F172A' : 'transparent',
                color: activeTab === 'feed' ? '#FFFFFF' : '#64748B',
                fontWeight: '700',
                fontSize: '12px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <List size={14} />
              <span>Live Threat Feed</span>
            </button>

            <button
              onClick={() => handleTabChange('map')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                background: activeTab === 'map' ? '#2563EB' : 'transparent',
                color: activeTab === 'map' ? '#FFFFFF' : '#64748B',
                fontWeight: '700',
                fontSize: '12px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <Globe2 size={14} />
              <span>Global Threat Map</span>
            </button>
          </div>

          {/* Toggle for Analytics Sidebar */}
          <button
            onClick={() => setShowRadar(!showRadar)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              borderRadius: '8px',
              background: showRadar ? '#0F172A' : '#FFFFFF',
              border: '1px solid #CBD5E1',
              color: showRadar ? '#FFFFFF' : '#1E293B',
              fontSize: '12px',
              fontWeight: '700',
              cursor: 'pointer',
              boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
              transition: 'all 0.15s ease',
            }}
          >
            <BarChart3 size={14} color={showRadar ? '#38BDF8' : '#2563EB'} />
            <span>{showRadar ? 'Hide Threat Analytics' : 'Threat Analytics Radar'}</span>
          </button>
        </div>

        {/* Primary Workspace: Live Alert Feed (Hero Focal Element) + Optional Analytics Radar */}
        <div
          id="live-threat-feed"
          style={{
            display: 'grid',
            gridTemplateColumns: showRadar ? 'minmax(0, 1fr) 350px' : 'minmax(0, 1fr)',
            gap: '16px',
            alignItems: 'start',
          }}
          className="soc-grid"
        >
          {/* Hero Focal Point: Active Tab View (takes 100% width when radar is hidden) */}
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

          {/* Secondary Telemetry: Threat Vector & Velocity Radar (Behind Toggle) */}
          {showRadar && (
            <section style={{ minWidth: 0 }}>
              <ThreatRadarPanel stats={stats} timeline={timeline} alerts={alerts} />
            </section>
          )}
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
        initialStage={inspectorStage}
      />

      {/* Outbound Real Alert Channels Configuration Modal */}
      <NotificationModal
        isOpen={isNotificationOpen}
        onClose={() => setIsNotificationOpen(false)}
      />
    </div>
  );
}
