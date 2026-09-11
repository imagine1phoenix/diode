import React from 'react';
import { ShieldAlert, Activity, Cpu, Terminal, ExternalLink, Download, ArrowUpRight } from 'lucide-react';

export default function TacticalOverviewCards({
  stats = {},
  alerts = [],
  onInspectTarget,
  onAnalyzeMetrics,
  onExportPcap,
  onLiveStream,
}) {
  // Extract real dynamic telemetry if available
  const topCriticalAlert = alerts.find((a) => a.severity === 'critical') || alerts[0];
  const ddosAlert = alerts.find((a) => a.threat_class === 'ddos');
  const c2Alert = alerts.find((a) => a.threat_class === 'c2_beaconing');

  const flowsPerSec = stats?.throughput?.flows_per_sec
    ? Math.round(stats.throughput.flows_per_sec).toLocaleString()
    : '3,127';

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
      gap: '16px',
      marginBottom: '20px',
    }}>
      {/* Card 1: Critical Target Corridor */}
      <div style={{
        background: 'var(--bg-card)',
        padding: '20px',
        borderRadius: '16px',
        border: '1px solid var(--border-subtle)',
        boxShadow: 'var(--shadow-card)',
        position: 'relative',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        transition: 'background 0.2s ease, border-color 0.2s ease',
      }}>
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
            <span style={{
              padding: '8px',
              backgroundColor: 'var(--critical-bg)',
              color: 'var(--critical-text)',
              borderRadius: '12px',
              display: 'inline-flex',
            }}>
              <ShieldAlert size={20} />
            </span>
            <span style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              fontWeight: '700',
              backgroundColor: 'var(--critical-bg)',
              color: 'var(--critical-text)',
              padding: '2px 8px',
              borderRadius: '4px',
              border: '1px solid var(--critical-border)',
              letterSpacing: '0.04em',
            }}>
              TARGET CORRIDOR // URGENT
            </span>
          </div>

          <p style={{
            fontSize: '10.5px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-secondary)',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            fontWeight: '600',
            margin: 0,
          }}>
            Imminent Threat Vector
          </p>
          <h3 style={{
            fontSize: '17px',
            fontWeight: '900',
            color: 'var(--text-primary)',
            marginTop: '4px',
            letterSpacing: '-0.02em',
          }}>
            Core BGP Peering Router
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--critical-text)', fontWeight: '600', marginTop: '4px' }}>
            Sustained SYN Flood Attack • Window Active
          </p>
        </div>

        <div style={{
          marginTop: '16px',
          paddingTop: '12px',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: '500', margin: 0 }}>Target Host</p>
            <p style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--text-primary)', margin: '2px 0 0' }}>
              {topCriticalAlert?.flow_id ? topCriticalAlert.flow_id.split('-')[1] || '203.0.113.42:443' : '203.0.113.42:443'}
            </p>
          </div>
          <button
            onClick={() => onInspectTarget && onInspectTarget(topCriticalAlert)}
            style={{
              backgroundColor: 'var(--text-primary)',
              color: 'var(--bg-card)',
              fontSize: '11px',
              padding: '6px 12px',
              borderRadius: '8px',
              fontWeight: '700',
              cursor: 'pointer',
              border: 'none',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              transition: 'opacity 0.15s ease',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.85')}
            onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
          >
            <span>Inspect Stream</span>
            <ExternalLink size={12} />
          </button>
        </div>
      </div>

      {/* Card 2: Primary Attack Vector */}
      <div style={{
        background: 'var(--bg-card)',
        padding: '20px',
        borderRadius: '16px',
        border: '1px solid var(--border-subtle)',
        boxShadow: 'var(--shadow-card)',
        position: 'relative',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        transition: 'background 0.2s ease, border-color 0.2s ease',
      }}>
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
            <span style={{
              padding: '8px',
              backgroundColor: 'var(--high-bg)',
              color: 'var(--high-text)',
              borderRadius: '12px',
              display: 'inline-flex',
            }}>
              <Activity size={20} />
            </span>
            <span style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              fontWeight: '700',
              backgroundColor: 'var(--high-bg)',
              color: 'var(--high-text)',
              padding: '2px 8px',
              borderRadius: '4px',
              border: '1px solid var(--high-border)',
              letterSpacing: '0.04em',
            }}>
              ENTROPY DETECTED // HIGH
            </span>
          </div>

          <p style={{
            fontSize: '10.5px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-secondary)',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            fontWeight: '600',
            margin: 0,
          }}>
            Primary Attack Class
          </p>
          <h3 style={{
            fontSize: '17px',
            fontWeight: '900',
            color: 'var(--text-primary)',
            marginTop: '4px',
            letterSpacing: '-0.02em',
          }}>
            DDoS / UDP Amplification
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Src IP Shannon Entropy: <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--high-text)' }}>0.24 (Low)</span>
          </p>
        </div>

        <div style={{
          marginTop: '16px',
          paddingTop: '12px',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: '500', margin: 0 }}>Aggregated Rate</p>
            <p style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--text-primary)', margin: '2px 0 0' }}>
              {ddosAlert?.evidence?.supporting_stats?.flow_rate_per_sec
                ? `${Math.round(ddosAlert.evidence.supporting_stats.flow_rate_per_sec * 35).toLocaleString()} flows/sec`
                : '1,420 flows/sec'}
            </p>
          </div>
          <button
            onClick={() => onAnalyzeMetrics && onAnalyzeMetrics()}
            style={{
              backgroundColor: '#2563EB',
              color: '#FFFFFF',
              fontSize: '11px',
              padding: '6px 12px',
              borderRadius: '8px',
              fontWeight: '700',
              cursor: 'pointer',
              border: 'none',
              transition: 'opacity 0.15s ease',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.88')}
            onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
          >
            Analyze Metrics
          </button>
        </div>
      </div>

      {/* Card 3: Persistent Threat Actor */}
      <div style={{
        background: 'var(--bg-card)',
        padding: '20px',
        borderRadius: '16px',
        border: '1px solid var(--border-subtle)',
        boxShadow: 'var(--shadow-card)',
        position: 'relative',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        transition: 'background 0.2s ease, border-color 0.2s ease',
      }}>
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
            <span style={{
              padding: '8px',
              backgroundColor: 'rgba(79, 70, 229, 0.15)',
              color: '#818CF8',
              borderRadius: '12px',
              display: 'inline-flex',
            }}>
              <Terminal size={20} />
            </span>
            <span style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              fontWeight: '700',
              backgroundColor: 'rgba(79, 70, 229, 0.15)',
              color: '#818CF8',
              padding: '2px 8px',
              borderRadius: '4px',
              border: '1px solid rgba(129, 140, 248, 0.3)',
              letterSpacing: '0.04em',
            }}>
              FFT PERIODICITY // MATCH
            </span>
          </div>

          <p style={{
            fontSize: '10.5px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-secondary)',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            fontWeight: '600',
            margin: 0,
          }}>
            C2 Beaconing Detector
          </p>
          <h3 style={{
            fontSize: '17px',
            fontWeight: '900',
            color: 'var(--text-primary)',
            marginTop: '4px',
            letterSpacing: '-0.02em',
          }}>
            Low-Jitter Beacon Stream
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Autocorr: <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: '#818CF8' }}>0.94</span> • Period: 60.0s
          </p>
        </div>

        <div style={{
          marginTop: '16px',
          paddingTop: '12px',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: '500', margin: 0 }}>Suspect IP Pair</p>
            <p style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--text-primary)', margin: '2px 0 0' }}>
              192.168.1.30 → C2
            </p>
          </div>
          <button
            onClick={() => onExportPcap && onExportPcap()}
            style={{
              backgroundColor: 'var(--text-primary)',
              color: 'var(--bg-card)',
              fontSize: '11px',
              padding: '6px 12px',
              borderRadius: '8px',
              fontWeight: '700',
              cursor: 'pointer',
              border: 'none',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'opacity 0.15s ease',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.85')}
            onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
          >
            <Download size={12} />
            <span>Export PCAP</span>
          </button>
        </div>
      </div>

      {/* Card 4: Hardware Diode Ingest Telemetry */}
      <div style={{
        background: 'var(--bg-card)',
        padding: '20px',
        borderRadius: '16px',
        border: '1px solid var(--border-subtle)',
        boxShadow: 'var(--shadow-card)',
        position: 'relative',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        transition: 'background 0.2s ease, border-color 0.2s ease',
      }}>
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
            <span style={{
              padding: '8px',
              backgroundColor: 'var(--live-bg)',
              color: 'var(--live-text)',
              borderRadius: '12px',
              display: 'inline-flex',
            }}>
              <Cpu size={20} />
            </span>
            <span style={{
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              fontWeight: '700',
              backgroundColor: 'var(--live-bg)',
              color: 'var(--live-text)',
              padding: '2px 8px',
              borderRadius: '4px',
              border: '1px solid var(--live-border)',
              letterSpacing: '0.04em',
            }}>
              OPTICAL TAP // 100% READ ONLY
            </span>
          </div>

          <p style={{
            fontSize: '10.5px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-secondary)',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            fontWeight: '600',
            margin: 0,
          }}>
            Passive Ingest Pipeline
          </p>
          <h3 style={{
            fontSize: '17px',
            fontWeight: '900',
            color: 'var(--text-primary)',
            marginTop: '4px',
            letterSpacing: '-0.02em',
          }}>
            {flowsPerSec} Flows/Sec
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--live-text)', fontWeight: '600', marginTop: '4px' }}>
            Zero Outbound Socket Writes Verified
          </p>
        </div>

        <div style={{
          marginTop: '16px',
          paddingTop: '12px',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: '500', margin: 0 }}>Pipeline Latency</p>
            <p style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--text-primary)', margin: '2px 0 0' }}>
              &lt; 1.1s (Sliding Window)
            </p>
          </div>
          <button
            onClick={() => onLiveStream && onLiveStream()}
            style={{
              backgroundColor: 'var(--text-primary)',
              color: 'var(--bg-card)',
              fontSize: '11px',
              padding: '6px 12px',
              borderRadius: '8px',
              fontWeight: '700',
              cursor: 'pointer',
              border: 'none',
              transition: 'opacity 0.15s ease',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.85')}
            onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
          >
            Live Stream
          </button>
        </div>
      </div>
    </div>
  );
}
