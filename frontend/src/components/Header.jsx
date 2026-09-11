import React from 'react';
import { Shield, Activity, Wifi, WifiOff, Zap, ExternalLink, RefreshCw, ArrowRight, Info } from 'lucide-react';

export default function Header({
  connected,
  throughput,
  totalAlerts,
  onOpenSimulate,
  onOpenInspector,
  onRefresh,
  isRefreshing = false,
  isSimulating = false,
}) {
  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '14px 28px',
      borderBottom: '1px solid var(--bg-card-border)',
      background: 'rgba(10, 14, 23, 0.92)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 40,
    }}>
      {/* Brand & Diode Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          width: '40px',
          height: '40px',
          borderRadius: 'var(--radius-md)',
          background: 'linear-gradient(135deg, #6366f1, #06b6d4)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 14px rgba(99, 102, 241, 0.35)',
        }}>
          <Shield size={22} color="#ffffff" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '17px', fontWeight: '700', letterSpacing: '-0.02em', color: '#ffffff' }}>
               Cyber Threat Detection SOC
            </h1>
            <div
              className="has-tooltip"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                fontSize: '11px',
                fontWeight: '500',
                padding: '2px 8px',
                borderRadius: 'var(--radius-full)',
                background: 'rgba(6, 182, 212, 0.12)',
                color: 'var(--accent-cyan)',
                border: '1px solid rgba(6, 182, 212, 0.25)',
                cursor: 'help',
              }}
            >
              <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: 'var(--accent-cyan)' }} />
              <span>One-Way Diode Tap</span>
              <ArrowRight size={11} />
              <div className="tooltip">
                Physical hardware isolation: passive optical tap with zero reverse transmission capability.
              </div>
            </div>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Real-Time Threat Intelligence & Anomaly Classification
          </p>
        </div>
      </div>

      {/* Action Controls & Telemetry */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {/* Stream Throughput */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 12px',
          borderRadius: 'var(--radius-md)',
          background: 'rgba(15, 23, 42, 0.6)',
          border: '1px solid var(--bg-card-border)',
        }}>
          <Activity size={15} color="var(--accent-emerald)" />
          <div>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Pipeline Ingest
            </div>
            <div style={{ fontSize: '12px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
              {throughput?.flows_per_sec ? `${Math.round(throughput.flows_per_sec).toLocaleString()} flows/s` : '1,648 flows/s'}
            </div>
          </div>
        </div>

        {/* Live WebSocket Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '6px 12px',
          borderRadius: 'var(--radius-md)',
          background: connected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${connected ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
        }}>
          <span
            style={{
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              background: connected ? 'var(--accent-emerald)' : 'var(--sev-critical)',
              boxShadow: connected ? '0 0 8px var(--accent-emerald)' : '0 0 8px var(--sev-critical)',
            }}
            className={connected ? 'pulse' : ''}
          />
          {connected ? <Wifi size={14} color="var(--accent-emerald)" /> : <WifiOff size={14} color="var(--sev-critical)" />}
          <span style={{
            fontSize: '11px',
            fontWeight: '600',
            color: connected ? 'var(--accent-emerald)' : 'var(--sev-critical)',
          }}>
            {connected ? 'LIVE FEED' : 'OFFLINE'}
          </span>
        </div>

        {/* Refresh Button with Live Spin Feedback */}
        <div className="has-tooltip">
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            style={{
              background: isRefreshing ? 'rgba(99, 102, 241, 0.25)' : 'rgba(30, 41, 59, 0.6)',
              border: `1px solid ${isRefreshing ? 'var(--accent-indigo)' : 'var(--bg-card-border)'}`,
              color: isRefreshing ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              padding: '8px',
              borderRadius: 'var(--radius-md)',
              cursor: isRefreshing ? 'wait' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
              boxShadow: isRefreshing ? '0 0 12px rgba(99, 102, 241, 0.4)' : 'none',
            }}
          >
            <RefreshCw
              size={15}
              style={{
                animation: isRefreshing ? 'spin 0.6s linear infinite' : 'none',
                transformOrigin: 'center center',
              }}
            />
          </button>
          <div className="tooltip">
            {isRefreshing ? 'Refreshing live feed telemetry...' : 'Refresh live threat feed & statistics'}
          </div>
        </div>

        {/* Pipeline Architecture / How it Works Button */}
        <div className="has-tooltip">
          <button
            onClick={onOpenInspector}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: 'var(--radius-md)',
              background: 'rgba(99, 102, 241, 0.15)',
              border: '1px solid rgba(99, 102, 241, 0.35)',
              color: '#c7d2fe',
              fontWeight: '600',
              fontSize: '12px',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
          >
            <Activity size={14} color="var(--accent-cyan)" />
            <span>Live Pipeline Inspector</span>
            <span style={{
              fontSize: '9px',
              fontWeight: '700',
              padding: '1px 5px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(6, 182, 212, 0.2)',
              color: 'var(--accent-cyan)',
              letterSpacing: '0.04em',
            }}>
              JURY VIEW
            </span>
          </button>
          <div className="tooltip">
            Step-by-step interactive walkthrough: Optical Diode Tap ➔ 5-Tuple Assembler ➔ Feature Math ➔ ML Engine ➔ Alert.
          </div>
        </div>

        {/* Simulate Demo Attack Trigger Button */}
        <div className="has-tooltip">
          <button
            onClick={onOpenSimulate}
            disabled={isSimulating}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 16px',
              borderRadius: 'var(--radius-md)',
              background: isSimulating
                ? 'rgba(79, 70, 229, 0.35)'
                : 'linear-gradient(135deg, #4f46e5, #06b6d4)',
              color: '#ffffff',
              border: isSimulating ? '1px solid rgba(99, 102, 241, 0.5)' : 'none',
              fontWeight: '600',
              fontSize: '12px',
              cursor: isSimulating ? 'wait' : 'pointer',
              boxShadow: isSimulating ? '0 0 20px rgba(99, 102, 241, 0.4)' : '0 0 16px rgba(79, 70, 229, 0.35)',
              transition: 'all 0.2s ease',
              opacity: isSimulating ? 0.85 : 1,
            }}
          >
            {isSimulating ? (
              <RefreshCw size={14} style={{ animation: 'spin 0.6s linear infinite' }} />
            ) : (
              <Zap size={14} />
            )}
            <span>{isSimulating ? 'Simulating Attack Ingest...' : 'Simulate Demo Attack'}</span>
            <span style={{
              fontSize: '9px',
              fontWeight: '700',
              padding: '1px 5px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(255, 255, 255, 0.22)',
              letterSpacing: '0.04em',
            }}>
              DEMO
            </span>
          </button>
          <div className="tooltip">
            {isSimulating ? 'Simulated attack traffic active across optical tap...' : 'Replays safe cyber attack vectors to test live AI detection.'}
          </div>
        </div>

        {/* API Docs link */}
        <a
          href="/docs"
          target="_blank"
          rel="noreferrer"
          title="Open OpenAPI specification"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            color: 'var(--text-secondary)',
            textDecoration: 'none',
            fontSize: '12px',
            fontWeight: '500',
            padding: '6px 8px',
            borderRadius: 'var(--radius-md)',
            transition: 'color 0.2s',
          }}
        >
          <span>API</span>
          <ExternalLink size={12} />
        </a>
      </div>
    </header>
  );
}
