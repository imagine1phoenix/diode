import React from 'react';
import { Shield, Activity, Wifi, WifiOff, Zap, ExternalLink, RefreshCw, ArrowRight, Sparkles, Bell } from 'lucide-react';

export default function Header({
  connected,
  throughput,
  totalAlerts,
  onOpenSimulate,
  onOpenInspector,
  onOpenCopilot,
  onOpenNotifications,
  onRefresh,
  isRefreshing = false,
  isSimulating = false,
}) {
  const flowsPerSec = throughput?.flows_per_sec
    ? Math.round(throughput.flows_per_sec).toLocaleString()
    : '3,127';

  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '12px 28px',
      borderBottom: '1px solid #E2E8F0',
      background: '#FFFFFF',
      boxShadow: '0 1px 3px 0 rgb(0 0 0 / 0.04)',
      position: 'sticky',
      top: 0,
      zIndex: 40,
      flexWrap: 'wrap',
      gap: '14px',
    }}>
      {/* Brand & Diode Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          width: '38px',
          height: '38px',
          borderRadius: '10px',
          background: 'linear-gradient(135deg, #0F172A, #2563EB)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 2px 8px rgba(15, 23, 42, 0.15)',
          color: '#FFFFFF',
        }}>
          <Shield size={20} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <h1 style={{
              fontSize: '16px',
              fontWeight: '900',
              letterSpacing: '-0.02em',
              color: '#0F172A',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
            }}>
              NET-DRISHTI // AIR-GAPPED TELEMETRY ENCLAVE
            </h1>
            <div
              className="has-tooltip"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '10.5px',
                fontWeight: '700',
                fontFamily: 'var(--font-mono)',
                padding: '3px 9px',
                borderRadius: '6px',
                background: '#DCFCE7',
                color: '#15803D',
                border: '1px solid #BBF7D0',
                cursor: 'help',
                letterSpacing: '0.04em',
              }}
            >
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#15803D' }} className="pulse" />
              <span>PASSIVE OPTICAL DIODE TAP (ZERO TX / READ-ONLY)</span>
              <div className="tooltip">
                Physical hardware isolation: passive optical tap with zero reverse transmission capability (PRD §1).
              </div>
            </div>
          </div>
          <p style={{ fontSize: '11.5px', color: '#64748B', fontWeight: '500', marginTop: '1px' }}>
            Unidirectional Cyber Threat Classification & Telemetry Forensics
          </p>
        </div>
      </div>

      {/* Action Controls & Telemetry */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        {/* Stream Efficiency & Latency Benchmark */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 12px',
          borderRadius: '8px',
          background: '#F8FAFC',
          border: '1px solid #E2E8F0',
        }}>
          <Activity size={15} color="#2563EB" />
          <div>
            <div style={{ fontSize: '9.5px', color: '#64748B', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Streaming Telemetry
            </div>
            <div style={{ fontSize: '11.5px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#0F172A' }}>
              99.2% EFFICIENCY // &lt; 1.1s LATENCY
            </div>
          </div>
        </div>

        {/* Live Diode Ingest Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '6px 12px',
          borderRadius: '8px',
          background: connected ? '#F0FDF4' : '#FEF2F2',
          border: `1px solid ${connected ? '#BBF7D0' : '#FECACA'}`,
        }}>
          <span
            style={{
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              background: connected ? '#15803D' : '#DC2626',
            }}
            className={connected ? 'pulse' : ''}
          />
          {connected ? <Wifi size={13} color="#15803D" /> : <WifiOff size={13} color="#DC2626" />}
          <span style={{
            fontSize: '11px',
            fontWeight: '700',
            fontFamily: 'var(--font-mono)',
            color: connected ? '#15803D' : '#DC2626',
          }}>
            {connected ? 'LIVE INGEST' : 'OFFLINE'}
          </span>
        </div>

        {/* Refresh Button */}
        <div className="has-tooltip">
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            style={{
              background: '#FFFFFF',
              border: '1px solid #E2E8F0',
              color: isRefreshing ? '#2563EB' : '#475569',
              padding: '7px 9px',
              borderRadius: '8px',
              cursor: isRefreshing ? 'wait' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
              boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
            }}
          >
            <RefreshCw
              size={14}
              style={{
                animation: isRefreshing ? 'spin 0.6s linear infinite' : 'none',
                transformOrigin: 'center center',
              }}
            />
          </button>
          <div className="tooltip">
            {isRefreshing ? 'Refreshing live telemetry...' : 'Refresh live threat stream & telemetry'}
          </div>
        </div>

        {/* Diode Copilot (Air-Gapped LLM) Button */}
        <button
          onClick={onOpenCopilot}
          title="Open Diode Copilot Air-Gapped LLM Dossier"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 13px',
            borderRadius: '8px',
            background: 'linear-gradient(135deg, #4F46E5, #2563EB)',
            color: '#FFFFFF',
            fontWeight: '700',
            fontSize: '12px',
            cursor: 'pointer',
            border: 'none',
            boxShadow: '0 2px 8px rgba(37, 99, 235, 0.25)',
            transition: 'opacity 0.15s ease',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.92')}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          <Sparkles size={14} color="#FDE047" />
          <span>✨ Diode Copilot (Air-Gapped LLM)</span>
        </button>

        {/* Pipeline Architecture / Detail Button */}
        <button
          onClick={onOpenInspector}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '5px',
            padding: '7px 12px',
            borderRadius: '8px',
            background: '#F1F5F9',
            border: '1px solid #CBD5E1',
            color: '#1E293B',
            fontWeight: '600',
            fontSize: '12px',
            cursor: 'pointer',
            transition: 'background 0.15s',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#E2E8F0')}
          onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = '#F1F5F9')}
        >
          <Activity size={13} color="#2563EB" />
          <span>Pipeline Detail</span>
        </button>

        {/* Alert Channels (Webhooks / Telegram / Slack) Button */}
        <button
          onClick={onOpenNotifications}
          title="Configure Outbound Alert Channels (Discord, Slack, Telegram, Webhook)"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 12px',
            borderRadius: '8px',
            background: '#F1F5F9',
            border: '1px solid #CBD5E1',
            color: '#1E293B',
            fontWeight: '600',
            fontSize: '12px',
            cursor: 'pointer',
            transition: 'background 0.15s',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#E2E8F0')}
          onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = '#F1F5F9')}
        >
          <Bell size={13} color="#EA580C" />
          <span>Alert Channels</span>
        </button>

        {/* Simulate Demo Attack Button */}
        <button
          onClick={onOpenSimulate}
          disabled={isSimulating}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '7px',
            padding: '7px 14px',
            borderRadius: '8px',
            background: '#0F172A',
            color: '#FFFFFF',
            fontWeight: '600',
            fontSize: '12px',
            cursor: isSimulating ? 'wait' : 'pointer',
            border: 'none',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            opacity: isSimulating ? 0.8 : 1,
            transition: 'background 0.15s',
          }}
          onMouseEnter={(e) => !isSimulating && (e.currentTarget.style.backgroundColor = '#1E293B')}
          onMouseLeave={(e) => !isSimulating && (e.currentTarget.style.backgroundColor = '#0F172A')}
        >
          {isSimulating ? (
            <RefreshCw size={13} style={{ animation: 'spin 0.6s linear infinite' }} />
          ) : (
            <Zap size={13} color="#38BDF8" />
          )}
          <span>{isSimulating ? 'Simulating...' : 'Simulate Demo Attack'}</span>
          <span style={{
            fontSize: '9px',
            fontWeight: '800',
            padding: '1px 5px',
            borderRadius: '4px',
            background: 'rgba(255, 255, 255, 0.2)',
            letterSpacing: '0.04em',
          }}>
            DEMO
          </span>
        </button>

        {/* OpenAPI Link */}
        <a
          href="/docs"
          target="_blank"
          rel="noreferrer"
          title="Open API Specification"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '3px',
            color: '#64748B',
            textDecoration: 'none',
            fontSize: '11.5px',
            fontWeight: '600',
            padding: '6px 8px',
            borderRadius: '6px',
          }}
        >
          <span>API</span>
          <ExternalLink size={11} />
        </a>
      </div>
    </header>
  );
}
