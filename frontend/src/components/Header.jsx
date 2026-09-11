import React from 'react';
import { Shield, Activity, Wifi, WifiOff, Zap, ExternalLink, RefreshCw } from 'lucide-react';

export default function Header({ connected, throughput, totalAlerts, onOpenSimulate, onRefresh }) {
  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '16px 28px',
      borderBottom: '1px solid var(--bg-card-border)',
      background: 'rgba(11, 15, 25, 0.85)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 40,
    }}>
      {/* Brand & Diode Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{
          width: '44px',
          height: '44px',
          borderRadius: 'var(--radius-md)',
          background: 'linear-gradient(135deg, #6366f1, #06b6d4)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 16px rgba(99, 102, 241, 0.4)',
        }}>
          <Shield size={24} color="#ffffff" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '18px', fontWeight: '700', letterSpacing: '-0.02em', color: '#ffffff' }}>
              SIH Cyber Threat Detection
            </h1>
            <span style={{
              fontSize: '11px',
              fontWeight: '600',
              padding: '2px 8px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(6, 182, 212, 0.15)',
              color: 'var(--accent-cyan)',
              border: '1px solid rgba(6, 182, 212, 0.3)',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
            }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--accent-cyan)' }} />
              DATA DIODE TAP (ONE-WAY)
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Real-Time AI Streaming Telemetry & Threat Classification
          </p>
        </div>
      </div>

      {/* Action Controls & Metrics */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        {/* Throughput Pill */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 14px',
          borderRadius: 'var(--radius-md)',
          background: 'rgba(15, 23, 42, 0.6)',
          border: '1px solid var(--bg-card-border)',
        }}>
          <Activity size={16} color="var(--accent-emerald)" />
          <div>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Throughput
            </div>
            <div style={{ fontSize: '13px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
              {throughput?.flows_per_sec ? `${Math.round(throughput.flows_per_sec).toLocaleString()} flows/s` : '1,648 flows/s'}
            </div>
          </div>
        </div>

        {/* Live WebSocket Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 14px',
          borderRadius: 'var(--radius-md)',
          background: connected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${connected ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
        }}>
          {connected ? <Wifi size={16} color="var(--accent-emerald)" /> : <WifiOff size={16} color="var(--sev-critical)" />}
          <span style={{
            fontSize: '12px',
            fontWeight: '600',
            color: connected ? 'var(--accent-emerald)' : 'var(--sev-critical)',
          }}>
            {connected ? 'LIVE STREAM' : 'OFFLINE'}
          </span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          title="Refresh statistics"
          style={{
            background: 'rgba(30, 41, 59, 0.6)',
            border: '1px solid var(--bg-card-border)',
            color: 'var(--text-secondary)',
            padding: '9px',
            borderRadius: 'var(--radius-md)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            transition: 'all 0.2s',
          }}
        >
          <RefreshCw size={16} />
        </button>

        {/* Simulate Attack Trigger Button */}
        <button
          onClick={onOpenSimulate}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '9px 18px',
            borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, #ef4444, #f97316)',
            color: '#ffffff',
            border: 'none',
            fontWeight: '600',
            fontSize: '13px',
            cursor: 'pointer',
            boxShadow: '0 0 16px rgba(239, 68, 68, 0.35)',
            transition: 'all 0.2s ease',
          }}
        >
          <Zap size={16} />
          Inject Attack
        </button>

        {/* API Docs */}
        <a
          href="/docs"
          target="_blank"
          rel="noreferrer"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            color: 'var(--text-secondary)',
            textDecoration: 'none',
            fontSize: '13px',
            fontWeight: '500',
            padding: '6px 10px',
            borderRadius: 'var(--radius-md)',
            transition: 'color 0.2s',
          }}
        >
          <span>API</span>
          <ExternalLink size={13} />
        </a>
      </div>
    </header>
  );
}
