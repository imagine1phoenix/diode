import React, { useState } from 'react';
import { X, Zap, Radio, Globe, ShieldAlert, Cpu, CheckCircle2, Loader2 } from 'lucide-react';

export default function SimulateModal({ isOpen, onClose, onSimulate, isSimulating }) {
  const [selectedThreat, setSelectedThreat] = useState('all');
  const [result, setResult] = useState(null);

  if (!isOpen) return null;

  const scenarios = [
    {
      id: 'all',
      name: 'Combined Attack Suite (PRD §4 Complete)',
      description: 'Generates realistic benign traffic alongside SYN flood, port sweep, C2 beaconing, and DGA DNS queries.',
      icon: Zap,
      color: '#ef4444',
      badge: 'Full Demo',
    },
    {
      id: 'ddos',
      name: 'Volumetric SYN Flood & UDP Amp',
      description: 'High packet-rate unidirectional burst testing arrival rate and source IP entropy detection.',
      icon: ShieldAlert,
      color: '#f97316',
      badge: 'Tier 1',
    },
    {
      id: 'recon_scan',
      name: 'Reconnaissance & Port Scanning',
      description: 'Probes high-cardinality destination ports and horizontal host sweeps.',
      icon: Cpu,
      color: '#eab308',
      badge: 'Tier 1',
    },
    {
      id: 'c2_beaconing',
      name: 'Botnet C2 Periodic Beaconing',
      description: 'Low-jitter periodic heartbeats evaluated via FFT spectral analysis and autocorrelation.',
      icon: Radio,
      color: '#a855f7',
      badge: 'Tier 1',
    },
    {
      id: 'dga_dns',
      name: 'DGA Domains & DNS Tunnelling',
      description: 'Random domain queries scored with English bigram models and character Shannon entropy.',
      icon: Globe,
      color: '#06b6d4',
      badge: 'Tier 1',
    },
  ];

  const handleRun = async () => {
    setResult(null);
    await onSimulate(selectedThreat);
    setResult('Traffic generated and processed through pipeline!');
    setTimeout(() => {
      onClose();
      setResult(null);
    }, 1500);
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 100,
      padding: '20px',
    }}
      onClick={onClose}
    >
      <div
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: '620px',
          padding: '28px',
          background: '#0d1322',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8)',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
          }}
        >
          <X size={20} />
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, #ef4444, #f97316)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <Zap size={22} color="#ffffff" />
          </div>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#ffffff' }}>
              Inject Simulated Cyber Attack
            </h2>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Simulate traffic across the read-only diode tap to demonstrate live detection
            </div>
          </div>
        </div>

        {/* Scenario selection list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', margin: '20px 0' }}>
          {scenarios.map((sc) => {
            const Icon = sc.icon;
            const isSelected = selectedThreat === sc.id;
            return (
              <div
                key={sc.id}
                onClick={() => setSelectedThreat(sc.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '14px',
                  padding: '12px 16px',
                  borderRadius: 'var(--radius-md)',
                  background: isSelected ? 'rgba(99, 102, 241, 0.15)' : 'rgba(15, 23, 42, 0.6)',
                  border: `1px solid ${isSelected ? 'var(--accent-indigo)' : 'var(--bg-card-border)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
              >
                <div style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: 'var(--radius-sm)',
                  background: `rgba(${sc.color === '#ef4444' ? '239, 68, 68' : '6, 182, 212'}, 0.15)`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  <Icon size={18} color={sc.color} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: '600', color: '#ffffff' }}>
                      {sc.name}
                    </span>
                    <span style={{
                      fontSize: '10px',
                      padding: '1px 6px',
                      borderRadius: 'var(--radius-full)',
                      background: 'rgba(255, 255, 255, 0.1)',
                      color: 'var(--text-secondary)',
                    }}>
                      {sc.badge}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {sc.description}
                  </div>
                </div>
                <input
                  type="radio"
                  name="scenario"
                  checked={isSelected}
                  onChange={() => setSelectedThreat(sc.id)}
                  style={{ accentColor: 'var(--accent-indigo)', cursor: 'pointer' }}
                />
              </div>
            );
          })}
        </div>

        {/* Action Status */}
        {result && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            color: 'var(--accent-emerald)',
            fontSize: '13px',
            fontWeight: '600',
            marginBottom: '14px',
          }}>
            <CheckCircle2 size={16} />
            {result}
          </div>
        )}

        {/* Action Footer */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
          <button
            onClick={onClose}
            style={{
              padding: '9px 18px',
              borderRadius: 'var(--radius-md)',
              background: 'transparent',
              border: '1px solid var(--bg-card-border)',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '13px',
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleRun}
            disabled={isSimulating}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 20px',
              borderRadius: 'var(--radius-md)',
              background: 'linear-gradient(135deg, #ef4444, #f97316)',
              border: 'none',
              color: '#ffffff',
              fontWeight: '600',
              cursor: isSimulating ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              opacity: isSimulating ? 0.7 : 1,
            }}
          >
            {isSimulating ? <Loader2 size={16} className="pulse" /> : <Zap size={16} />}
            {isSimulating ? 'Ingesting Simulated Traffic...' : 'Execute Simulation'}
          </button>
        </div>
      </div>
    </div>
  );
}
