import React, { useState } from 'react';
import { X, Zap, Radio, Globe, ShieldAlert, Cpu, CheckCircle2, Loader2, ArrowUpRight, Play, Sparkles, Shield } from 'lucide-react';
import { THREAT_CONFIG } from './ThreatDonutChart';

export default function SimulateModal({
  isOpen,
  onClose,
  onSimulate,
  isSimulating,
  onOpenInspector,
}) {
  const [selectedThreat, setSelectedThreat] = useState('all');
  const [result, setResult] = useState(null);

  if (!isOpen) return null;

  const scenarios = [
    {
      id: 'all',
      name: 'Combined Threat Scenario Suite',
      description: 'Replays benign baseline traffic mixed with SYN flood, port sweep, C2 beacon, DGA DNS, encrypted malware, and exfiltration.',
      icon: Zap,
      color: '#2563EB',
      badge: 'Full Demo Suite',
    },
    {
      id: 'ddos',
      name: 'Volumetric SYN & UDP Flooding',
      description: 'High packet-rate burst testing arrival rate velocity and source IP entropy detection.',
      icon: ShieldAlert,
      color: '#DC2626',
      badge: 'Network Layer',
    },
    {
      id: 'recon_scan',
      name: 'Reconnaissance & Port Scanning',
      description: 'Probes high-cardinality destination ports and horizontal subnet sweeps.',
      icon: Cpu,
      color: '#D97706',
      badge: 'Service Mapping',
    },
    {
      id: 'c2_beaconing',
      name: 'Botnet C2 Periodic Beaconing',
      description: 'Low-jitter periodic heartbeats evaluated via FFT spectral analysis and host-pair time series.',
      icon: Radio,
      color: '#4F46E5',
      badge: 'Host Heartbeat',
    },
    {
      id: 'dga_dns',
      name: 'DGA Domains & DNS Tunnelling',
      description: 'Random domain queries scored with trained ML Random Forest and Shannon character entropy.',
      icon: Globe,
      color: '#0284C7',
      badge: 'AI / ML Classified',
    },
    {
      id: 'encrypted_malware',
      name: 'Encrypted Malware (JA3 Signature)',
      description: 'TLS Client Hello handshakes matching curated Cobalt Strike and TrickBot threat intel blocklists.',
      icon: Shield,
      color: '#7C3AED',
      badge: 'Cryptographic JA3',
    },
    {
      id: 'exfiltration',
      name: 'Data Exfiltration (Egress Spike)',
      description: 'Heavy outbound payload bursts exceeding physical diode egress baseline limits.',
      icon: ArrowUpRight,
      color: '#059669',
      badge: 'Egress Saturation',
    },
  ];

  // Run with Interactive Pipeline Walkthrough (Jury Mode)
  const handleRunWithInspector = async () => {
    setResult(null);
    try {
      const res = await onSimulate(selectedThreat);
      setResult(`Simulated stream ingested: ${res.alerts_generated || 0} alerts detected.`);
      if (onOpenInspector) {
        onClose();
        onOpenInspector(selectedThreat, res);
      }
    } catch (err) {
      setResult('Simulation failed — check server logs.');
    }
  };

  // Instant Run without Opening Pipeline Inspector
  const handleRunInstant = async () => {
    setResult(null);
    try {
      const res = await onSimulate(selectedThreat);
      setResult(`Simulated stream ingested: ${res.alerts_generated || 0} alerts detected.`);
      setTimeout(() => {
        onClose();
      }, 1000);
    } catch (err) {
      setResult('Simulation failed — check server logs.');
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(15, 23, 42, 0.5)',
      backdropFilter: 'blur(6px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 100,
      padding: '20px',
    }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '620px',
          padding: '26px',
          background: '#FFFFFF',
          borderRadius: '16px',
          border: '1px solid #E2E8F0',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.15)',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '18px',
            right: '18px',
            background: '#F1F5F9',
            border: 'none',
            color: '#64748B',
            borderRadius: '50%',
            width: '28px',
            height: '28px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
          }}
        >
          <X size={16} />
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #2563EB, #0284C7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 4px 12px rgba(37, 99, 235, 0.25)',
          }}>
            <Zap size={20} color="#ffffff" />
          </div>
          <div>
            <h2 style={{ fontSize: '17px', fontWeight: '800', color: '#0F172A', letterSpacing: '-0.01em' }}>
              Threat Scenario Simulator
            </h2>
            <div style={{ fontSize: '12px', color: '#64748B', fontWeight: '500' }}>
              Safe offline replay across the one-way diode tap to demonstrate live AI detection
            </div>
          </div>
        </div>

        {/* Scenario selection list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', margin: '18px 0' }}>
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
                  gap: '12px',
                  padding: '10px 14px',
                  borderRadius: '10px',
                  background: isSelected ? '#EFF6FF' : '#F8FAFC',
                  border: `1px solid ${isSelected ? '#93C5FD' : '#E2E8F0'}`,
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
              >
                <div style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  background: isSelected ? '#DBEAFE' : '#FFFFFF',
                  border: '1px solid #E2E8F0',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  <Icon size={16} color={sc.color} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: '700', color: '#0F172A' }}>
                      {sc.name}
                    </span>
                    <span style={{
                      fontSize: '9px',
                      padding: '1px 6px',
                      borderRadius: '9999px',
                      background: isSelected ? '#BFDBFE' : '#E2E8F0',
                      color: isSelected ? '#1E40AF' : '#475569',
                      fontWeight: '700',
                    }}>
                      {sc.badge}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: '#64748B', marginTop: '2px' }}>
                    {sc.description}
                  </div>
                </div>
                <input
                  type="radio"
                  name="scenario"
                  checked={isSelected}
                  onChange={() => setSelectedThreat(sc.id)}
                  style={{ accentColor: '#2563EB', cursor: 'pointer' }}
                />
              </div>
            );
          })}
        </div>

        {/* Jury Guidance Callout */}
        <div style={{
          margin: '14px 0 16px',
          padding: '12px 14px',
          borderRadius: '10px',
          background: '#EFF6FF',
          border: '1px solid #BFDBFE',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}>
          <Sparkles size={16} color="#2563EB" />
          <div style={{ fontSize: '11.5px', color: '#1E3A8A', lineHeight: '1.4' }}>
            <strong style={{ color: '#1E40AF' }}>Recommendation for Judges:</strong> Use{' '}
            <span style={{ color: '#2563EB', fontWeight: '700' }}>"Launch Live Pipeline Walkthrough"</span> to observe how the one-way optical diode ingest, 5-tuple flow assembly, entropy/FFT math, and ML models classify threats in sequence.
          </div>
        </div>

        {/* Action Status */}
        {result && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            color: '#15803D',
            fontSize: '12px',
            fontWeight: '700',
            marginBottom: '12px',
          }}>
            <CheckCircle2 size={15} />
            {result}
          </div>
        )}

        {/* Action Footer */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
          <button
            onClick={onClose}
            style={{
              padding: '8px 16px',
              borderRadius: '8px',
              background: '#F1F5F9',
              border: '1px solid #CBD5E1',
              color: '#475569',
              cursor: 'pointer',
              fontSize: '12px',
              fontWeight: '600',
            }}
          >
            Cancel
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {/* Instant Background Ingest */}
            <button
              onClick={handleRunInstant}
              disabled={isSimulating}
              title="Runs immediately in background without opening the visual pipeline modal"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 14px',
                borderRadius: '8px',
                background: '#FFFFFF',
                border: '1px solid #CBD5E1',
                color: '#0F172A',
                fontWeight: '600',
                cursor: isSimulating ? 'not-allowed' : 'pointer',
                fontSize: '12px',
                opacity: isSimulating ? 0.6 : 1,
              }}
            >
              <Zap size={13} color="#2563EB" />
              <span>Instant Ingest</span>
            </button>

            {/* Launch Pipeline Walkthrough (Jury Mode) */}
            <button
              onClick={handleRunWithInspector}
              disabled={isSimulating}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 18px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #2563EB, #1D4ED8)',
                border: 'none',
                color: '#ffffff',
                fontWeight: '700',
                cursor: isSimulating ? 'not-allowed' : 'pointer',
                fontSize: '12px',
                opacity: isSimulating ? 0.7 : 1,
                boxShadow: '0 2px 8px rgba(37, 99, 235, 0.3)',
              }}
            >
              {isSimulating ? <Loader2 size={15} className="pulse" /> : <Play size={14} />}
              <span>{isSimulating ? 'Ingesting Simulated Stream...' : 'Launch Live Pipeline Walkthrough'}</span>
              <span style={{
                fontSize: '9px',
                fontWeight: '800',
                padding: '1px 6px',
                borderRadius: '9999px',
                background: 'rgba(255, 255, 255, 0.25)',
                letterSpacing: '0.04em',
              }}>
                JURY MODE
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
