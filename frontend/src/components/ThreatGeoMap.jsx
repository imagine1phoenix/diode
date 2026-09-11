import React, { useState, useEffect, useRef, useMemo } from 'react';
import { geoNaturalEarth1, geoPath, geoGraticule10 } from 'd3-geo';
import { feature } from 'topojson-client';
import {
  Globe2, Shield, AlertTriangle, Crosshair, ZoomIn, ZoomOut,
  RotateCcw, Radio, Activity, Eye, Zap, Layers, RefreshCw, Flame, Filter
} from 'lucide-react';
import { getApiUrl } from '../api';
import worldData from 'world-atlas/countries-110m.json';

// Pre-compute geographical features once to maintain 60 FPS
const COUNTRIES_FEATURE = feature(worldData, worldData.objects.countries).features;
const GRATICULE_FEATURE = geoGraticule10();

// Standard tactical SVG canvas dimensions
const CANVAS_WIDTH = 960;
const CANVAS_HEIGHT = 480;

// Natural Earth projection fitted precisely to canvas
const projection = geoNaturalEarth1().fitSize([CANVAS_WIDTH, CANVAS_HEIGHT], { type: 'Sphere' });
const pathGenerator = geoPath().projection(projection);
const graticulePath = pathGenerator(GRATICULE_FEATURE);

export default function ThreatGeoMap({ alerts = [] }) {
  const [geoData, setGeoData] = useState([]);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('all'); // 'all' | 'critical' | 'high'
  const [loading, setLoading] = useState(false);

  // Fetch threat geo data from backend API
  const fetchGeo = () => {
    setLoading(true);
    fetch(getApiUrl('/api/geoip/threats?limit=250'))
      .then((res) => res.json())
      .then((data) => {
        setGeoData(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to fetch geo threats:', err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchGeo();
    const timer = setInterval(fetchGeo, 6000);
    return () => clearInterval(timer);
  }, []);

  // Protected Enclave Target (New Delhi SOC Optical Tap)
  const [targetX, targetY] = useMemo(() => {
    return projection([77.2090, 28.6139]) || [670, 155];
  }, []);

  // Filter nodes based on user toggle
  const filteredNodes = useMemo(() => {
    if (severityFilter === 'critical') {
      return geoData.filter((n) => n.max_severity === 'critical');
    }
    if (severityFilter === 'high') {
      return geoData.filter((n) => n.max_severity === 'critical' || n.max_severity === 'high');
    }
    return geoData;
  }, [geoData, severityFilter]);

  // Overall incident calculations
  const totalIncidents = useMemo(() => {
    return geoData.reduce((acc, n) => acc + (n.incident_count || 1), 0);
  }, [geoData]);

  // Top 4 adversary origins for tactical HUD
  const topOrigins = useMemo(() => {
    return geoData.slice(0, 4);
  }, [geoData]);

  return (
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Tactical Map Header & Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '28px',
              height: '28px',
              borderRadius: '6px',
              background: 'rgba(6, 182, 212, 0.15)',
              border: '1px solid rgba(6, 182, 212, 0.35)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Globe2 size={16} color="var(--accent-cyan)" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 style={{ fontSize: '15px', fontWeight: '700', color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
                  Live Cyber Threat Operations Map
                </h2>
                <span style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-full)',
                  background: 'rgba(239, 68, 68, 0.12)',
                  color: '#f87171',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                }}>
                  <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#ef4444', animation: 'pulse 1.5s infinite' }} />
                  {filteredNodes.length} Active Hotspots
                </span>
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                Real-time passive optical tap telemetry • Global adversary attribution to shielded New Delhi enclave
              </p>
            </div>
          </div>
        </div>

        {/* Severity Filter Controls & Refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Filter Pills */}
          <div style={{
            display: 'inline-flex',
            background: 'var(--bg-surface)',
            padding: '3px',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            gap: '2px',
          }}>
            <button
              onClick={() => setSeverityFilter('all')}
              style={{
                fontSize: '11px',
                fontWeight: '600',
                padding: '4px 10px',
                borderRadius: '4px',
                border: 'none',
                background: severityFilter === 'all' ? 'rgba(99, 102, 241, 0.3)' : 'transparent',
                color: severityFilter === 'all' ? '#ffffff' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              All Origins ({geoData.length})
            </button>
            <button
              onClick={() => setSeverityFilter('high')}
              style={{
                fontSize: '11px',
                fontWeight: '600',
                padding: '4px 10px',
                borderRadius: '4px',
                border: 'none',
                background: severityFilter === 'high' ? 'rgba(249, 115, 22, 0.25)' : 'transparent',
                color: severityFilter === 'high' ? '#fdba74' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              High & Critical
            </button>
            <button
              onClick={() => setSeverityFilter('critical')}
              style={{
                fontSize: '11px',
                fontWeight: '600',
                padding: '4px 10px',
                borderRadius: '4px',
                border: 'none',
                background: severityFilter === 'critical' ? 'rgba(239, 68, 68, 0.25)' : 'transparent',
                color: severityFilter === 'critical' ? '#fca5a5' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              Critical Only
            </button>
          </div>

          <button
            onClick={fetchGeo}
            disabled={loading}
            title="Refresh GeoIP telemetry"
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              padding: '6px 10px',
              borderRadius: 'var(--radius-sm)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '11px',
            }}
          >
            <RefreshCw size={12} className={loading ? 'pulse' : ''} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {/* High-Tech Vector World Map Canvas */}
      <div style={{
        position: 'relative',
        background: 'radial-gradient(ellipse at 50% 45%, #0d1a36 0%, #040813 100%)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid rgba(99, 102, 241, 0.25)',
        overflow: 'hidden',
        boxShadow: 'inset 0 0 60px rgba(0, 0, 0, 0.6)',
      }}>
        {/* Style injection for dash-flow animation & radar pulses */}
        <style>{`
          @keyframes attackArcFlow {
            from { stroke-dashoffset: 40; }
            to { stroke-dashoffset: 0; }
          }
          @keyframes radarPing {
            0% { r: 4px; opacity: 0.8; }
            100% { r: 24px; opacity: 0; }
          }
          @keyframes targetShieldPing {
            0% { r: 6px; opacity: 0.9; }
            100% { r: 32px; opacity: 0; }
          }
          .threat-arc-critical {
            stroke: url(#arcCritGrad);
            stroke-dasharray: 6 4;
            animation: attackArcFlow 1.2s linear infinite;
          }
          .threat-arc-high {
            stroke: url(#arcHighGrad);
            stroke-dasharray: 5 4;
            animation: attackArcFlow 1.8s linear infinite;
          }
          .threat-arc-medium {
            stroke: url(#arcMedGrad);
            stroke-dasharray: 4 4;
            animation: attackArcFlow 2.4s linear infinite;
          }
        `}</style>

        <svg
          viewBox={`0 0 ${CANVAS_WIDTH} ${CANVAS_HEIGHT}`}
          style={{ width: '100%', height: 'auto', display: 'block' }}
        >
          <defs>
            {/* Threat Arcs Gradients */}
            <linearGradient id="arcCritGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" />
              <stop offset="60%" stopColor="#f87171" stopOpacity="0.7" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.3" />
            </linearGradient>
            <linearGradient id="arcHighGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#f97316" stopOpacity="0.9" />
              <stop offset="60%" stopColor="#fb923c" stopOpacity="0.7" />
              <stop offset="100%" stopColor="#6366f1" stopOpacity="0.3" />
            </linearGradient>
            <linearGradient id="arcMedGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#eab308" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.2" />
            </linearGradient>

            {/* Target Enclave Defense Glow */}
            <radialGradient id="targetDefenseShield" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#3b82f6" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Graticule Latitude/Longitude Coordinate Grid */}
          <path
            d={graticulePath}
            fill="none"
            stroke="rgba(99, 102, 241, 0.08)"
            strokeWidth="0.75"
            strokeDasharray="2 3"
          />

          {/* Real World Countries and Continents (177 sovereign landmasses) */}
          <g>
            {COUNTRIES_FEATURE.map((country, idx) => {
              const d = pathGenerator(country);
              if (!d) return null;
              return (
                <path
                  key={`country-${idx}`}
                  d={d}
                  fill="rgba(22, 32, 54, 0.85)"
                  stroke="rgba(99, 102, 241, 0.28)"
                  strokeWidth="0.65"
                  style={{ transition: 'fill 0.2s ease' }}
                  onMouseEnter={(e) => e.target.setAttribute('fill', 'rgba(38, 54, 88, 0.95)')}
                  onMouseLeave={(e) => e.target.setAttribute('fill', 'rgba(22, 32, 54, 0.85)')}
                />
              );
            })}
          </g>

          {/* Glowing Attack Trajectory Arcs from Origin Hotspots to Protected Enclave */}
          {filteredNodes.map((node, i) => {
            const projected = projection([node.lon, node.lat]);
            if (!projected) return null;
            const [srcX, srcY] = projected;

            // Compute curved arc trajectory towards target
            const dx = targetX - srcX;
            const dy = targetY - srcY;
            const dist = Math.sqrt(dx * dx + dy * dy);
            // Parabolic control point arching over the globe
            const cx = (srcX + targetX) / 2;
            const cy = (srcY + targetY) / 2 - Math.min(100, Math.max(25, dist * 0.25));
            const pathD = `M ${srcX} ${srcY} Q ${cx} ${cy} ${targetX} ${targetY}`;

            const isCrit = node.max_severity === 'critical';
            const isHigh = node.max_severity === 'high';
            const arcClass = isCrit
              ? 'threat-arc-critical'
              : isHigh
              ? 'threat-arc-high'
              : 'threat-arc-medium';

            const isHovered = hoveredNode && hoveredNode.ip === node.ip;

            return (
              <g key={`arc-group-${i}`}>
                {/* Background Shadow / Glow Arc */}
                <path
                  d={pathD}
                  fill="none"
                  stroke={isCrit ? '#ef4444' : isHigh ? '#f97316' : '#eab308'}
                  strokeWidth={isHovered ? '2.5' : isCrit ? '1.8' : '1.2'}
                  opacity={isHovered ? '0.9' : '0.35'}
                />
                {/* Animated Dynamic Laser Pulse */}
                <path
                  d={pathD}
                  fill="none"
                  className={arcClass}
                  strokeWidth={isHovered ? '3' : isCrit ? '2' : '1.4'}
                  opacity={isHovered ? '1' : '0.85'}
                />
              </g>
            );
          })}

          {/* Protected Enclave Target (New Delhi SOC Tap) */}
          <g>
            {/* Concentric Defense Shield Waves */}
            <circle cx={targetX} cy={targetY} r="28" fill="url(#targetDefenseShield)" />
            <circle
              cx={targetX}
              cy={targetY}
              r="14"
              fill="none"
              stroke="#06b6d4"
              strokeWidth="1.5"
              style={{ animation: 'targetShieldPing 2s cubic-bezier(0, 0.2, 0.8, 1) infinite' }}
            />
            <circle
              cx={targetX}
              cy={targetY}
              r="24"
              fill="none"
              stroke="#06b6d4"
              strokeWidth="0.8"
              opacity="0.5"
              style={{ animation: 'targetShieldPing 2s cubic-bezier(0, 0.2, 0.8, 1) infinite 0.75s' }}
            />
            {/* Solid Center Beacon */}
            <circle cx={targetX} cy={targetY} r="5" fill="#06b6d4" stroke="#ffffff" strokeWidth="1.5" />

            {/* HUD Tactical Callout Label */}
            <line
              x1={targetX}
              y1={targetY}
              x2={targetX + 30}
              y2={targetY - 24}
              stroke="#06b6d4"
              strokeWidth="1"
              strokeDasharray="2 2"
            />
            <line
              x1={targetX + 30}
              y1={targetY - 24}
              x2={targetX + 180}
              y2={targetY - 24}
              stroke="#06b6d4"
              strokeWidth="1"
            />
            <text
              x={targetX + 34}
              y={targetY - 28}
              fill="#38bdf8"
              fontSize="9"
              fontFamily="Inter, sans-serif"
              fontWeight="800"
              letterSpacing="0.08em"
            >
              PROTECTED ENCLAVE (TAP)
            </text>
            <text
              x={targetX + 34}
              y={targetY - 14}
              fill="#94a3b8"
              fontSize="8"
              fontFamily="JetBrains Mono, monospace"
            >
              28.61°N, 77.20°E • 1-WAY INGEST
            </text>
          </g>

          {/* Attacker Origin Nodes / Hotspots */}
          {filteredNodes.map((node, i) => {
            const projected = projection([node.lon, node.lat]);
            if (!projected) return null;
            const [x, y] = projected;

            const isCrit = node.max_severity === 'critical';
            const isHigh = node.max_severity === 'high';
            const nodeColor = isCrit ? '#ef4444' : isHigh ? '#f97316' : '#eab308';
            const baseRadius = Math.min(8, 3.5 + Math.log2(node.incident_count || 1));
            const isHovered = hoveredNode && hoveredNode.ip === node.ip;

            return (
              <g
                key={`node-${i}`}
                onMouseEnter={() => setHoveredNode(node)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => setSelectedNode(node)}
                style={{ cursor: 'pointer' }}
              >
                {/* Outer Expanding Radar Blip */}
                <circle
                  cx={x}
                  cy={y}
                  r={baseRadius * 2.2}
                  fill="none"
                  stroke={nodeColor}
                  strokeWidth="1.2"
                  style={{ animation: `radarPing ${isCrit ? '1.4s' : '2s'} cubic-bezier(0, 0.2, 0.8, 1) infinite` }}
                />

                {/* Ambient Halo */}
                <circle
                  cx={x}
                  cy={y}
                  r={baseRadius * 1.6}
                  fill={nodeColor}
                  opacity={isHovered ? '0.4' : '0.2'}
                />

                {/* Core Dot with High-Contrast Border */}
                <circle
                  cx={x}
                  cy={y}
                  r={isHovered ? baseRadius + 2 : baseRadius}
                  fill={nodeColor}
                  stroke="#ffffff"
                  strokeWidth={isHovered ? '2' : '1.2'}
                />
              </g>
            );
          })}
        </svg>

        {/* Hover Tooltip HUD Card */}
        {hoveredNode && (
          <div style={{
            position: 'absolute',
            top: '16px',
            right: '16px',
            background: 'rgba(10, 16, 30, 0.94)',
            backdropFilter: 'blur(12px)',
            border: '1px solid rgba(99, 102, 241, 0.4)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px 16px',
            pointerEvents: 'none',
            boxShadow: '0 10px 30px rgba(0, 0, 0, 0.7)',
            fontSize: '11px',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
            minWidth: '220px',
            zIndex: 10,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: '700', color: '#ffffff', fontSize: '13px' }}>
                {hoveredNode.city}, {hoveredNode.country}
              </span>
              <span style={{
                fontSize: '9px',
                fontWeight: '800',
                padding: '2px 6px',
                borderRadius: '3px',
                background: hoveredNode.max_severity === 'critical' ? 'rgba(239, 68, 68, 0.25)' : 'rgba(249, 115, 22, 0.25)',
                color: hoveredNode.max_severity === 'critical' ? '#ef4444' : '#f97316',
                border: `1px solid ${hoveredNode.max_severity === 'critical' ? '#ef4444' : '#f97316'}`,
                textTransform: 'uppercase',
                fontFamily: 'var(--font-mono)',
              }}>
                {hoveredNode.max_severity}
              </span>
            </div>

            <div style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
              Adversary IP: {hoveredNode.ip}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
              <span>Recorded Ingests:</span>
              <span style={{ color: '#ffffff', fontWeight: '700', fontFamily: 'var(--font-mono)' }}>
                {hoveredNode.incident_count.toLocaleString()}
              </span>
            </div>

            <div style={{ color: 'var(--text-muted)', fontSize: '10px', marginTop: '2px', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '6px' }}>
              <span style={{ color: 'var(--text-secondary)', fontWeight: '600' }}>Active Vectors: </span>
              {hoveredNode.threat_types.join(', ')}
            </div>
          </div>
        )}

        {/* Tactical Origin Hotspot Strip (Bottom HUD) */}
        <div style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          background: 'linear-gradient(to top, rgba(6, 11, 22, 0.95) 0%, rgba(6, 11, 22, 0.8) 70%, transparent 100%)',
          padding: '10px 16px',
          borderTop: '1px solid rgba(99, 102, 241, 0.18)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '10px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Crosshair size={13} color="var(--accent-cyan)" />
            <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Primary Threat Origins:
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {topOrigins.map((orig, idx) => (
              <div
                key={`orig-${idx}`}
                onMouseEnter={() => setHoveredNode(orig)}
                onMouseLeave={() => setHoveredNode(null)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: 'rgba(30, 41, 59, 0.7)',
                  border: '1px solid rgba(99, 102, 241, 0.2)',
                  borderRadius: '4px',
                  padding: '3px 8px',
                  fontSize: '11px',
                  cursor: 'pointer',
                }}
              >
                <span style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  background: orig.max_severity === 'critical' ? '#ef4444' : '#f97316',
                }} />
                <span style={{ color: '#f8fafc', fontWeight: '600' }}>{orig.city}</span>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '10px' }}>({orig.incident_count})</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
