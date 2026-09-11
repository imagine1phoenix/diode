import React from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

export const THREAT_CONFIG = {
  ddos: { label: 'DDoS Flooding', color: '#8b5cf6', icon: 'Flood' },
  recon_scan: { label: 'Recon & Port Scan', color: '#6366f1', icon: 'Scan' },
  c2_beaconing: { label: 'Botnet C2 Beacon', color: '#ec4899', icon: 'Beacon' },
  dga_dns: { label: 'DGA / DNS Tunnel', color: '#0284c7', icon: 'DGA' },
  encrypted_malware: { label: 'Encrypted Malware', color: '#10b981', icon: 'Malware' },
  exfiltration: { label: 'Data Exfiltration', color: '#d97706', icon: 'Exfil' },
};

export default function ThreatDonutChart({ threatStats = {} }) {
  const keys = Object.keys(THREAT_CONFIG);
  const dataValues = keys.map((k) => threatStats[k] || 0);
  const total = dataValues.reduce((a, b) => a + b, 0);

  const data = {
    labels: keys.map((k) => THREAT_CONFIG[k].label),
    datasets: [
      {
        data: dataValues,
        backgroundColor: keys.map((k) => THREAT_CONFIG[k].color),
        borderColor: '#FFFFFF',
        borderWidth: 2,
        hoverOffset: 5,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '70%',
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#475569',
          boxWidth: 8,
          boxHeight: 8,
          usePointStyle: true,
          pointStyle: 'circle',
          padding: 8,
          font: { family: 'Inter', size: 10, weight: '500' },
        },
      },
      tooltip: {
        backgroundColor: '#0F172A',
        titleColor: '#F8FAFC',
        bodyColor: '#CBD5E1',
        borderColor: '#334155',
        borderWidth: 1,
        padding: 8,
        cornerRadius: 6,
      },
    },
  };

  return (
    <div className="glass-panel" style={{ padding: '16px 18px', height: '220px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <h3 style={{ fontSize: '13px', fontWeight: '800', color: '#0F172A' }}>
          Threat Vector Distribution
        </h3>
        <span style={{ fontSize: '11px', color: '#64748B', fontFamily: 'var(--font-mono)', fontWeight: '600' }}>
          {total.toLocaleString()} detections
        </span>
      </div>
      <div style={{ flex: 1, position: 'relative' }}>
        {total === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontSize: '12px' }}>
            No threats detected yet
          </div>
        ) : (
          <Doughnut data={data} options={options} />
        )}
      </div>
    </div>
  );
}
