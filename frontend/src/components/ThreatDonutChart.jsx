import React from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

const THREAT_LABELS = {
  ddos: 'DDoS / Flooding',
  recon_scan: 'Recon & Port Scan',
  c2_beaconing: 'Botnet C2 Beaconing',
  dga_dns: 'DGA / DNS Tunnel',
  encrypted_malware: 'Encrypted Malware',
  exfiltration: 'Data Exfiltration',
};

const THREAT_COLORS = {
  ddos: '#ef4444',
  recon_scan: '#f97316',
  c2_beaconing: '#a855f7',
  dga_dns: '#06b6d4',
  encrypted_malware: '#6366f1',
  exfiltration: '#ec4899',
};

export default function ThreatDonutChart({ threatStats = {} }) {
  const keys = Object.keys(THREAT_LABELS);
  const dataValues = keys.map((k) => threatStats[k] || 0);
  const total = dataValues.reduce((a, b) => a + b, 0);

  const data = {
    labels: keys.map((k) => THREAT_LABELS[k]),
    datasets: [
      {
        data: dataValues,
        backgroundColor: keys.map((k) => THREAT_COLORS[k]),
        borderColor: '#0e131f',
        borderWidth: 2,
        hoverOffset: 6,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '72%',
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#94a3b8',
          boxWidth: 10,
          boxHeight: 10,
          usePointStyle: true,
          pointStyle: 'circle',
          padding: 14,
          font: { family: 'Inter', size: 11, weight: '500' },
        },
      },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#f8fafc',
        bodyColor: '#94a3b8',
        borderColor: 'rgba(255, 255, 255, 0.1)',
        borderWidth: 1,
        padding: 10,
        cornerRadius: 8,
      },
    },
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', height: '360px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#f8fafc' }}>
          Threat Classification Matrix
        </h3>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {total.toLocaleString()} detections
        </span>
      </div>
      <div style={{ flex: 1, position: 'relative' }}>
        {total === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)' }}>
            No threats classified yet
          </div>
        ) : (
          <Doughnut data={data} options={options} />
        )}
      </div>
    </div>
  );
}
