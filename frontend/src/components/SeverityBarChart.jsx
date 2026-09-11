import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

const SEVERITY_CONFIG = [
  { key: 'critical', label: 'Critical', color: '#ef4444' },
  { key: 'high', label: 'High', color: '#f97316' },
  { key: 'medium', label: 'Medium', color: '#eab308' },
  { key: 'low', label: 'Low', color: '#06b6d4' },
];

export default function SeverityBarChart({ severityStats = {} }) {
  const data = {
    labels: SEVERITY_CONFIG.map((s) => s.label),
    datasets: [
      {
        data: SEVERITY_CONFIG.map((s) => severityStats[s.key] || 0),
        backgroundColor: SEVERITY_CONFIG.map((s) => s.color),
        borderRadius: 4,
        borderSkipped: false,
        barPercentage: 0.5,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#f8fafc',
        bodyColor: '#94a3b8',
        borderColor: 'rgba(255, 255, 255, 0.1)',
        borderWidth: 1,
        padding: 8,
        cornerRadius: 6,
      },
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#94a3b8', font: { family: 'Inter', size: 10, weight: '600' } },
        border: { color: 'rgba(148, 163, 184, 0.1)' },
      },
      y: {
        grid: { color: 'rgba(148, 163, 184, 0.06)' },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9 }, precision: 0 },
        border: { display: false },
      },
    },
  };

  return (
    <div className="glass-panel" style={{ padding: '16px 18px', height: '190px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <h3 style={{ fontSize: '13px', fontWeight: '600', color: '#f8fafc' }}>
          Alerts by Severity Tier
        </h3>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          Urgency Classification
        </span>
      </div>
      <div style={{ flex: 1, position: 'relative' }}>
        <Bar data={data} options={options} />
      </div>
    </div>
  );
}
