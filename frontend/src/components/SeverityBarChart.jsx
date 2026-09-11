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
  { key: 'critical', label: 'Critical', color: '#DC2626' },
  { key: 'high', label: 'High', color: '#D97706' },
  { key: 'medium', label: 'Medium', color: '#CA8A04' },
  { key: 'low', label: 'Low', color: '#0284C7' },
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
        backgroundColor: '#0F172A',
        titleColor: '#F8FAFC',
        bodyColor: '#CBD5E1',
        borderColor: '#334155',
        borderWidth: 1,
        padding: 8,
        cornerRadius: 6,
      },
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#64748B', font: { family: 'Inter', size: 10, weight: '600' } },
        border: { color: '#E2E8F0' },
      },
      y: {
        grid: { color: '#F1F5F9' },
        ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 9 }, precision: 0 },
        border: { display: false },
      },
    },
  };

  return (
    <div className="glass-panel" style={{ padding: '16px 18px', height: '190px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <h3 style={{ fontSize: '13px', fontWeight: '800', color: '#0F172A' }}>
          Alerts by Severity Tier
        </h3>
        <span style={{ fontSize: '11px', color: '#64748B', fontWeight: '500' }}>
          Urgency Classification
        </span>
      </div>
      <div style={{ flex: 1, position: 'relative' }}>
        <Bar data={data} options={options} />
      </div>
    </div>
  );
}
