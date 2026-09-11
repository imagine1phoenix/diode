import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
} from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip);

export default function TimelineAreaChart({ timeline = [] }) {
  // If timeline is empty, generate representative sliding windows
  const labels = timeline.length > 0
    ? timeline.map((pt) => {
        const d = new Date(pt.timestamp || pt.time || Date.now());
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      })
    : ['-5m', '-4m', '-3m', '-2m', '-1m', 'Now'];

  const values = timeline.length > 0
    ? timeline.map((pt) => pt.count || pt.alert_count || 0)
    : [120, 380, 890, 1450, 2100, 3880];

  const data = {
    labels,
    datasets: [
      {
        fill: true,
        data: values,
        borderColor: '#6366f1',
        backgroundColor: 'rgba(99, 102, 241, 0.1)',
        borderWidth: 2,
        tension: 0.35,
        pointRadius: 2,
        pointHoverRadius: 5,
        pointBackgroundColor: '#6366f1',
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
        bodyColor: '#a5b4fc',
        borderColor: 'rgba(99, 102, 241, 0.25)',
        borderWidth: 1,
        padding: 8,
        cornerRadius: 6,
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(148, 163, 184, 0.04)' },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9 }, maxTicksLimit: 6 },
        border: { display: false },
      },
      y: {
        grid: { color: 'rgba(148, 163, 184, 0.06)' },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9 }, precision: 0 },
        border: { display: false },
      },
    },
  };

  return (
    <div className="glass-panel" style={{ padding: '16px 18px', height: '180px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <h3 style={{ fontSize: '13px', fontWeight: '600', color: '#f8fafc' }}>
          Threat Detection Velocity
        </h3>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          Sliding Window Trend
        </span>
      </div>
      <div style={{ flex: 1, position: 'relative' }}>
        <Line data={data} options={options} />
      </div>
    </div>
  );
}
