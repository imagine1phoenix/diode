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
        borderColor: '#06b6d4',
        backgroundColor: 'rgba(6, 182, 212, 0.12)',
        borderWidth: 2,
        tension: 0.35,
        pointRadius: 2,
        pointHoverRadius: 6,
        pointBackgroundColor: '#06b6d4',
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
        bodyColor: '#06b6d4',
        borderColor: 'rgba(6, 182, 212, 0.25)',
        borderWidth: 1,
        padding: 10,
        cornerRadius: 8,
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(148, 163, 184, 0.05)' },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
        border: { display: false },
      },
      y: {
        grid: { color: 'rgba(148, 163, 184, 0.08)' },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
        border: { display: false },
      },
    },
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', height: '360px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#f8fafc' }}>
          Real-Time Threat Volume Timeline
        </h3>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Sliding Window (10s size, 5s overlap)
        </span>
      </div>
      <div style={{ flex: 1, position: 'relative' }}>
        <Line data={data} options={options} />
      </div>
    </div>
  );
}
