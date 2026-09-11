/**
 * SIH Cyber Threat Detection — Dashboard Application
 *
 * Real-time alert feed via WebSocket with Chart.js visualizations.
 * Polling fallback if WebSocket is unavailable.
 *
 * PRD §4: Polling or WebSocket for live updates.
 * rules.md R6.5: Dashboard reads from Alert Store via API.
 */

(() => {
    'use strict';

    // ================================================================
    // Configuration
    // ================================================================
    const API_BASE = window.location.origin;
    const WS_URL = `ws://${window.location.host}/ws/alerts`;
    const POLL_INTERVAL_MS = 3000;
    const MAX_TABLE_ROWS = 100;

    // ================================================================
    // State
    // ================================================================
    let ws = null;
    let pollTimer = null;
    let alertCache = [];
    let threatChart = null;
    let severityChart = null;
    let timelineChart = null;

    // ================================================================
    // DOM References
    // ================================================================
    const dom = {
        throughputValue: document.getElementById('throughput-value'),
        totalAlertsValue: document.getElementById('total-alerts-value'),
        connectionDot: document.querySelector('.connection__dot'),
        connectionText: document.querySelector('.connection__text'),
        countCritical: document.getElementById('count-critical'),
        countHigh: document.getElementById('count-high'),
        countMedium: document.getElementById('count-medium'),
        countLow: document.getElementById('count-low'),
        alertTableBody: document.getElementById('alert-table-body'),
        filterThreat: document.getElementById('filter-threat'),
        filterSeverity: document.getElementById('filter-severity'),
        evidenceModal: document.getElementById('evidence-modal'),
        modalClose: document.getElementById('modal-close'),
        modalMeta: document.getElementById('modal-meta'),
        modalJson: document.getElementById('modal-json'),
    };

    // ================================================================
    // Threat class display names & colors
    // ================================================================
    const THREAT_LABELS = {
        ddos: 'DDoS',
        recon_scan: 'Recon / Scan',
        c2_beaconing: 'C2 Beaconing',
        dga_dns: 'DGA / DNS',
        encrypted_malware: 'Enc. Malware',
        exfiltration: 'Exfiltration',
    };

    const THREAT_COLORS = {
        ddos: '#ef4444',
        recon_scan: '#f97316',
        c2_beaconing: '#a855f7',
        dga_dns: '#06b6d4',
        encrypted_malware: '#ec4899',
        exfiltration: '#10b981',
    };

    const SEVERITY_COLORS = {
        critical: '#ef4444',
        high: '#f97316',
        medium: '#eab308',
        low: '#3b82f6',
    };

    // ================================================================
    // Chart.js Setup
    // ================================================================
    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: '#94a3b8',
                    font: { family: "'Inter', sans-serif", size: 11 },
                    padding: 12,
                },
            },
        },
    };

    function initCharts() {
        // --- Threat Breakdown (Doughnut) ---
        const threatCtx = document.getElementById('threat-chart').getContext('2d');
        threatChart = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: Object.values(THREAT_LABELS),
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: Object.values(THREAT_COLORS),
                    borderColor: '#111827',
                    borderWidth: 2,
                    hoverOffset: 8,
                }],
            },
            options: {
                ...chartDefaults,
                cutout: '65%',
                plugins: {
                    ...chartDefaults.plugins,
                    legend: {
                        ...chartDefaults.plugins.legend,
                        position: 'right',
                    },
                },
            },
        });

        // --- Severity Distribution (Horizontal Bar) ---
        const sevCtx = document.getElementById('severity-chart').getContext('2d');
        severityChart = new Chart(sevCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.7)',
                        'rgba(249, 115, 22, 0.7)',
                        'rgba(234, 179, 8, 0.7)',
                        'rgba(59, 130, 246, 0.7)',
                    ],
                    borderColor: [
                        '#ef4444', '#f97316', '#eab308', '#3b82f6',
                    ],
                    borderWidth: 1,
                    borderRadius: 6,
                    barPercentage: 0.6,
                }],
            },
            options: {
                ...chartDefaults,
                indexAxis: 'y',
                plugins: {
                    ...chartDefaults.plugins,
                    legend: { display: false },
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        ticks: { color: '#64748b', font: { family: "'Inter', sans-serif" } },
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8', font: { family: "'Inter', sans-serif", weight: 600 } },
                    },
                },
            },
        });

        // --- Timeline (Line) ---
        const tlCtx = document.getElementById('timeline-chart').getContext('2d');
        timelineChart = new Chart(tlCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Alerts',
                    data: [],
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                    pointBackgroundColor: '#6366f1',
                    pointBorderColor: '#1e1b4b',
                    pointBorderWidth: 2,
                    borderWidth: 2,
                }],
            },
            options: {
                ...chartDefaults,
                plugins: {
                    ...chartDefaults.plugins,
                    legend: { display: false },
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        ticks: {
                            color: '#64748b',
                            maxRotation: 0,
                            maxTicksLimit: 10,
                            font: { family: "'JetBrains Mono', monospace", size: 10 },
                        },
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        ticks: { color: '#64748b', font: { family: "'Inter', sans-serif" } },
                        beginAtZero: true,
                    },
                },
            },
        });
    }

    // ================================================================
    // Data Fetching
    // ================================================================
    async function fetchJSON(path) {
        try {
            const res = await fetch(`${API_BASE}${path}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return await res.json();
        } catch (err) {
            console.error(`Fetch failed: ${path}`, err);
            return null;
        }
    }

    async function refreshStats() {
        const stats = await fetchJSON('/api/stats');
        if (!stats) return;

        // Pipeline throughput
        if (stats.pipeline) {
            dom.throughputValue.textContent = `${stats.pipeline.flows_per_sec} flows/s`;
        }

        // Alert counts
        const alertStats = stats.alerts || {};
        dom.totalAlertsValue.textContent = alertStats.total_alerts || 0;

        // Severity cards
        const bySev = alertStats.by_severity || {};
        dom.countCritical.textContent = bySev.critical || 0;
        dom.countHigh.textContent = bySev.high || 0;
        dom.countMedium.textContent = bySev.medium || 0;
        dom.countLow.textContent = bySev.low || 0;

        // Update threat chart
        const byThreat = alertStats.by_threat_class || {};
        const threatKeys = Object.keys(THREAT_LABELS);
        threatChart.data.datasets[0].data = threatKeys.map(k => byThreat[k] || 0);
        threatChart.update('none');

        // Update severity chart
        severityChart.data.datasets[0].data = [
            bySev.critical || 0,
            bySev.high || 0,
            bySev.medium || 0,
            bySev.low || 0,
        ];
        severityChart.update('none');
    }

    async function refreshTimeline() {
        const data = await fetchJSON('/api/timeline?minutes=30&bucket_seconds=60');
        if (!data) return;

        timelineChart.data.labels = data.map(d => {
            const t = new Date(d.bucket);
            return t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        });
        timelineChart.data.datasets[0].data = data.map(d => d.count);
        timelineChart.update('none');
    }

    async function refreshAlerts() {
        const threat = dom.filterThreat.value;
        const sev = dom.filterSeverity.value;
        let path = `/api/alerts?limit=${MAX_TABLE_ROWS}`;
        if (threat) path += `&threat_class=${threat}`;
        if (sev) path += `&severity=${sev}`;

        const data = await fetchJSON(path);
        if (!data) return;

        alertCache = data;
        renderAlertTable(data);
    }

    // ================================================================
    // Alert Table Rendering
    // ================================================================
    function renderAlertTable(alerts) {
        const tbody = dom.alertTableBody;

        if (!alerts || alerts.length === 0) {
            tbody.innerHTML = '<tr class="alert-table__empty"><td colspan="6">No alerts yet…</td></tr>';
            return;
        }

        tbody.innerHTML = alerts.map(a => buildAlertRow(a)).join('');
    }

    function buildAlertRow(alert) {
        const sev = alert.severity || 'low';
        const threat = alert.threat_class || 'unknown';
        const conf = typeof alert.confidence === 'number' ? alert.confidence : 0;
        const confPct = Math.round(conf * 100);
        const ts = formatTimestamp(alert.timestamp);
        const confColor = conf >= 0.7 ? '#ef4444' : conf >= 0.4 ? '#eab308' : '#3b82f6';

        return `
            <tr class="alert-row" data-alert-id="${escapeHTML(alert.alert_id)}">
                <td><span class="severity-badge severity-badge--${sev}">${sev}</span></td>
                <td><span class="timestamp">${ts}</span></td>
                <td><span class="threat-tag threat-tag--${threat}">${THREAT_LABELS[threat] || threat}</span></td>
                <td><span class="flow-id" title="${escapeHTML(alert.flow_id)}">${escapeHTML(alert.flow_id)}</span></td>
                <td>
                    <div class="confidence-bar">
                        <div class="confidence-bar__track">
                            <div class="confidence-bar__fill" style="width:${confPct}%; background:${confColor}"></div>
                        </div>
                        <span class="confidence-bar__value">${confPct}%</span>
                    </div>
                </td>
                <td><button class="evidence-btn" onclick="window.__showEvidence('${escapeHTML(alert.alert_id)}')">View</button></td>
            </tr>
        `;
    }

    function addAlertToTable(alert) {
        // Remove empty placeholder
        const empty = dom.alertTableBody.querySelector('.alert-table__empty');
        if (empty) empty.remove();

        // Check filters
        const threatFilter = dom.filterThreat.value;
        const sevFilter = dom.filterSeverity.value;
        if (threatFilter && alert.threat_class !== threatFilter) return;
        if (sevFilter && alert.severity !== sevFilter) return;

        // Prepend new row with animation
        const temp = document.createElement('tbody');
        temp.innerHTML = buildAlertRow(alert);
        const newRow = temp.firstElementChild;
        newRow.classList.add('alert-row--new');
        dom.alertTableBody.prepend(newRow);

        // Trim table
        while (dom.alertTableBody.children.length > MAX_TABLE_ROWS) {
            dom.alertTableBody.lastChild.remove();
        }

        // Update cache
        alertCache.unshift(alert);
        if (alertCache.length > MAX_TABLE_ROWS) alertCache.pop();
    }

    // ================================================================
    // Evidence Modal
    // ================================================================
    window.__showEvidence = function(alertId) {
        const alert = alertCache.find(a => a.alert_id === alertId);
        if (!alert) return;

        // Build meta section
        dom.modalMeta.innerHTML = `
            <div class="modal__meta-item">
                <span class="modal__meta-label">Alert ID</span>
                <span class="modal__meta-value">${escapeHTML(alert.alert_id)}</span>
            </div>
            <div class="modal__meta-item">
                <span class="modal__meta-label">Timestamp</span>
                <span class="modal__meta-value">${escapeHTML(alert.timestamp)}</span>
            </div>
            <div class="modal__meta-item">
                <span class="modal__meta-label">Threat Class</span>
                <span class="modal__meta-value">${THREAT_LABELS[alert.threat_class] || alert.threat_class}</span>
            </div>
            <div class="modal__meta-item">
                <span class="modal__meta-label">Flow ID</span>
                <span class="modal__meta-value">${escapeHTML(alert.flow_id)}</span>
            </div>
            <div class="modal__meta-item">
                <span class="modal__meta-label">Confidence</span>
                <span class="modal__meta-value">${Math.round(alert.confidence * 100)}%</span>
            </div>
            <div class="modal__meta-item">
                <span class="modal__meta-label">Severity</span>
                <span class="modal__meta-value">${alert.severity}</span>
            </div>
        `;

        // Build evidence JSON
        const evidence = typeof alert.evidence === 'string'
            ? JSON.parse(alert.evidence) : alert.evidence;
        dom.modalJson.textContent = JSON.stringify(evidence, null, 2);

        // Show modal
        dom.evidenceModal.hidden = false;
    };

    dom.modalClose.addEventListener('click', () => {
        dom.evidenceModal.hidden = true;
    });

    dom.evidenceModal.addEventListener('click', (e) => {
        if (e.target === dom.evidenceModal) {
            dom.evidenceModal.hidden = true;
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !dom.evidenceModal.hidden) {
            dom.evidenceModal.hidden = true;
        }
    });

    // ================================================================
    // Filters
    // ================================================================
    dom.filterThreat.addEventListener('change', refreshAlerts);
    dom.filterSeverity.addEventListener('change', refreshAlerts);

    // ================================================================
    // WebSocket Connection
    // ================================================================
    function connectWebSocket() {
        try {
            ws = new WebSocket(WS_URL);

            ws.onopen = () => {
                dom.connectionDot.className = 'connection__dot connected';
                dom.connectionText.textContent = 'Live';
                console.log('WebSocket connected');

                // Stop polling fallback
                if (pollTimer) {
                    clearInterval(pollTimer);
                    pollTimer = null;
                }
            };

            ws.onmessage = (event) => {
                try {
                    const alert = JSON.parse(event.data);
                    addAlertToTable(alert);
                    refreshStats();
                    refreshTimeline();
                } catch (err) {
                    console.error('Failed to parse WebSocket message:', err);
                }
            };

            ws.onclose = () => {
                dom.connectionDot.className = 'connection__dot disconnected';
                dom.connectionText.textContent = 'Disconnected';
                console.log('WebSocket disconnected — reconnecting in 3s');
                startPolling();
                setTimeout(connectWebSocket, 3000);
            };

            ws.onerror = (err) => {
                console.error('WebSocket error:', err);
                ws.close();
            };
        } catch (err) {
            console.error('WebSocket connection failed:', err);
            startPolling();
            setTimeout(connectWebSocket, 5000);
        }
    }

    // ================================================================
    // Polling Fallback
    // ================================================================
    function startPolling() {
        if (pollTimer) return;
        dom.connectionDot.className = 'connection__dot';
        dom.connectionText.textContent = 'Polling';
        pollTimer = setInterval(() => {
            refreshAlerts();
            refreshStats();
            refreshTimeline();
        }, POLL_INTERVAL_MS);
    }

    // ================================================================
    // Utilities
    // ================================================================
    function formatTimestamp(ts) {
        if (!ts) return '—';
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString([], {
                hour: '2-digit', minute: '2-digit', second: '2-digit',
            }) + ' ' + d.toLocaleDateString([], {
                month: 'short', day: 'numeric',
            });
        } catch {
            return ts;
        }
    }

    function escapeHTML(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    }

    // ================================================================
    // Initialize
    // ================================================================
    function init() {
        initCharts();
        refreshStats();
        refreshAlerts();
        refreshTimeline();
        connectWebSocket();

        // Periodic refresh for stats & timeline even with WebSocket
        setInterval(refreshStats, 5000);
        setInterval(refreshTimeline, 10000);
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
