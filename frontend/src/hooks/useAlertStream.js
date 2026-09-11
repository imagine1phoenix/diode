import { useState, useEffect, useCallback, useRef } from 'react';
import { getApiUrl, getWsUrl } from '../api';

export function useAlertStream() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total_alerts: 0,
    by_threat_class: {},
    by_severity: {},
    throughput: { flows_per_sec: 0, alerts_per_sec: 0 },
  });
  const [timeline, setTimeline] = useState([]);
  const [connected, setConnected] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  // Fetch initial data with cache-busting
  const fetchStatsAndAlerts = useCallback(async () => {
    try {
      const timestamp = Date.now();
      const [statsRes, alertsRes, timelineRes] = await Promise.all([
        fetch(getApiUrl(`/api/stats?_t=${timestamp}`)),
        fetch(getApiUrl(`/api/alerts?limit=100&_t=${timestamp}`)),
        fetch(getApiUrl(`/api/timeline?minutes=30&_t=${timestamp}`)),
      ]);

      if (statsRes.ok) {
        const data = await statsRes.json();
        setStats({
          total_alerts: data.alerts?.total_alerts || 0,
          by_threat_class: data.alerts?.by_threat_class || {},
          by_severity: data.alerts?.by_severity || {},
          throughput: data.pipeline || { flows_per_sec: 0, alerts_per_sec: 0 },
        });
      }

      if (alertsRes.ok) {
        const alertList = await alertsRes.json();
        // Deduplicate incoming list by alert_id and flow signature
        const seen = new Set();
        const uniqueAlerts = [];
        for (const a of alertList) {
          const key = a.alert_id || `${a.flow_id}-${a.threat_class}-${a.timestamp}`;
          if (!seen.has(key)) {
            seen.add(key);
            uniqueAlerts.push(a);
          }
        }
        setAlerts(uniqueAlerts);

        // Harmonize stats with the loaded alerts
        if (uniqueAlerts.length > 0) {
          const byThreat = {};
          const bySev = {};
          for (const a of uniqueAlerts) {
            const tc = a.threat_class || 'unknown';
            const sev = a.severity || 'low';
            byThreat[tc] = (byThreat[tc] || 0) + 1;
            bySev[sev] = (bySev[sev] || 0) + 1;
          }
          setStats((prev) => ({
            ...prev,
            total_alerts: uniqueAlerts.length,
            by_threat_class: byThreat,
            by_severity: bySev,
          }));
        }
      }

      if (timelineRes.ok) {
        const tl = await timelineRes.json();
        setTimeline(tl);
      }
    } catch (err) {
      console.warn('Failed to fetch initial stats:', err);
    }
  }, []);

  // Manual refresh with visual spinning indicator (minimum 600ms duration)
  const manualRefresh = useCallback(async () => {
    setIsRefreshing(true);
    const startTime = Date.now();
    try {
      await fetchStatsAndAlerts();
    } finally {
      const elapsed = Date.now() - startTime;
      const remainingDelay = Math.max(0, 600 - elapsed);
      setTimeout(() => {
        setIsRefreshing(false);
      }, remainingDelay);
    }
  }, [fetchStatsAndAlerts]);

  // Connect WebSocket
  useEffect(() => {
    let unmounted = false;

    function connectWs() {
      const wsUrl = getWsUrl('/ws');

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!unmounted) {
          setConnected(true);
          console.log('✅ SOC WebSocket connected');
        }
      };

      ws.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
          const key = alert.alert_id || `${alert.flow_id}-${alert.threat_class}-${alert.timestamp}`;

          setAlerts((prev) => {
            const exists = prev.some((a) => {
              const prevKey = a.alert_id || `${a.flow_id}-${a.threat_class}-${a.timestamp}`;
              return prevKey === key;
            });
            if (exists) return prev; // Avoid duplicate alerts
            return [alert, ...prev.slice(0, 249)];
          });

          // Increment stats in real time only if not duplicate
          setStats((prev) => {
            const threatClass = alert.threat_class || 'unknown';
            const severity = alert.severity || 'low';
            return {
              ...prev,
              total_alerts: prev.total_alerts + 1,
              by_threat_class: {
                ...prev.by_threat_class,
                [threatClass]: (prev.by_threat_class[threatClass] || 0) + 1,
              },
              by_severity: {
                ...prev.by_severity,
                [severity]: (prev.by_severity[severity] || 0) + 1,
              },
            };
          });
        } catch (err) {
          console.error('Error parsing WS message:', err);
        }
      };

      ws.onclose = () => {
        if (!unmounted) {
          setConnected(false);
          console.log('WebSocket disconnected — reconnecting in 3s...');
          reconnectTimeoutRef.current = setTimeout(connectWs, 3000);
        }
      };

      ws.onerror = (err) => {
        console.warn('WebSocket error:', err);
        ws.close();
      };
    }

    fetchStatsAndAlerts();
    connectWs();

    // Fallback polling every 5s for stats & timeline
    const interval = setInterval(fetchStatsAndAlerts, 5000);

    return () => {
      unmounted = true;
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) wsRef.current.close();
      clearInterval(interval);
    };
  }, [fetchStatsAndAlerts]);

  const [lastSimulationResult, setLastSimulationResult] = useState(null);

  // Simulate Attack Trigger
  const simulateAttack = async (threatClass = 'all') => {
    setIsSimulating(true);
    try {
      const res = await fetch(getApiUrl(`/api/simulate?threat_class=${threatClass}`), {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        setLastSimulationResult(data);
        await fetchStatsAndAlerts();
        return data;
      }
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
    return null;
  };

  return {
    alerts,
    stats,
    timeline,
    connected,
    isSimulating,
    isRefreshing,
    simulateAttack,
    lastSimulationResult,
    refresh: manualRefresh,
  };
}

