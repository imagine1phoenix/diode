import { useState, useEffect, useCallback, useRef } from 'react';

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
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  // Fetch initial data
  const fetchStatsAndAlerts = useCallback(async () => {
    try {
      const [statsRes, alertsRes, timelineRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/alerts?limit=100'),
        fetch('/api/timeline?minutes=30'),
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
        setAlerts(alertList);
      }

      if (timelineRes.ok) {
        const tl = await timelineRes.json();
        setTimeline(tl);
      }
    } catch (err) {
      console.warn('Failed to fetch initial stats:', err);
    }
  }, []);

  // Connect WebSocket
  useEffect(() => {
    let unmounted = false;

    function connectWs() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/ws`;

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
          setAlerts((prev) => [alert, ...prev.slice(0, 249)]);

          // Increment stats in real time
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

  // Simulate Attack Trigger
  const simulateAttack = async (threatClass = 'all') => {
    setIsSimulating(true);
    try {
      const res = await fetch(`/api/simulate?threat_class=${threatClass}`, {
        method: 'POST',
      });
      if (res.ok) {
        await fetchStatsAndAlerts();
      }
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  return {
    alerts,
    stats,
    timeline,
    connected,
    isSimulating,
    simulateAttack,
    refresh: fetchStatsAndAlerts,
  };
}
