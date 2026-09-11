import React, { useState, useEffect } from 'react';
import {
  X, Bell, Send, CheckCircle2, AlertTriangle, ExternalLink,
  Shield, Radio, Loader2, RefreshCw, Eye, EyeOff, Bot, Sparkles
} from 'lucide-react';
import { getApiUrl } from '../api';

export default function NotificationModal({ isOpen, onClose }) {
  const [config, setConfig] = useState({
    webhook_url: '',
    telegram_bot_token: '',
    telegram_chat_id: '',
    min_severity: 'high',
    cooldown_seconds: 60,
  });
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [showTgToken, setShowTgToken] = useState(false);

  // Fetch active config and logs on open
  useEffect(() => {
    if (!isOpen) return;

    let mounted = true;
    async function loadData() {
      setLoading(true);
      try {
        const [cfgRes, logsRes] = await Promise.all([
          fetch(getApiUrl('/api/notifications/config')),
          fetch(getApiUrl('/api/notifications/logs?limit=15')),
        ]);

        if (cfgRes.ok && mounted) {
          const cfgData = await cfgRes.json();
          setConfig((prev) => ({
            ...prev,
            webhook_url: cfgData.webhook_url || '',
            telegram_chat_id: cfgData.telegram_chat_id || '',
            min_severity: cfgData.min_severity || 'high',
            cooldown_seconds: cfgData.cooldown_seconds || 60,
          }));
        }

        if (logsRes.ok && mounted) {
          const logsData = await logsRes.json();
          setLogs(logsData || []);
        }
      } catch (err) {
        console.warn('Failed to load notification settings:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadData();
    return () => { mounted = false; };
  }, [isOpen]);

  if (!isOpen) return null;

  // Auto-detect webhook format
  const getWebhookBadge = (url) => {
    if (!url) return { label: 'Unconfigured', color: '#64748B', bg: '#F1F5F9' };
    if (url.includes('discord.com')) return { label: 'Discord Rich Embed', color: '#5865F2', bg: '#EEF2FF' };
    if (url.includes('slack.com')) return { label: 'Slack Block Kit', color: '#E01E5A', bg: '#FDF2F8' };
    return { label: 'Standard JSON Webhook', color: '#2563EB', bg: '#EFF6FF' };
  };

  const webhookBadge = getWebhookBadge(config.webhook_url);

  // Save updated config
  const handleSave = async () => {
    setSaving(true);
    setSaveSuccess(false);
    try {
      const payload = {
        webhook_url: config.webhook_url,
        telegram_chat_id: config.telegram_chat_id,
        min_severity: config.min_severity,
        cooldown_seconds: Number(config.cooldown_seconds),
      };
      if (config.telegram_bot_token.trim()) {
        payload.telegram_bot_token = config.telegram_bot_token.trim();
      }

      const res = await fetch(getApiUrl('/api/notifications/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 3000);
      }
    } catch (err) {
      console.error('Save error:', err);
    } finally {
      setSaving(false);
    }
  };

  // Trigger test dispatch
  const handleTestDispatch = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch(getApiUrl('/api/notifications/test'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          channel: 'all',
          webhook_url: config.webhook_url,
          telegram_bot_token: config.telegram_bot_token,
          telegram_chat_id: config.telegram_chat_id,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setTestResult(data);
        // Refresh logs
        const logsRes = await fetch(getApiUrl('/api/notifications/logs?limit=15'));
        if (logsRes.ok) {
          const l = await logsRes.json();
          setLogs(l || []);
        }
      }
    } catch (err) {
      setTestResult({ status: 'error', error: String(err) });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(8px)',
        padding: '16px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '16px',
          boxShadow: 'var(--shadow-card)',
          maxWidth: '820px',
          width: '100%',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          transition: 'background 0.2s ease, border-color 0.2s ease',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '18px 24px',
          borderBottom: '1px solid var(--border-subtle)',
          background: 'var(--bg-surface-hover)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '10px',
              background: 'rgba(79, 70, 229, 0.15)',
              border: '1px solid rgba(129, 140, 248, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#818CF8',
            }}>
              <Bell size={18} />
            </div>
            <div>
              <h2 style={{
                fontSize: '15px',
                fontWeight: '900',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '-0.01em',
                margin: 0,
              }}>
                External Alert Dispatcher // Operational Integrations
              </h2>
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', margin: '2px 0 0', fontWeight: '500' }}>
                Forward High & Critical detections directly to Webhooks, Discord, Slack, and Telegram
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Content Body */}
        <div style={{ padding: '24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Webhook Card */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            padding: '16px 18px',
            boxShadow: 'var(--shadow-sm)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>Webhook / Slack / Discord URL</span>
              </div>
              <span style={{
                fontSize: '10.5px',
                fontWeight: '700',
                fontFamily: 'var(--font-mono)',
                color: webhookBadge.color,
                background: webhookBadge.bg,
                padding: '2px 8px',
                borderRadius: '6px',
              }}>
                {webhookBadge.label}
              </span>
            </div>
            <input
              type="text"
              placeholder="https://discord.com/api/webhooks/... or https://hooks.slack.com/... or https://api.yourdomain.com/alert"
              value={config.webhook_url}
              onChange={(e) => setConfig({ ...config, webhook_url: e.target.value })}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle)',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
                background: 'var(--bg-surface)',
                color: 'var(--text-primary)',
              }}
            />
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '6px', marginBottom: 0 }}>
              Discord and Slack webhooks are automatically converted to native color-coded rich cards.
            </p>
          </div>

          {/* Telegram Bot Card */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            padding: '16px 18px',
            boxShadow: 'var(--shadow-sm)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Bot size={15} color="#0284C7" />
              <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>Telegram Bot Integration</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <label style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  Bot Token
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showTgToken ? 'text' : 'password'}
                    placeholder="123456:ABC-DEF1234..."
                    value={config.telegram_bot_token}
                    onChange={(e) => setConfig({ ...config, telegram_bot_token: e.target.value })}
                    style={{
                      width: '100%',
                      padding: '8px 32px 8px 12px',
                      borderRadius: '8px',
                      border: '1px solid var(--border-subtle)',
                      fontSize: '11.5px',
                      fontFamily: 'var(--font-mono)',
                      outline: 'none',
                      background: 'var(--bg-surface)',
                      color: 'var(--text-primary)',
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowTgToken(!showTgToken)}
                    style={{
                      position: 'absolute',
                      right: '8px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-secondary)',
                      cursor: 'pointer',
                    }}
                  >
                    {showTgToken ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  Chat ID or Channel
                </label>
                <input
                  type="text"
                  placeholder="-100123456789 or @soc_channel"
                  value={config.telegram_chat_id}
                  onChange={(e) => setConfig({ ...config, telegram_chat_id: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '8px',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '11.5px',
                    fontFamily: 'var(--font-mono)',
                    outline: 'none',
                    background: 'var(--bg-surface)',
                    color: 'var(--text-primary)',
                  }}
                />
              </div>
            </div>
          </div>

          {/* Trigger Threshold & Anti-Spam */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <div style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '12px',
              padding: '14px 16px',
            }}>
              <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-primary)', display: 'block', marginBottom: '8px' }}>
                Minimum Severity Gate
              </span>
              <div style={{ display: 'flex', gap: '6px' }}>
                {[
                  { id: 'critical', label: 'Critical Only' },
                  { id: 'high', label: 'High & Critical (Recommended)' },
                  { id: 'all', label: 'All Detections' },
                ].map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setConfig({ ...config, min_severity: item.id })}
                    style={{
                      flex: 1,
                      padding: '6px 8px',
                      borderRadius: '6px',
                      border: '1px solid',
                      borderColor: config.min_severity === item.id ? '#2563EB' : 'var(--border-subtle)',
                      background: config.min_severity === item.id ? 'rgba(37, 99, 235, 0.15)' : 'var(--bg-surface)',
                      color: config.min_severity === item.id ? 'var(--accent-blue)' : 'var(--text-secondary)',
                      fontSize: '11px',
                      fontWeight: config.min_severity === item.id ? '700' : '500',
                      cursor: 'pointer',
                    }}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>

            <div style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '12px',
              padding: '14px 16px',
            }}>
              <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-primary)', display: 'block', marginBottom: '8px' }}>
                Anti-Flood Rate Limit (Cooldown)
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                  type="number"
                  min={5}
                  max={3600}
                  value={config.cooldown_seconds}
                  onChange={(e) => setConfig({ ...config, cooldown_seconds: e.target.value })}
                  style={{
                    width: '80px',
                    padding: '6px 10px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '12px',
                    fontWeight: '700',
                    fontFamily: 'var(--font-mono)',
                    background: 'var(--bg-surface)',
                    color: 'var(--text-primary)',
                  }}
                />
                <span style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                  seconds per identical threat vector
                </span>
              </div>
            </div>
          </div>

          {/* Action Bar */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingTop: '8px',
            borderTop: '1px solid var(--border-subtle)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                type="button"
                onClick={handleTestDispatch}
                disabled={testing || (!config.webhook_url && !config.telegram_bot_token)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '7px 14px',
                  borderRadius: '8px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-primary)',
                  fontSize: '11.5px',
                  fontWeight: '700',
                  cursor: (!config.webhook_url && !config.telegram_bot_token) ? 'not-allowed' : 'pointer',
                  opacity: (!config.webhook_url && !config.telegram_bot_token) ? 0.5 : 1,
                }}
              >
                {testing ? <Loader2 size={13} className="spin" /> : <Send size={13} color="#2563EB" />}
                <span>Send Test Alert</span>
              </button>

              {testResult && (
                <span style={{
                  fontSize: '11px',
                  fontWeight: '600',
                  color: testResult.total_sent > 0 ? '#15803D' : '#D97706',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                }}>
                  {testResult.total_sent > 0 ? <CheckCircle2 size={13} /> : <AlertTriangle size={13} />}
                  {testResult.total_sent > 0
                    ? `Dispatched ${testResult.total_sent} test notifications`
                    : 'No destinations configured'}
                </span>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {saveSuccess && (
                <span style={{ fontSize: '11px', color: '#15803D', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle2 size={14} />
                  Settings saved
                </span>
              )}
              <button
                type="button"
                onClick={handleSave}
                disabled={saving}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 18px',
                  borderRadius: '8px',
                  background: 'var(--text-primary)',
                  border: 'none',
                  color: 'var(--bg-card)',
                  fontSize: '12px',
                  fontWeight: '700',
                  cursor: 'pointer',
                }}
              >
                {saving && <Loader2 size={13} className="spin" />}
                <span>Save Configuration</span>
              </button>
            </div>
          </div>

          {/* Audit Logs Table */}
          <div style={{ marginTop: '8px' }}>
            <span style={{
              fontSize: '11px',
              fontWeight: '800',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: 'var(--text-secondary)',
              display: 'block',
              marginBottom: '6px',
            }}>
              Outbound Dispatch Logs (Last {logs.length})
            </span>
            <div style={{
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              maxHeight: '160px',
              overflowY: 'auto',
              background: 'var(--bg-surface)',
            }}>
              {logs.length === 0 ? (
                <div style={{ padding: '24px', textAlign: 'center', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                  No notifications dispatched yet. Trigger an attack simulation or test alert to see real deliveries.
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-secondary)', textAlign: 'left' }}>
                      <th style={{ padding: '6px 10px' }}>Time</th>
                      <th style={{ padding: '6px 10px' }}>Channel</th>
                      <th style={{ padding: '6px 10px' }}>Destination</th>
                      <th style={{ padding: '6px 10px' }}>Status</th>
                      <th style={{ padding: '6px 10px', textAlign: 'right' }}>Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((log, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '5px 10px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td style={{ padding: '5px 10px', fontWeight: '700', color: 'var(--text-primary)' }}>
                          {log.channel}
                        </td>
                        <td style={{ padding: '5px 10px', color: 'var(--text-secondary)', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {log.target}
                        </td>
                        <td style={{ padding: '5px 10px' }}>
                          <span style={{
                            padding: '1px 6px',
                            borderRadius: '4px',
                            fontSize: '10px',
                            fontWeight: '700',
                            fontFamily: 'var(--font-mono)',
                            background: log.status === 'delivered' ? 'var(--live-bg)' : 'var(--critical-bg)',
                            color: log.status === 'delivered' ? 'var(--live-text)' : 'var(--critical-text)',
                          }}>
                            {log.status_code ? `HTTP ${log.status_code}` : log.status}
                          </span>
                        </td>
                        <td style={{ padding: '5px 10px', textAlign: 'right', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                          {log.latency_ms}ms
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
