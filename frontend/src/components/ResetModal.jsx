import React, { useState } from 'react';
import { X, RotateCcw, Sparkles, Trash2, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';

export default function ResetModal({
  isOpen,
  onClose,
  onReset,
  isResetting = false,
}) {
  const [resetMode, setResetMode] = useState('baseline'); // 'baseline' or 'empty'
  const [clearNotifications, setClearNotifications] = useState(true);
  const [statusMessage, setStatusMessage] = useState(null);

  if (!isOpen) return null;

  const handleExecuteReset = async () => {
    setStatusMessage(null);
    try {
      const res = await onReset(resetMode, clearNotifications);
      if (res && res.status === 'success') {
        setStatusMessage(
          resetMode === 'empty'
            ? '✅ Enclave successfully cleared to zero alerts.'
            : `✅ Enclave restored to clean multi-vector baseline (${res.total_alerts || 6} alerts).`
        );
        setTimeout(() => {
          onClose();
          setStatusMessage(null);
        }, 900);
      } else {
        setStatusMessage('⚠️ Reset completed, refreshing enclave telemetry...');
        setTimeout(() => {
          onClose();
          setStatusMessage(null);
        }, 900);
      }
    } catch (err) {
      console.error('Reset execution error:', err);
      setStatusMessage('❌ Reset failed. Check server console logs.');
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(6px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 110,
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '560px',
          padding: '26px',
          background: 'var(--bg-card)',
          borderRadius: '16px',
          border: '1px solid var(--border-subtle)',
          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.45)',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '18px',
            right: '18px',
            background: 'transparent',
            border: 'none',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            padding: '4px',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          aria-label="Close Reset Modal"
        >
          <X size={18} />
        </button>

        {/* Modal Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
          <div
            style={{
              width: '42px',
              height: '42px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, #EF4444, #DC2626)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#FFFFFF',
              boxShadow: '0 4px 12px rgba(220, 38, 38, 0.25)',
              flexShrink: 0,
            }}
          >
            <RotateCcw size={20} />
          </div>
          <div>
            <h2
              style={{
                fontSize: '17px',
                fontWeight: '800',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '-0.01em',
              }}
            >
              Reset Enclave State
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Restore clean baseline or wipe telemetry slate for a pristine live demo.
            </p>
          </div>
        </div>

        {/* Mode Selector Cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', margin: '20px 0' }}>
          {/* Mode 1: Baseline Reset */}
          <div
            onClick={() => setResetMode('baseline')}
            style={{
              padding: '14px',
              borderRadius: '12px',
              border: `2px solid ${resetMode === 'baseline' ? '#2563EB' : 'var(--border-subtle)'}`,
              background: resetMode === 'baseline' ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
            }}
          >
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: '#EFF6FF',
                color: '#2563EB',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                marginTop: '2px',
              }}
            >
              <Sparkles size={16} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '13px', fontWeight: '800', color: 'var(--text-primary)' }}>
                  Restore Clean Baseline
                </span>
                <span
                  style={{
                    fontSize: '10px',
                    fontWeight: '800',
                    padding: '2px 7px',
                    borderRadius: '4px',
                    background: '#DBEAFE',
                    color: '#1D4ED8',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  RECOMMENDED
                </span>
              </div>
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: '1.4' }}>
                Flushes previous attack bursts, zeroes latency metrics, and re-seeds a balanced 6-vector baseline
                covering DDoS, Port Scans, C2 Beaconing, DGA DNS, JA3 Malware, and Exfiltration.
              </p>
            </div>
          </div>

          {/* Mode 2: Wipe Clean Slate */}
          <div
            onClick={() => setResetMode('empty')}
            style={{
              padding: '14px',
              borderRadius: '12px',
              border: `2px solid ${resetMode === 'empty' ? '#DC2626' : 'var(--border-subtle)'}`,
              background: resetMode === 'empty' ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
            }}
          >
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: '#FEF2F2',
                color: '#DC2626',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                marginTop: '2px',
              }}
            >
              <Trash2 size={16} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '13px', fontWeight: '800', color: 'var(--text-primary)' }}>
                  Wipe Clean Slate (0 Alerts)
                </span>
                <span
                  style={{
                    fontSize: '10px',
                    fontWeight: '800',
                    padding: '2px 7px',
                    borderRadius: '4px',
                    background: '#FEE2E2',
                    color: '#B91C1C',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  EMPTY SLATE
                </span>
              </div>
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: '1.4' }}>
                Clears all alerts from SQLite database to 0. Resets radar and KPI charts completely.
                Allows presenting a clean start before triggering attack simulations live.
              </p>
            </div>
          </div>
        </div>

        {/* Clear Notifications Option */}
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '12px',
            color: 'var(--text-primary)',
            cursor: 'pointer',
            padding: '4px 0',
            marginBottom: '18px',
            userSelect: 'none',
          }}
        >
          <input
            type="checkbox"
            checked={clearNotifications}
            onChange={(e) => setClearNotifications(e.target.checked)}
            style={{ width: '15px', height: '15px', cursor: 'pointer', accentColor: '#2563EB' }}
          />
          <span style={{ fontWeight: '500' }}>
            Also clear webhook delivery audit logs and anti-flood rate-limit caches
          </span>
        </label>

        {/* Status Message */}
        {statusMessage && (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: '8px',
              fontSize: '12px',
              fontWeight: '600',
              marginBottom: '16px',
              background: statusMessage.startsWith('✅') ? '#ECFDF5' : '#FEF2F2',
              color: statusMessage.startsWith('✅') ? '#047857' : '#B91C1C',
              border: `1px solid ${statusMessage.startsWith('✅') ? '#A7F3D0' : '#FECACA'}`,
            }}
          >
            {statusMessage}
          </div>
        )}

        {/* Modal Actions */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '10px' }}>
          <button
            onClick={onClose}
            disabled={isResetting}
            style={{
              padding: '8px 16px',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              background: 'transparent',
              color: 'var(--text-primary)',
              fontSize: '12px',
              fontWeight: '600',
              cursor: isResetting ? 'not-allowed' : 'pointer',
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleExecuteReset}
            disabled={isResetting}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '7px',
              padding: '8px 18px',
              borderRadius: '8px',
              border: 'none',
              background: resetMode === 'empty' ? 'linear-gradient(135deg, #EF4444, #B91C1C)' : 'linear-gradient(135deg, #2563EB, #1D4ED8)',
              color: '#FFFFFF',
              fontSize: '12.5px',
              fontWeight: '700',
              cursor: isResetting ? 'wait' : 'pointer',
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.2)',
              transition: 'opacity 0.15s ease',
            }}
          >
            {isResetting ? (
              <>
                <Loader2 size={14} style={{ animation: 'spin 0.6s linear infinite' }} />
                <span>Resetting Enclave...</span>
              </>
            ) : (
              <>
                <RotateCcw size={14} />
                <span>{resetMode === 'empty' ? 'Wipe Everything to Zero' : 'Reset to Clean Baseline'}</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
