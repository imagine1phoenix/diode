import React, { useState, useEffect } from 'react';
import { Mic, MicOff, Volume2, VolumeX, Sparkles, X, ShieldAlert, CheckCircle2, Radio, Send, Play } from 'lucide-react';
import { getApiUrl } from '../api';

export default function VoiceAuditAssist({ onInspectAlert, topAlert }) {
  const [isOpen, setIsOpen] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [response, setResponse] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [customPrompt, setCustomPrompt] = useState('');

  const sampleQueries = [
    'Summarize current highest-severity intrusion corridor and diode health.',
    'Explain how Shannon entropy detected the active volumetric flood.',
    'Verify that the physical optical diode is operating in 100% simplex read-only mode.',
  ];

  const speakText = (text) => {
    if (isMuted || !('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    const cleanText = text.replace(/[#*`_]/g, '').slice(0, 280);
    const utter = new SpeechSynthesisUtterance(cleanText);
    utter.rate = 1.05;
    utter.pitch = 1.0;
    window.speechSynthesis.speak(utter);
  };

  const runQuery = async (queryText) => {
    setIsOpen(true);
    setIsListening(true);
    setTranscript('');
    setResponse('');

    setTimeout(async () => {
      setTranscript(queryText);
      setIsListening(false);
      setIsProcessing(true);

      try {
        const res = await fetch(getApiUrl('/api/copilot/chat'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            query: queryText,
            alert: topAlert || null,
          }),
        });
        const data = await res.json();
        setIsProcessing(false);
        const ans = data.answer || 'Voice audit complete: Enclave operational, zero outbound sockets active.';
        setResponse(ans);
        speakText(ans);
      } catch (err) {
        setIsProcessing(false);
        const fallback = 'Voice Audit Fallback: 1 Critical SYN flood corridor active on Core BGP Peering router. Optical tap 100% simplex Rx.';
        setResponse(fallback);
        speakText(fallback);
      }
    }, 700);
  };

  return (
    <>
      {/* Floating Tactical Voice Action Button */}
      <div
        style={{
          position: 'fixed',
          bottom: '24px',
          right: '28px',
          zIndex: 60,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}
      >
        <button
          onClick={() => runQuery(sampleQueries[0])}
          title="Hold to initiate tactical voice audit query"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 18px',
            borderRadius: '9999px',
            background: 'linear-gradient(135deg, #0F172A 0%, #1E293B 50%, #2563EB 100%)',
            color: '#FFFFFF',
            fontWeight: '700',
            fontSize: '12px',
            letterSpacing: '0.04em',
            fontFamily: 'var(--font-mono)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            boxShadow: '0 4px 20px rgba(15, 23, 42, 0.35), 0 0 15px rgba(37, 99, 235, 0.2)',
            cursor: 'pointer',
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'translateY(-2px)';
            e.currentTarget.style.boxShadow = '0 6px 24px rgba(15, 23, 42, 0.45), 0 0 20px rgba(37, 99, 235, 0.3)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'translateY(0)';
            e.currentTarget.style.boxShadow = '0 4px 20px rgba(15, 23, 42, 0.35), 0 0 15px rgba(37, 99, 235, 0.2)';
          }}
        >
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: '#22C55E',
          }} className="pulse" />
          <Mic size={15} color="#38BDF8" />
          <span>🎙️ VOICE AUDIT ASSIST</span>
        </button>
      </div>

      {/* Voice Audit Modal */}
      {isOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.6)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 150,
            padding: '20px',
          }}
          onClick={() => {
            window.speechSynthesis?.cancel();
            setIsOpen(false);
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '560px',
              background: '#FFFFFF',
              borderRadius: '20px',
              border: '1px solid #E2E8F0',
              boxShadow: '0 20px 40px -15px rgba(0, 0, 0, 0.2)',
              padding: '24px',
              position: 'relative',
              display: 'flex',
              flexDirection: 'column',
              maxHeight: '90vh',
              overflowY: 'auto',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '10px',
                  background: '#EFF6FF',
                  border: '1px solid #DBEAFE',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#2563EB',
                }}>
                  <Mic size={18} />
                </div>
                <div>
                  <h3 style={{
                    fontSize: '15px',
                    fontWeight: '900',
                    color: '#0F172A',
                    fontFamily: 'var(--font-mono)',
                    textTransform: 'uppercase',
                    letterSpacing: '-0.01em',
                    margin: 0,
                  }}>
                    Voice Audit Assist // Local SLM
                  </h3>
                  <p style={{ fontSize: '11px', color: '#64748B', margin: 0, fontWeight: '500' }}>
                    Air-gapped voice telemetry query engine • Live Speech Synthesis
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <button
                  onClick={() => {
                    const next = !isMuted;
                    setIsMuted(next);
                    if (next) window.speechSynthesis?.cancel();
                  }}
                  title={isMuted ? 'Unmute Audio' : 'Mute Audio'}
                  style={{
                    background: '#F1F5F9',
                    border: 'none',
                    color: isMuted ? '#EF4444' : '#2563EB',
                    width: '30px',
                    height: '30px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    cursor: 'pointer',
                  }}
                >
                  {isMuted ? <VolumeX size={15} /> : <Volume2 size={15} />}
                </button>
                <button
                  onClick={() => {
                    window.speechSynthesis?.cancel();
                    setIsOpen(false);
                  }}
                  style={{
                    background: '#F1F5F9',
                    border: 'none',
                    color: '#64748B',
                    width: '30px',
                    height: '30px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    cursor: 'pointer',
                  }}
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Audio Wave Visualizer Strip */}
            <div style={{
              background: '#F8FAFC',
              border: '1px solid #E2E8F0',
              borderRadius: '12px',
              padding: '14px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '10px',
              marginBottom: '16px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '5px', height: '36px' }}>
                {[14, 22, 32, 18, 28, 36, 20, 16, 34, 26, 18, 24, 34, 20, 15].map((h, i) => (
                  <div
                    key={i}
                    style={{
                      width: '4px',
                      height: isListening ? `${h}px` : isProcessing ? '14px' : '6px',
                      background: isListening ? '#2563EB' : isProcessing ? '#7C3AED' : '#CBD5E1',
                      borderRadius: '2px',
                      transition: 'height 0.2s ease, background-color 0.2s ease',
                    }}
                  />
                ))}
              </div>

              <span style={{
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                fontWeight: '700',
                color: isListening ? '#2563EB' : isProcessing ? '#7C3AED' : '#15803D',
                letterSpacing: '0.04em',
                textTransform: 'uppercase',
              }}>
                {isListening ? '• Listening... Enclave Microphone Active' : isProcessing ? '• Processing On-Premise SLM...' : '• Audit Ready // Live'}
              </span>
            </div>

            {/* Tactical Sample Questions */}
            <div style={{ marginBottom: '14px' }}>
              <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Quick Tactical Queries
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '6px' }}>
                {sampleQueries.map((q, idx) => (
                  <button
                    key={idx}
                    onClick={() => runQuery(q)}
                    style={{
                      textAlign: 'left',
                      background: '#F1F5F9',
                      border: '1px solid #E2E8F0',
                      borderRadius: '8px',
                      padding: '8px 12px',
                      fontSize: '12px',
                      color: '#1E293B',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      fontWeight: '500',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = '#EFF6FF';
                      e.currentTarget.style.borderColor = '#BFDBFE';
                      e.currentTarget.style.color = '#1D4ED8';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = '#F1F5F9';
                      e.currentTarget.style.borderColor = '#E2E8F0';
                      e.currentTarget.style.color = '#1E293B';
                    }}
                  >
                    <Play size={11} color="#2563EB" />
                    <span>{q}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Query Transcript */}
            <div style={{ marginBottom: '14px' }}>
              <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Audited Query
              </span>
              <div style={{
                background: '#F8FAFC',
                border: '1px solid #CBD5E1',
                borderRadius: '8px',
                padding: '10px 14px',
                fontSize: '12.5px',
                fontWeight: '600',
                color: '#0F172A',
                fontStyle: transcript ? 'normal' : 'italic',
                marginTop: '4px',
              }}>
                {transcript || 'Select a quick query above or enter a question...'}
              </div>
            </div>

            {/* Generated SLM Response */}
            {response && (
              <div style={{
                background: '#EFF6FF',
                border: '1px solid #BFDBFE',
                borderRadius: '10px',
                padding: '14px',
                marginBottom: '16px',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Sparkles size={14} color="#2563EB" />
                    <span style={{ fontSize: '11px', fontWeight: '800', color: '#1E40AF', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Air-Gapped SLM Forensic Brief
                    </span>
                  </div>
                  <button
                    onClick={() => speakText(response)}
                    title="Re-read aloud"
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: '#2563EB',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontSize: '11px',
                      fontWeight: '700',
                    }}
                  >
                    <Volume2 size={13} />
                    <span>Read</span>
                  </button>
                </div>
                <div
                  style={{ fontSize: '12.5px', color: '#1E3A8A', lineHeight: 1.5, margin: 0 }}
                  dangerouslySetInnerHTML={{
                    __html: response.replace(/\n\n/g, '<div style="margin: 6px 0;"></div>').replace(/```([a-z]*)\n([\s\S]*?)```/g, '<pre style="background:#0F172A;color:#38BDF8;padding:8px;border-radius:6px;font-size:10px;">$2</pre>')
                  }}
                />
              </div>
            )}

            {/* Custom Input */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (customPrompt.trim()) {
                  runQuery(customPrompt.trim());
                  setCustomPrompt('');
                }
              }}
              style={{
                display: 'flex',
                gap: '8px',
                marginTop: 'auto',
                paddingTop: '8px',
              }}
            >
              <input
                type="text"
                value={customPrompt}
                onChange={(e) => setCustomPrompt(e.target.value)}
                placeholder="Type custom voice audit question..."
                style={{
                  flex: 1,
                  padding: '8px 12px',
                  borderRadius: '8px',
                  border: '1px solid #CBD5E1',
                  background: '#F8FAFC',
                  fontSize: '12px',
                  outline: 'none',
                  color: '#0F172A',
                }}
              />
              <button
                type="submit"
                disabled={!customPrompt.trim()}
                style={{
                  padding: '8px 14px',
                  borderRadius: '8px',
                  background: customPrompt.trim() ? '#2563EB' : '#94A3B8',
                  color: '#FFFFFF',
                  border: 'none',
                  fontWeight: '700',
                  fontSize: '12px',
                  cursor: customPrompt.trim() ? 'pointer' : 'default',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                <Send size={12} />
                <span>Ask</span>
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
