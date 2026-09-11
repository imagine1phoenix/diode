// API & WebSocket Configuration for DIODE Enclave Dashboard
// Supports local monolithic deployment (FastAPI serving React) and decoupled cloud deployments (Vercel, Render, AWS)

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
export const WS_BASE_URL = (import.meta.env.VITE_WS_BASE_URL || '').replace(/\/$/, '');

export function getApiUrl(endpoint) {
  const cleanPath = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return API_BASE_URL ? `${API_BASE_URL}${cleanPath}` : cleanPath;
}

export function getWsUrl(endpoint = '/ws') {
  const cleanPath = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  if (WS_BASE_URL) {
    return `${WS_BASE_URL}${cleanPath}`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  return `${protocol}//${host}${cleanPath}`;
}
