// Thin fetch wrapper for the FastAPI backend. Requests go through the
// Vite dev-server proxy at /api (see vite.config.js), which forwards
// to http://127.0.0.1:8000 — no CORS juggling, no hardcoded host.

const BASE = '/api';

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
  } catch {
    throw new Error('Cannot reach the backend. Make sure it is running on port 8000.');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore parse failure, fall back to statusText */
    }
    if (res.status === 502 || res.status === 504) {
      detail = 'Cannot reach the backend. Make sure it is running on port 8000.';
    }
    throw new Error(detail || `Request to ${path} failed (${res.status})`);
  }
  return res.json();
}

function qs(params = {}) {
  const clean = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (clean.length === 0) return '';
  return '?' + new URLSearchParams(clean).toString();
}

export const api = {
  health: () => request('/health'),
  stats: (params) => request(`/stats${qs(params)}`),
  events: (params) => request(`/events${qs(params)}`),
  suspiciousEvents: (params) => request(`/events/suspicious${qs(params)}`),
  event: (id) => request(`/events/${id}`),
  timeline: (params) => request(`/timeline${qs(params)}`),
  loadDemo: (numNormalEvents) => request(`/demo/load${qs({ num_normal_events: numNormalEvents })}`, { method: 'POST' }),
  collect: (params) => request(`/collect${qs(params)}`, { method: 'POST' }),
  safeIncident: () => request('/collect/safe-incident', { method: 'POST' }),
  runAnalysis: (params) => request(`/analysis/run${qs(params)}`, { method: 'POST' }),
};
