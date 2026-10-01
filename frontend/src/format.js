// Shared, locale-aware formatting helpers for timestamps and numbers.

export function parseTime(iso) {
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : t;
}

export function formatDateTime(iso) {
  const t = parseTime(iso);
  if (t == null) return iso || '—';
  return new Date(t).toLocaleString(undefined, {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

export function formatFullDateTime(iso) {
  const t = parseTime(iso);
  if (t == null) return iso || '—';
  return new Date(t).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZoneName: 'short',
  });
}

// Axis label that includes the date only when the visible span needs it.
export function formatAxis(ms, spanMs) {
  const d = new Date(ms);
  const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
  if (spanMs < 20 * 60 * 60 * 1000) return time;
  return `${d.toLocaleDateString(undefined, { month: 'short', day: '2-digit' })} ${time}`;
}

export function formatNumber(n) {
  if (n == null) return '—';
  return n.toLocaleString();
}

export function pluralize(n, word) {
  return `${formatNumber(n)} ${word}${n === 1 ? '' : 's'}`;
}
