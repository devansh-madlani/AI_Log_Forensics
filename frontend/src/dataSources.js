// Evidence scopes the dashboard can focus on. `hostOs` links a live
// source to the backend host OS reported by GET /health, so the UI can
// mark "this machine" and jump to the right scope after a collection.
export const DATA_SOURCE_OPTIONS = [
  {
    id: 'all',
    label: 'All Sources',
    detail: 'Every collected and demo record',
    params: {},
  },
  {
    id: 'windows-live',
    label: 'Windows',
    detail: 'Observed Windows Event Log evidence',
    params: { os: 'windows', data_origin: 'OBSERVED' },
    hostOs: 'Windows',
  },
  {
    id: 'macos-live',
    label: 'macOS',
    detail: 'Observed macOS Unified Log evidence',
    params: { os: 'macos', data_origin: 'OBSERVED' },
    hostOs: 'macOS',
  },
  {
    id: 'linux-live',
    label: 'Linux',
    detail: 'Observed Linux journal and syslog evidence',
    params: { os: 'linux', data_origin: 'OBSERVED' },
    hostOs: 'Linux',
  },
  {
    id: 'synthetic-demo',
    label: 'Demo',
    detail: 'Clearly labeled synthetic Windows attack scenario',
    params: { data_origin: 'SYNTHETIC_DEMO' },
  },
];

export function getDataSourceOption(id) {
  return DATA_SOURCE_OPTIONS.find((option) => option.id === id) || DATA_SOURCE_OPTIONS[0];
}

export function sourceForHost(hostOs) {
  return DATA_SOURCE_OPTIONS.find((option) => option.hostOs && option.hostOs === hostOs) || null;
}
