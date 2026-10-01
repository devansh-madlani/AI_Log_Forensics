import { useEffect, useRef, useState } from 'react';
import Icon from './Icon';
import './Header.css';

const OS_ICON = { Windows: 'windows', macOS: 'apple', Linux: 'linux' };

const MAX_EVENT_OPTIONS = [200, 1000, 2000, 5000];
const WINDOW_OPTIONS = [
  { value: '15m', label: 'Last 15 minutes' },
  { value: '1h', label: 'Last hour' },
  { value: '6h', label: 'Last 6 hours' },
  { value: '1d', label: 'Last 24 hours' },
];

function HostStatus({ host }) {
  if (host === undefined) {
    return <span className="host-status host-status--pending"><span className="host-status__dot" />Connecting…</span>;
  }
  if (host === null) {
    return (
      <span className="host-status host-status--down" role="status">
        <span className="host-status__dot" />Backend offline
      </span>
    );
  }
  return (
    <span className={`host-status ${host.live_collection_supported ? 'host-status--ok' : 'host-status--warn'}`} role="status">
      <span className="host-status__dot" />
      {OS_ICON[host.host_os] && <Icon name={OS_ICON[host.host_os]} size={14} />}
      <span>This machine: <strong>{host.host_os}</strong></span>
      <span className="host-status__sub">
        {host.live_collection_supported ? 'Live collection ready' : 'Demo data only'}
      </span>
    </span>
  );
}

function CollectOptions({ options, onChange, hostOs, onClose }) {
  const ref = useRef(null);

  useEffect(() => {
    function onDocClick(e) {
      if (ref.current && !ref.current.contains(e.target) && !e.target.closest('[data-collect-options-toggle]')) onClose();
    }
    function onKey(e) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [onClose]);

  const usesWindow = hostOs === 'macOS' || hostOs === 'Linux';

  return (
    <div className="collect-options" ref={ref} role="dialog" aria-label="Collection options">
      <div className="collect-options__title">Collection options</div>
      <label className="collect-options__field">
        <span>{hostOs === 'Windows' ? 'Newest events per log' : 'Maximum events'}</span>
        <select
          value={options.max_events_per_channel}
          onChange={(e) => onChange({ ...options, max_events_per_channel: Number(e.target.value) })}
        >
          {MAX_EVENT_OPTIONS.map((n) => <option key={n} value={n}>{n.toLocaleString()}</option>)}
        </select>
      </label>
      {usesWindow && (
        <label className="collect-options__field">
          <span>Time window</span>
          <select value={options.last} onChange={(e) => onChange({ ...options, last: e.target.value })}>
            {WINDOW_OPTIONS.map((w) => <option key={w.value} value={w.value}>{w.label}</option>)}
          </select>
        </label>
      )}
      {hostOs === 'Windows' && (
        <label className="collect-options__check">
          <input
            type="checkbox"
            checked={options.include_sysmon}
            onChange={(e) => onChange({ ...options, include_sysmon: e.target.checked })}
          />
          <span>Include Sysmon (if installed)</span>
        </label>
      )}
      <p className="collect-options__note">
        {hostOs === 'Windows' && 'Reads Security, System and Application. The Security log needs the backend running as Administrator.'}
        {hostOs === 'macOS' && 'Reads the Unified Log with Apple’s log tool. Shorter windows collect faster.'}
        {hostOs === 'Linux' && 'Reads the systemd journal (falls back to /var/log). Run the backend with sudo to include auth logs.'}
      </p>
    </div>
  );
}

export default function Header({
  host, onLoadDemo, onCollect, onSafeIncident, onRunAnalysis, busy, lastAction, unanalyzedCount, sourceLabel,
  collectOptions, onCollectOptionsChange,
}) {
  const [optionsOpen, setOptionsOpen] = useState(false);
  const canCollect = Boolean(host && host.live_collection_supported);

  return (
    <header className="app-header">
      <div className="app-header__identity">
        <div className="app-header__mark" aria-hidden="true">
          <Icon name="shield" size={20} strokeWidth={2} />
        </div>
        <div className="app-header__titles">
          <h1 className="app-header__title">Forensic Log Analysis</h1>
          <p className="app-header__subtitle">Find and explain suspicious activity in host logs</p>
        </div>
      </div>

      <div className="app-header__status">
        <HostStatus host={host} />
      </div>

      <div className="app-header__actions">
        <div className="collect-group">
          <button
            className="btn collect-group__main"
            onClick={onCollect}
            disabled={busy || !canCollect}
            title={canCollect ? `Collect live logs from this ${host.host_os} machine` : 'Live collection is not available on this host'}
          >
            {busy && lastAction === 'collect' ? <span className="btn__spinner" /> : <Icon name="collect" />}
            {busy && lastAction === 'collect' ? 'Collecting…' : 'Collect live logs'}
          </button>
          <button
            className="btn btn--icon collect-group__toggle"
            onClick={() => setOptionsOpen((v) => !v)}
            disabled={!canCollect}
            aria-expanded={optionsOpen}
            aria-label="Collection options"
            data-collect-options-toggle
          >
            <Icon name="sliders" />
          </button>
          {optionsOpen && canCollect && (
            <CollectOptions
              options={collectOptions}
              onChange={onCollectOptionsChange}
              hostOs={host.host_os}
              onClose={() => setOptionsOpen(false)}
            />
          )}
        </div>
        <button
          className="btn"
          onClick={onSafeIncident}
          disabled={busy || !canCollect}
          title={canCollect
            ? 'Briefly create and remove a test account, fail some logons, then collect and analyze the real events'
            : 'Live collection is not available on this host'}
        >
          {busy && lastAction === 'incident' ? <span className="btn__spinner" /> : <Icon name="flask" />}
          {busy && lastAction === 'incident' ? 'Staging…' : 'Stage safe incident'}
        </button>
        <button className="btn" onClick={onLoadDemo} disabled={busy || host === null}>
          {busy && lastAction === 'demo' ? <span className="btn__spinner" /> : <Icon name="beaker" />}
          {busy && lastAction === 'demo' ? 'Loading…' : 'Load demo'}
        </button>
        <button
          className="btn btn--primary"
          onClick={onRunAnalysis}
          disabled={busy || host === null}
          title={`Run analysis on ${sourceLabel} events`}
        >
          {busy && lastAction === 'analysis' ? <span className="btn__spinner" /> : <Icon name="analyze" />}
          {busy && lastAction === 'analysis' ? 'Analyzing…' : 'Run analysis'}
          {unanalyzedCount > 0 && !(busy && lastAction === 'analysis') && (
            <span className="btn__count" aria-label={`${unanalyzedCount} events awaiting analysis`}>
              {unanalyzedCount > 999 ? '999+' : unanalyzedCount}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}
