import { useMemo, useState } from 'react';
import RiskBadge, { DataOriginTag } from './RiskBadge';
import Icon from './Icon';
import { formatDateTime, formatNumber } from '../format';
import './SuspiciousTable.css';

const LEVEL_OPTIONS = [
  { value: 'MEDIUM', label: 'Medium+' },
  { value: 'HIGH', label: 'High+' },
  { value: 'CRITICAL', label: 'Critical' },
];

function searchText(ev) {
  return [
    ev.event_type, ev.log_source, ev.provider, ev.event_id, ev.message, ev.user,
    ev.process_name, ev.command_line, ev.source_ip, ev.destination_ip, ev.computer,
    ...(ev.analysis_reasons || []),
  ].filter(Boolean).join(' ').toLowerCase();
}

function ScoreBar({ score, level }) {
  const value = score == null ? 0 : Math.round(score);
  return (
    <div className={`score-bar score-bar--${(level || 'low').toLowerCase()}`} title={`Risk score ${value}/100`}>
      <span className="score-bar__value">{score == null ? '—' : value}</span>
      <span className="score-bar__track"><span className="score-bar__fill" style={{ width: `${value}%` }} /></span>
    </div>
  );
}

function SkeletonRows() {
  return Array.from({ length: 6 }, (_, i) => (
    <tr key={i} className="skeleton-row">
      <td colSpan={5}><div className="skeleton" style={{ height: 18, width: `${90 - i * 8}%` }} /></td>
    </tr>
  ));
}

export default function SuspiciousTable({
  events, total, selectedId, onSelect, minRiskLevel, onChangeMinRiskLevel, loading, hasUnanalyzed,
}) {
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return events;
    return events.filter((ev) => searchText(ev).includes(q));
  }, [events, query]);

  const emptyMessage = query
    ? `No suspicious events match “${query}”.`
    : hasUnanalyzed
      ? 'Events are waiting to be scored — click Run analysis to find suspicious activity.'
      : 'Nothing at this risk level. That’s a good sign — try a lower threshold to review more.';

  return (
    <section className="panel suspicious-panel" aria-labelledby="suspicious-title">
      <div className="panel__header">
        <div>
          <h2 className="panel__title" id="suspicious-title">Suspicious events</h2>
          <p className="panel__subtitle">
            {total == null
              ? 'Ranked by risk score, most severe first.'
              : `${query ? `${formatNumber(filtered.length)} of ` : ''}${formatNumber(total)} flagged, most severe first.`}
            {total != null && total > events.length && ` Showing the top ${formatNumber(events.length)}.`}
          </p>
        </div>
        <div className="suspicious-panel__controls">
          <label className="search-field">
            <Icon name="search" size={14} />
            <span className="sr-only">Search suspicious events</span>
            <input
              type="search"
              placeholder="Search type, user, process, reason…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          <div className="segmented" role="radiogroup" aria-label="Minimum risk level">
            {LEVEL_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                role="radio"
                aria-checked={minRiskLevel === opt.value}
                className={`segmented__item segmented__item--${opt.value.toLowerCase()} ${minRiskLevel === opt.value ? 'is-active' : ''}`}
                onClick={() => onChangeMinRiskLevel(opt.value)}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col" className="col-risk">Risk</th>
              <th scope="col" className="col-time">When</th>
              <th scope="col">Event</th>
              <th scope="col" className="col-reason">Why flagged</th>
              <th scope="col" className="col-anomaly">Anomaly</th>
            </tr>
          </thead>
          <tbody>
            {loading && events.length === 0 && <SkeletonRows />}
            {filtered.map((ev) => {
              const reasons = ev.analysis_reasons || [];
              return (
                <tr
                  key={ev.id}
                  className={ev.id === selectedId ? 'is-selected' : ''}
                  onClick={() => onSelect(ev.id)}
                  tabIndex={0}
                  aria-selected={ev.id === selectedId}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelect(ev.id);
                    }
                  }}
                >
                  <td className="col-risk">
                    <RiskBadge level={ev.risk_level} size="sm" />
                    <ScoreBar score={ev.risk_score} level={ev.risk_level} />
                  </td>
                  <td className="col-time mono">
                    <span className="cell-time">{formatDateTime(ev.timestamp)}</span>
                    <DataOriginTag origin={ev.data_origin} />
                  </td>
                  <td className="col-event">
                    <div className="cell-primary">{ev.event_type}</div>
                    <div className="cell-secondary">
                      <span>{ev.log_source}</span>
                      {ev.event_id != null && <span className="mono">ID {ev.event_id}</span>}
                      {ev.user && <span>{ev.user}</span>}
                    </div>
                  </td>
                  <td className="col-reason">
                    <div className="cell-reason" title={reasons.join('\n')}>{reasons[0] || '—'}</div>
                    {reasons.length > 1 && <div className="cell-more">+{reasons.length - 1} more reason{reasons.length > 2 ? 's' : ''}</div>}
                  </td>
                  <td className="col-anomaly mono">{ev.anomaly_score != null ? ev.anomaly_score.toFixed(2) : '—'}</td>
                </tr>
              );
            })}
            {!loading && filtered.length === 0 && (
              <tr className="empty-row">
                <td colSpan={5}>
                  <Icon name={query ? 'search' : 'check'} size={18} />
                  <span>{emptyMessage}</span>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
