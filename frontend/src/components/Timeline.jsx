import { useMemo, useState } from 'react';
import { formatAxis, formatDateTime, formatNumber, parseTime } from '../format';
import './Timeline.css';

const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const RISK_COLOR_VAR = {
  LOW: '--risk-low',
  MEDIUM: '--risk-medium',
  HIGH: '--risk-high',
  CRITICAL: '--risk-critical',
};
const TICKS = 5;

// Bar height reflects the risk score's magnitude (0-100 -> 10-100%),
// and horizontal position reflects real elapsed time — so bursts of
// activity visually cluster and severity reads as amplitude, the way
// a seismograph encodes real information rather than decorating it.
export default function Timeline({ events, selectedId, onSelect }) {
  const [hover, setHover] = useState(null);

  const { points, ticks } = useMemo(() => {
    const timed = (events || [])
      .map((e) => ({ e, t: parseTime(e.timestamp) }))
      .filter((p) => p.t != null);
    if (timed.length === 0) return { points: [], ticks: [] };

    const min = Math.min(...timed.map((p) => p.t));
    const max = Math.max(...timed.map((p) => p.t));
    const span = Math.max(max - min, 1);

    // Draw low-risk first so high-risk bars sit on top when they overlap.
    const pts = timed
      .map(({ e, t }) => ({
        id: e.id,
        pct: ((t - min) / span) * 100,
        heightPct: e.analyzed ? Math.max(10, e.risk_score ?? 0) : 6,
        level: e.analyzed ? (e.risk_level || 'LOW') : null,
        event: e,
      }))
      .sort((a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level));

    const tickList = Array.from({ length: TICKS }, (_, i) => {
      const t = min + (span * i) / (TICKS - 1);
      return { pct: (i / (TICKS - 1)) * 100, label: formatAxis(t, span) };
    });
    return { points: pts, ticks: tickList };
  }, [events]);

  const hoverPoint = hover != null ? points.find((p) => p.id === hover) : null;

  return (
    <div className="timeline" role="group" aria-labelledby="timeline-title">
      <div className="panel__header">
        <div>
          <h2 className="panel__title" id="timeline-title">Incident trace</h2>
          <p className="panel__subtitle">
            {points.length > 0
              ? `The ${formatNumber(points.length)} most recent events. Taller bars carry a higher risk score; click one to inspect it.`
              : 'Chronological view of the selected scope.'}
          </p>
        </div>
        {points.some((p) => !p.level) && (
          <div className="timeline-legend">
            <span className="timeline-legend__item">
              <span className="timeline-legend__dot timeline-legend__dot--pending" />
              Grey bars are not analyzed yet
            </span>
          </div>
        )}
      </div>

      {points.length === 0 ? (
        <div className="timeline-empty">No events in this scope yet.</div>
      ) : (
        <div className="timeline-body">
          <div className="timeline-track" onMouseLeave={() => setHover(null)}>
            <div className="timeline-track__grid">
              {ticks.map((t) => <span key={t.pct} style={{ left: `${t.pct}%` }} />)}
            </div>
            <div className="timeline-track__baseline" />
            {points.map((p) => (
              <button
                key={p.id}
                className={`timeline-bar ${p.id === selectedId ? 'is-selected' : ''} ${p.level ? '' : 'is-pending'}`}
                style={{
                  left: `${p.pct}%`,
                  height: `${p.heightPct}%`,
                  background: p.level ? `var(${RISK_COLOR_VAR[p.level]})` : undefined,
                }}
                onClick={() => onSelect(p.id)}
                onMouseEnter={() => setHover(p.id)}
                onFocus={() => setHover(p.id)}
                onBlur={() => setHover(null)}
                aria-label={`${formatDateTime(p.event.timestamp)} ${p.event.event_type}, ${p.level ? p.level.toLowerCase() + ' risk' : 'not analyzed'}`}
              />
            ))}
            {hoverPoint && (
              <div
                className="timeline-tip"
                style={{ left: `clamp(90px, ${hoverPoint.pct}%, calc(100% - 90px))` }}
                role="tooltip"
              >
                <div className="timeline-tip__time mono">{formatDateTime(hoverPoint.event.timestamp)}</div>
                <div className="timeline-tip__type">{hoverPoint.event.event_type}</div>
                <div className="timeline-tip__meta">
                  {hoverPoint.level
                    ? `${hoverPoint.level.charAt(0) + hoverPoint.level.slice(1).toLowerCase()} risk, score ${Math.round(hoverPoint.event.risk_score ?? 0)}`
                    : 'Not analyzed yet'}
                </div>
              </div>
            )}
          </div>
          <div className="timeline-axis">
            {ticks.map((t, i) => (
              <span
                key={t.pct}
                style={{ left: `${t.pct}%` }}
                className={i === 0 ? 'is-first' : i === ticks.length - 1 ? 'is-last' : ''}
              >
                {t.label}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
