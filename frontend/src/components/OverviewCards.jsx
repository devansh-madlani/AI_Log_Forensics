import { formatNumber } from '../format';
import './OverviewCards.css';

const LEVELS = [
  { key: 'LOW', label: 'Low' },
  { key: 'MEDIUM', label: 'Medium' },
  { key: 'HIGH', label: 'High' },
  { key: 'CRITICAL', label: 'Critical' },
];

function pct(part, whole) {
  if (!whole) return 0;
  return (part / whole) * 100;
}

function RiskDistribution({ stats }) {
  const breakdown = stats.risk_breakdown || {};
  const analyzed = stats.analyzed_events || 0;
  return (
    <div className="summary__dist">
      <div className="summary__label">Risk distribution of {formatNumber(analyzed)} analyzed events</div>
      <div className="risk-dist__bar" role="img" aria-label={LEVELS.map((l) => `${l.label} ${breakdown[l.key] || 0}`).join(', ')}>
        {analyzed === 0 ? (
          <span className="risk-dist__empty" />
        ) : (
          LEVELS.map((l) => {
            const n = breakdown[l.key] || 0;
            if (!n) return null;
            return (
              <span
                key={l.key}
                className={`risk-dist__seg risk-dist__seg--${l.key.toLowerCase()}`}
                style={{ flexGrow: Math.max(pct(n, analyzed), 1.2) }}
                title={`${l.label}: ${formatNumber(n)} (${pct(n, analyzed).toFixed(1)}%)`}
              />
            );
          })
        )}
      </div>
      <ul className="risk-dist__legend">
        {LEVELS.map((l) => (
          <li key={l.key}>
            <span className={`risk-dist__dot risk-dist__dot--${l.key.toLowerCase()}`} />
            {l.label} <strong>{formatNumber(breakdown[l.key] || 0)}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}

// Summary strip across the top of the incident trace. Numbers sit on one
// baseline, separated by hairlines, instead of a row of identical cards.
export default function OverviewCards({ stats }) {
  if (!stats) {
    return (
      <div className="summary" aria-busy="true">
        {[0, 1, 2, 3].map((i) => (
          <div className="summary__metric" key={i}>
            <div className="skeleton" style={{ width: 70, height: 12 }} />
            <div className="skeleton" style={{ width: 54, height: 30, marginTop: 10 }} />
          </div>
        ))}
        <div className="summary__dist"><div className="skeleton" style={{ height: 44 }} /></div>
      </div>
    );
  }

  const analyzed = stats.analyzed_events || 0;
  const metrics = [
    {
      key: 'total',
      label: 'Events',
      value: stats.total_events,
      sub: stats.unanalyzed_events > 0 ? `${formatNumber(stats.unanalyzed_events)} awaiting analysis` : 'All analyzed',
    },
    {
      key: 'medium',
      label: 'Suspicious',
      value: stats.suspicious_events,
      sub: analyzed ? `${pct(stats.suspicious_events, analyzed).toFixed(1)}% of analyzed` : 'Medium risk or higher',
    },
    { key: 'high', label: 'High risk', value: stats.high_risk_events, sub: 'Score 61 to 80' },
    { key: 'critical', label: 'Critical', value: stats.critical_risk_events, sub: 'Score 81 to 100' },
  ];

  return (
    <div className="summary">
      {metrics.map((m) => (
        <div className={`summary__metric summary__metric--${m.key} ${m.value > 0 ? 'has-value' : ''}`} key={m.key}>
          <div className="summary__label">{m.label}</div>
          <div className="summary__value">{formatNumber(m.value ?? 0)}</div>
          <div className="summary__sub">{m.sub}</div>
        </div>
      ))}
      <RiskDistribution stats={stats} />
    </div>
  );
}
