import './RiskBadge.css';

const LABELS = {
  LOW: 'Low',
  MEDIUM: 'Medium',
  HIGH: 'High',
  CRITICAL: 'Critical',
};

// The signature visual element of this dashboard: a die-cut "evidence
// tag" badge, styled after a physical case-file tag, using the
// graduated LOW -> CRITICAL heat scale. Used everywhere a risk level
// appears (table rows, timeline, detail panel) so the same visual
// vocabulary carries meaning throughout the console.
export default function RiskBadge({ level, size = 'md' }) {
  if (!level) return <span className="risk-badge risk-badge--unknown">—</span>;
  const key = level.toUpperCase();
  return (
    <span className={`risk-badge risk-badge--${key.toLowerCase()} risk-badge--${size}`}>
      <span className="risk-badge__notch" aria-hidden="true" />
      {LABELS[key] || level}
    </span>
  );
}

export function DataOriginTag({ origin }) {
  const isSynthetic = origin === 'SYNTHETIC_DEMO';
  return (
    <span className={`origin-tag ${isSynthetic ? 'origin-tag--synthetic' : 'origin-tag--observed'}`}>
      {isSynthetic ? 'Demo data' : 'Observed'}
    </span>
  );
}
