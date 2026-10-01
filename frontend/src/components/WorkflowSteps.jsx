import Icon from './Icon';
import './WorkflowSteps.css';

// Collect -> Analyze -> Investigate, derived from the scoped stats so the
// investigator always knows what the next step is.
export default function WorkflowSteps({ stats }) {
  const total = stats?.total_events ?? 0;
  const pending = stats?.unanalyzed_events ?? 0;
  const analyzed = stats?.analyzed_events ?? 0;

  const steps = [
    { key: 'collect', label: 'Collect', state: total > 0 ? 'done' : 'current' },
    { key: 'analyze', label: 'Analyze', state: total === 0 ? 'todo' : pending > 0 ? 'current' : 'done' },
    { key: 'investigate', label: 'Investigate', state: analyzed > 0 && pending === 0 ? 'current' : analyzed > 0 ? 'partial' : 'todo' },
  ];

  return (
    <ol className="workflow" aria-label="Investigation workflow">
      {steps.map((s, i) => (
        <li key={s.key} className={`workflow__step workflow__step--${s.state}`} aria-current={s.state === 'current' ? 'step' : undefined}>
          <span className="workflow__marker">
            {s.state === 'done' ? <Icon name="check" size={12} strokeWidth={2.4} /> : i + 1}
          </span>
          <span className="workflow__label">{s.label}</span>
          {s.key === 'analyze' && pending > 0 && <span className="workflow__hint">{pending.toLocaleString()} pending</span>}
        </li>
      ))}
    </ol>
  );
}
