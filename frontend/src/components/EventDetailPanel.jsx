import { useEffect, useState } from 'react';
import RiskBadge, { DataOriginTag } from './RiskBadge';
import Icon from './Icon';
import { formatFullDateTime } from '../format';
import './EventDetailPanel.css';

function Field({ label, value, mono, wide }) {
  if (value === undefined || value === null || value === '') return null;
  return (
    <div className={`detail-field ${wide ? 'detail-field--wide' : ''}`}>
      <dt className="detail-field__label">{label}</dt>
      <dd className={`detail-field__value ${mono ? 'mono' : ''}`}>{value}</dd>
    </div>
  );
}

function ScoreGauge({ score, level }) {
  const value = score == null ? 0 : Math.round(score);
  const circumference = 2 * Math.PI * 26;
  return (
    <div className={`gauge gauge--${(level || 'none').toLowerCase()}`} aria-label={`Risk score ${score == null ? 'not available' : value + ' out of 100'}`}>
      <svg viewBox="0 0 64 64" width="64" height="64" aria-hidden="true">
        <circle cx="32" cy="32" r="26" className="gauge__track" />
        <circle
          cx="32" cy="32" r="26"
          className="gauge__fill"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - value / 100)}
        />
      </svg>
      <span className="gauge__value">{score == null ? '—' : value}</span>
    </div>
  );
}

function Collapsible({ title, children, onCopy }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(onCopy());
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable - ignore */
    }
  }

  return (
    <section className="detail-section">
      <div className="collapsible-head">
        <button className="collapsible-toggle" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          <Icon name={open ? 'chevronDown' : 'chevron'} size={14} />
          {title}
        </button>
        {open && onCopy && (
          <button className="btn btn--quiet collapsible-copy" onClick={copy}>
            {copied ? <><Icon name="check" size={13} /> Copied</> : 'Copy'}
          </button>
        )}
      </div>
      {open && children}
    </section>
  );
}

// Note: the parent renders this with `key={event.id}` when an event is
// selected, so a fresh component instance (and fresh collapse state)
// is mounted whenever the selection changes - no effect needed to
// reset state in response to a prop change.
export default function EventDetailPanel({ event, loading, onClose }) {
  const open = Boolean(event) || loading;

  useEffect(() => {
    if (!open) return undefined;
    function onKey(e) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) {
    return (
      <aside className="panel detail-panel detail-panel--empty" aria-label="Event detail">
        <div className="detail-empty">
          <div className="detail-empty__icon"><Icon name="file" size={22} /></div>
          <h2>No event selected</h2>
          <p>Pick an event from the table or timeline to see why it was flagged, its extracted fields, and the original raw evidence.</p>
        </div>
      </aside>
    );
  }

  if (loading && !event) {
    return (
      <>
        <div className="detail-backdrop" onClick={onClose} />
        <aside className="panel detail-panel is-open" aria-label="Event detail" aria-busy="true">
          <div className="detail-panel__body">
            <div className="skeleton" style={{ height: 22, width: '60%' }} />
            <div className="skeleton" style={{ height: 64, marginTop: 16 }} />
            <div className="skeleton" style={{ height: 120, marginTop: 16 }} />
          </div>
        </aside>
      </>
    );
  }

  let prettyRaw = event.raw_data;
  try {
    prettyRaw = JSON.stringify(JSON.parse(event.raw_data), null, 2);
  } catch {
    /* leave as-is if not JSON */
  }
  const reasons = event.analysis_reasons || [];
  const network = (ip, port) => (ip ? `${ip}${port ? ':' + port : ''}` : null);

  return (
    <>
      <div className="detail-backdrop" onClick={onClose} />
      <aside className="panel detail-panel is-open" aria-labelledby="detail-title">
        <div className="detail-panel__head">
          <div className="detail-panel__titles">
            <span className="detail-panel__case mono">EVT-{String(event.id).padStart(5, '0')}</span>
            <h2 className="detail-panel__title" id="detail-title">{event.event_type}</h2>
            <div className="detail-panel__badges">
              <RiskBadge level={event.risk_level} />
              <DataOriginTag origin={event.data_origin} />
              {event.operating_system && <span className="os-chip">{event.operating_system}</span>}
            </div>
          </div>
          <button className="btn btn--quiet btn--icon" onClick={onClose} aria-label="Close event detail">
            <Icon name="close" />
          </button>
        </div>

        <div className="detail-panel__body">
          <section className="detail-scores">
            <ScoreGauge score={event.risk_score} level={event.risk_level} />
            <div className="detail-scores__text">
              <div className="detail-scores__row">
                <span>Forensic risk score</span>
                <strong className="mono">{event.risk_score != null ? Math.round(event.risk_score) : '—'}<small>/100</small></strong>
              </div>
              <div className="detail-scores__row">
                <span>ML anomaly score</span>
                <strong className="mono">{event.anomaly_score != null ? event.anomaly_score.toFixed(2) : '—'}<small>/1.00</small></strong>
              </div>
              <p className="detail-scores__note">Risk = anomaly signal (up to 40 pts) + named, auditable rules.</p>
            </div>
          </section>

          <section className="detail-section">
            <h3 className="detail-section__title">Why flagged</h3>
            {reasons.length > 0 ? (
              <ul className="reason-list">
                {reasons.map((r, i) => (
                  <li key={i} className={r.startsWith('No significant') ? 'is-benign' : ''}>
                    <Icon name={r.startsWith('No significant') ? 'check' : r.startsWith('High ML') ? 'sparkle' : 'alert'} size={14} />
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="reason-list__empty">Not analyzed yet — run analysis to generate a risk assessment.</p>
            )}
          </section>

          <section className="detail-section">
            <h3 className="detail-section__title">Event facts</h3>
            <dl className="detail-grid">
              <Field label="Timestamp" value={formatFullDateTime(event.timestamp)} mono wide />
              <Field label="Event ID" value={event.event_id} mono />
              <Field label="Source" value={event.log_source} />
              <Field label="Provider" value={event.provider} wide />
              <Field label="Host" value={event.computer} />
              <Field label="User" value={event.user} />
              <Field label="Level" value={event.level} />
              <Field label="Process" value={event.process_name} mono wide />
              <Field label="Process ID" value={event.process_id} mono />
              <Field label="Parent process" value={event.parent_process} mono wide />
              <Field label="Command line" value={event.command_line} mono wide />
              <Field label="Source" value={network(event.source_ip, event.source_port)} mono />
              <Field label="Destination" value={network(event.destination_ip, event.destination_port)} mono />
            </dl>
          </section>

          <section className="detail-section">
            <h3 className="detail-section__title">Message</h3>
            <p className="detail-message">{event.message || '—'}</p>
          </section>

          {event.features && Object.keys(event.features).length > 0 && (
            <Collapsible title="Extracted ML features" onCopy={() => JSON.stringify(event.features, null, 2)}>
              <div className="feature-grid">
                {Object.entries(event.features).map(([k, v]) => (
                  <div key={k} className="feature-grid__row">
                    <span>{k.replaceAll('_', ' ')}</span>
                    <span className="mono">{String(v)}</span>
                  </div>
                ))}
              </div>
            </Collapsible>
          )}

          <Collapsible title="Raw event (original evidence)" onCopy={() => prettyRaw}>
            <pre className="raw-block mono">{prettyRaw}</pre>
          </Collapsible>
        </div>
      </aside>
    </>
  );
}
