import { useEffect } from 'react';
import Icon from './Icon';
import './Notices.css';

const ICONS = { success: 'check', info: 'info', warning: 'alert', error: 'alert' };
const AUTO_DISMISS_MS = 9000;

function Notice({ notice, onDismiss }) {
  useEffect(() => {
    if (notice.sticky || (notice.kind !== 'success' && notice.kind !== 'info')) return undefined;
    const t = setTimeout(() => onDismiss(notice.id), AUTO_DISMISS_MS);
    return () => clearTimeout(t);
  }, [notice, onDismiss]);

  return (
    <div className={`notice notice--${notice.kind}`} role={notice.kind === 'error' ? 'alert' : 'status'}>
      <Icon name={ICONS[notice.kind]} size={16} className="notice__icon" />
      <div className="notice__content">
        <div className="notice__title">{notice.title}</div>
        {notice.body && <div className="notice__body">{notice.body}</div>}
        {notice.details && notice.details.length > 0 && (
          <ul className="notice__details">
            {notice.details.map((d, i) => <li key={i}>{d}</li>)}
          </ul>
        )}
      </div>
      <button className="notice__dismiss" onClick={() => onDismiss(notice.id)} aria-label="Dismiss notification">
        <Icon name="close" size={14} />
      </button>
    </div>
  );
}

export default function Notices({ notices, onDismiss }) {
  if (notices.length === 0) return null;
  return (
    <div className="notices" aria-live="polite">
      {notices.map((n) => <Notice key={n.id} notice={n} onDismiss={onDismiss} />)}
    </div>
  );
}
