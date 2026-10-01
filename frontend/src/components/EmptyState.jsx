import Icon from './Icon';
import './EmptyState.css';

const OS_ICON = { Windows: 'windows', macOS: 'apple', Linux: 'linux' };

// Scope-aware empty state: explains *why* a scope is empty and offers
// the action that can actually fill it on this host.
export default function EmptyState({ source, host, busy, onCollect, onLoadDemo }) {
  const canCollect = Boolean(host && host.live_collection_supported);
  const hostOs = host?.host_os;

  let icon = 'layers';
  let title = 'No evidence loaded yet';
  let body = 'Collect real logs from this machine, or load the clearly labeled synthetic demo scenario to explore the workflow.';
  let showCollect = canCollect;
  let showDemo = true;

  if (source.hostOs) {
    icon = OS_ICON[source.hostOs];
    if (source.hostOs === hostOs) {
      title = `No ${source.hostOs} events collected yet`;
      body = `Collect live logs from this ${source.hostOs} machine, then run analysis to score them.`;
      showDemo = false;
    } else {
      title = `${source.hostOs} logs are collected on ${source.hostOs}`;
      body = `This backend is running on ${hostOs || 'another OS'}. To gather ${source.hostOs} evidence, run the backend on a ${source.hostOs} machine and click Collect live logs there.`;
      showCollect = false;
      showDemo = false;
    }
  } else if (source.id === 'synthetic-demo') {
    icon = 'beaker';
    title = 'Demo dataset not loaded';
    body = 'The demo generates normal Windows activity plus one injected attack storyline. Every event carries a hatched “Demo data” tag so it can’t be mistaken for real evidence.';
    showCollect = false;
  }

  return (
    <section className="empty-state panel">
      <div className="empty-state__icon"><Icon name={icon} size={26} /></div>
      <h2 className="empty-state__title">{title}</h2>
      <p className="empty-state__body">{body}</p>
      {(showCollect || showDemo) && (
        <div className="empty-state__actions">
          {showCollect && (
            <button className="btn btn--primary" onClick={onCollect} disabled={busy}>
              <Icon name="collect" /> Collect {hostOs} logs
            </button>
          )}
          {showDemo && (
            <button className={`btn ${showCollect ? '' : 'btn--primary'}`} onClick={onLoadDemo} disabled={busy || host === null}>
              <Icon name="beaker" /> Load demo dataset
            </button>
          )}
        </div>
      )}
    </section>
  );
}
