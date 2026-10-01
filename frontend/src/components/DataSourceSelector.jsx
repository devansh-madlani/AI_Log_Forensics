import Icon from './Icon';
import { DATA_SOURCE_OPTIONS, getDataSourceOption } from '../dataSources';
import { formatNumber } from '../format';
import './DataSourceSelector.css';

const SOURCE_ICON = {
  all: 'layers',
  'windows-live': 'windows',
  'macos-live': 'apple',
  'linux-live': 'linux',
  'synthetic-demo': 'beaker',
};

// Segmented source switcher. Each tab shows how many events that scope
// holds, and the live source matching the backend host is marked
// "this machine" so it's obvious where Collect Live Logs will land.
export default function DataSourceSelector({ value, onChange, counts, hostOs }) {
  const selected = getDataSourceOption(value);

  function onKeyDown(e) {
    const idx = DATA_SOURCE_OPTIONS.findIndex((o) => o.id === value);
    let next = null;
    if (e.key === 'ArrowRight') next = DATA_SOURCE_OPTIONS[(idx + 1) % DATA_SOURCE_OPTIONS.length];
    if (e.key === 'ArrowLeft') next = DATA_SOURCE_OPTIONS[(idx - 1 + DATA_SOURCE_OPTIONS.length) % DATA_SOURCE_OPTIONS.length];
    if (next) {
      e.preventDefault();
      onChange(next.id);
      requestAnimationFrame(() => document.getElementById(`source-tab-${next.id}`)?.focus());
    }
  }

  return (
    <section className="source-bar" aria-label="Evidence source">
      <div className="source-bar__tabs" role="tablist" aria-label="Choose evidence source" onKeyDown={onKeyDown}>
        {DATA_SOURCE_OPTIONS.map((option) => {
          const active = option.id === value;
          const count = counts ? counts[option.id] : undefined;
          const isHost = option.hostOs && option.hostOs === hostOs;
          return (
            <button
              key={option.id}
              id={`source-tab-${option.id}`}
              role="tab"
              aria-selected={active}
              tabIndex={active ? 0 : -1}
              className={`source-tab ${active ? 'is-active' : ''}`}
              onClick={() => onChange(option.id)}
            >
              <Icon name={SOURCE_ICON[option.id]} size={15} />
              <span className="source-tab__label">{option.label}</span>
              {count !== undefined && <span className="source-tab__count">{formatNumber(count)}</span>}
              {isHost && <span className="source-tab__host" title="Collect live logs reads from this machine">This machine</span>}
            </button>
          );
        })}
      </div>
      <p className="source-bar__detail">
        <Icon name="info" size={14} />
        {selected.detail}. Stats, events, timeline and analysis all use this scope.
      </p>
    </section>
  );
}
