import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';
import Header from './components/Header';
import OverviewCards from './components/OverviewCards';
import SuspiciousTable from './components/SuspiciousTable';
import EventDetailPanel from './components/EventDetailPanel';
import Timeline from './components/Timeline';
import DataSourceSelector from './components/DataSourceSelector';
import WorkflowSteps from './components/WorkflowSteps';
import Notices from './components/Notices';
import EmptyState from './components/EmptyState';
import { DATA_SOURCE_OPTIONS, getDataSourceOption, sourceForHost } from './dataSources';
import { pluralize } from './format';
import './App.css';

const TIMELINE_LIMIT = 600;
const HEALTH_RETRY_MS = 5000;

let noticeSeq = 0;

export default function App() {
  const [host, setHost] = useState(undefined); // undefined = checking, null = offline
  const [stats, setStats] = useState(null);
  const [sourceCounts, setSourceCounts] = useState(null);
  const [suspicious, setSuspicious] = useState({ events: [], total: null });
  const [timelineEvents, setTimelineEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [minRiskLevel, setMinRiskLevel] = useState('MEDIUM');
  const [dataSource, setDataSource] = useState('all');
  const [busy, setBusy] = useState(false);
  const [lastAction, setLastAction] = useState(null);
  const [notices, setNotices] = useState([]);
  const [collectOptions, setCollectOptions] = useState({ max_events_per_channel: 200, last: '1h', include_sysmon: false });
  const selectionRequest = useRef(0);

  const selectedSource = getDataSourceOption(dataSource);
  const sourceParams = selectedSource.params;

  const notify = useCallback((notice) => {
    const id = ++noticeSeq;
    setNotices((list) => [{ id, ...notice }, ...list].slice(0, 4));
  }, []);
  const dismissNotice = useCallback((id) => setNotices((list) => list.filter((n) => n.id !== id)), []);

  // --- backend health / host detection ------------------------------
  // Checks immediately on load, then retries every few seconds while the
  // backend is offline (including when a data request discovers it's down).
  const [healthAttempt, setHealthAttempt] = useState(0);
  useEffect(() => {
    if (host) return undefined;
    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const h = await api.health();
        if (!cancelled) setHost(h);
      } catch {
        if (!cancelled) {
          setHost(null);
          setHealthAttempt((n) => n + 1);
        }
      }
    }, host === undefined ? 0 : HEALTH_RETRY_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [host, healthAttempt]);

  // --- data loading ---------------------------------------------------
  const refreshRequest = useRef(0);
  const refreshAll = useCallback(async (riskLevelOverride) => {
    const level = riskLevelOverride ?? minRiskLevel;
    // Rapid filter/source changes can overlap; only the newest refresh may
    // write state, so a slow older response never overwrites a newer one.
    const requestId = ++refreshRequest.current;
    try {
      const [statsRes, suspiciousRes, timelineRes, ...countRes] = await Promise.all([
        api.stats(sourceParams),
        api.suspiciousEvents({ min_risk_level: level, ...sourceParams }),
        api.timeline({ limit: TIMELINE_LIMIT, ...sourceParams }),
        ...DATA_SOURCE_OPTIONS.map((o) => api.stats(o.params)),
      ]);
      if (requestId !== refreshRequest.current) return;
      setStats(statsRes);
      setSuspicious({ events: suspiciousRes.events, total: suspiciousRes.total });
      setTimelineEvents(timelineRes.events);
      setSourceCounts(Object.fromEntries(DATA_SOURCE_OPTIONS.map((o, i) => [o.id, countRes[i].total_events])));
    } catch (err) {
      setHost((h) => (err.message.startsWith('Cannot reach') ? null : h));
    } finally {
      setLoading(false);
    }
  }, [minRiskLevel, sourceParams]);

  useEffect(() => {
    if (host) queueMicrotask(() => { void refreshAll(); });
  }, [refreshAll, host]);

  // --- selection ------------------------------------------------------
  const handleEventSelect = useCallback((eventId) => {
    const requestId = ++selectionRequest.current;
    setSelectedId(eventId);
    setSelectedEvent(null);
    if (eventId == null) return;
    api.event(eventId).then((ev) => {
      if (selectionRequest.current === requestId) setSelectedEvent(ev);
    }).catch((err) => notify({ kind: 'error', title: 'Could not open that event', body: err.message }));
  }, [notify]);

  const closeDetail = useCallback(() => handleEventSelect(null), [handleEventSelect]);

  function switchSource(nextSource) {
    handleEventSelect(null);
    setDataSource(nextSource);
  }

  // --- actions --------------------------------------------------------
  async function runAction(action, fn) {
    setBusy(true);
    setLastAction(action);
    try {
      await fn();
    } catch (err) {
      notify({ kind: 'error', title: ACTION_ERROR_TITLES[action], body: err.message });
    } finally {
      setBusy(false);
      setLastAction(null);
    }
  }

  function handleLoadDemo() {
    return runAction('demo', async () => {
      const result = await api.loadDemo(140);
      notify({
        kind: 'success',
        title: `Loaded ${pluralize(result.events_ingested, 'demo event')}`,
        body: 'Showing the demo scope. Run analysis to score the injected attack storyline.',
      });
      if (dataSource !== 'synthetic-demo' && dataSource !== 'all') switchSource('synthetic-demo');
      else await refreshAll();
    });
  }

  function handleCollect() {
    return runAction('collect', async () => {
      const params = { max_events_per_channel: collectOptions.max_events_per_channel };
      if (host?.host_os === 'Windows' && collectOptions.include_sysmon) params.include_sysmon = true;
      if (host?.host_os === 'macOS' || host?.host_os === 'Linux') params.last = collectOptions.last;
      const result = await api.collect(params);
      const warnings = result.warnings || [];
      notify({
        kind: warnings.length ? 'warning' : 'success',
        title: `Collected ${pluralize(result.events_ingested, `${result.operating_system} event`)}`,
        body: `Read with ${result.collector}. Run analysis to score them.`,
        details: warnings,
      });
      const hostSource = sourceForHost(result.operating_system);
      if (hostSource && dataSource !== hostSource.id && dataSource !== 'all') switchSource(hostSource.id);
      else await refreshAll();
    });
  }

  function handleSafeIncident() {
    const ok = window.confirm(
      `Stage a safe test incident on this ${host?.host_os} machine?\n\n`
      + 'This briefly creates a local account "forensics_demo" (random password, never shown), '
      + 'adds it to the admin group, makes a few failed logons and writes a suspicious command as log text only. '
      + 'Everything it creates is removed straight away. Nothing is downloaded or run.\n\n'
      + 'The real events are then collected and analyzed.',
    );
    if (!ok) return undefined;
    return runAction('incident', async () => {
      const result = await api.safeIncident();
      const analysis = await api.runAnalysis({ batch_id: result.batch_id });
      const b = analysis.risk_level_breakdown || {};
      notify({
        kind: (result.warnings || []).length ? 'warning' : 'success',
        sticky: true,
        title: `Safe incident staged: ${b.CRITICAL || 0} critical and ${b.HIGH || 0} high-risk events`,
        body: `Collected ${pluralize(result.events_ingested, `real ${result.operating_system} event`)} and analyzed them. What was done on this machine:`,
        details: [...(result.incident_steps || []), ...(result.warnings || [])],
      });
      const hostSource = sourceForHost(result.operating_system);
      if (hostSource && dataSource !== hostSource.id && dataSource !== 'all') switchSource(hostSource.id);
      else await refreshAll();
    });
  }

  function handleRunAnalysis() {
    return runAction('analysis', async () => {
      const result = await api.runAnalysis(sourceParams);
      if (result.analyzed_events === 0) {
        notify({
          kind: 'info',
          title: 'Nothing new to analyze',
          body: dataSource === 'all'
            ? 'Every event is already scored. Pick a single source to re-run its baseline.'
            : `No ${selectedSource.label} events are available in this scope.`,
        });
      } else {
        const b = result.risk_level_breakdown || {};
        notify({
          kind: 'success',
          title: `Analyzed ${pluralize(result.analyzed_events, 'event')}${dataSource === 'all' ? '' : ` in the ${selectedSource.label} baseline`}`,
          body: `${b.CRITICAL || 0} critical, ${b.HIGH || 0} high, ${b.MEDIUM || 0} medium and ${b.LOW || 0} low.`,
        });
      }
      await refreshAll();
    });
  }

  const unanalyzedCount = stats ? stats.unanalyzed_events : 0;
  const scopeEmpty = stats && stats.total_events === 0;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">Skip to events</a>
      <Header
        host={host}
        onLoadDemo={handleLoadDemo}
        onCollect={handleCollect}
        onSafeIncident={handleSafeIncident}
        onRunAnalysis={handleRunAnalysis}
        busy={busy}
        lastAction={lastAction}
        unanalyzedCount={unanalyzedCount}
        sourceLabel={selectedSource.label}
        collectOptions={collectOptions}
        onCollectOptionsChange={setCollectOptions}
      />

      <div className="app-content">
        {host === null && (
          <div className="offline-banner" role="alert">
            <strong>The backend isn’t reachable.</strong> Start it from the project folder with{' '}
            <code>start-backend.ps1</code> (Windows) or <code>./start-backend.sh</code> (Linux/macOS). This page reconnects automatically.
          </div>
        )}

        <Notices notices={notices} onDismiss={dismissNotice} />

        <div className="scope-row">
          <DataSourceSelector value={dataSource} onChange={switchSource} counts={sourceCounts} hostOs={host?.host_os} />
          <WorkflowSteps stats={stats} />
        </div>

        {host === null && !stats ? null : scopeEmpty ? (
          <EmptyState source={selectedSource} host={host} busy={busy} onCollect={handleCollect} onLoadDemo={handleLoadDemo} />
        ) : (
          <>
            <section className="panel trace" aria-label="Incident trace">
              <OverviewCards stats={stats} />
              <Timeline events={timelineEvents} selectedId={selectedId} onSelect={handleEventSelect} />
            </section>

            <main className="app-main" id="main">
              <SuspiciousTable
                events={suspicious.events}
                total={suspicious.total}
                selectedId={selectedId}
                onSelect={handleEventSelect}
                minRiskLevel={minRiskLevel}
                onChangeMinRiskLevel={setMinRiskLevel}
                loading={loading}
                hasUnanalyzed={unanalyzedCount > 0}
              />
              <EventDetailPanel
                key={selectedEvent?.id ?? (selectedId != null ? `loading-${selectedId}` : 'none')}
                event={selectedEvent}
                loading={selectedId != null && !selectedEvent}
                onClose={closeDetail}
              />
            </main>
          </>
        )}
      </div>

      <footer className="app-footer">
        Runs entirely on this machine. Anomaly detection uses an Isolation Forest; every risk point is tied to a named, auditable reason.
      </footer>
    </div>
  );
}

const ACTION_ERROR_TITLES = {
  collect: 'Collection failed',
  incident: 'Could not stage the safe test incident',
  demo: 'Could not load the demo dataset',
  analysis: 'Analysis failed',
};
