# AI Log Analysis for Forensics — MVP

**Cross-platform Log Collection + Normalization + Isolation Forest Anomaly Detection + Explainable Risk Scoring + Investigator Dashboard**

This is the first working milestone of the larger AI Log Analysis for Forensics project
(`Collect → Normalize → Detect → Correlate → Reconstruct Timeline → Explain → Report`).
This milestone implements the first three stages end-to-end, plus a basic
chronological timeline, with a working local API and dashboard:

```
Windows Event Logs / macOS Unified Logs
        ↓
Log Collector            (real host logs, or synthetic demo data)
        ↓
Normalizer                (common event schema, raw evidence preserved)
        ↓
Feature Extraction         (rarity/frequency + explainable rule flags)
        ↓
Isolation Forest           (unsupervised anomaly detection)
        ↓
Risk / Suspicion Score     (0-100, explainable, ML + rules combined)
        ↓
REST API (FastAPI + SQLite)
        ↓
React Dashboard
```

Everything runs **locally**. No cloud services are used or required.

---

## Repository layout

```
ai-log-forensics/
  backend/
    app/
      main.py               FastAPI app + all REST routes
      pipeline.py            orchestrates ingest -> normalize -> analyze -> store
      schemas.py              shared NormalizedEvent schema (single source of truth)
      database.py             SQLAlchemy engine/session (SQLite)
      models.py                 ORM model for the events table
      collector/
        windows_collector.py  real Windows Event Log collector (pywin32/win32evtlog)
        macos_collector.py    real macOS Unified Log collector (/usr/bin/log)
        linux_collector.py    real Linux collector (journalctl, falls back to /var/log)
      normalizer/
        normalize.py            raw record -> NormalizedEvent
      features/
        feature_extraction.py   NormalizedEvent batch -> numeric feature matrix
      ml/
        anomaly_detector.py      Isolation Forest wrapper
      scoring/
        risk_scoring.py          ML score + rules -> risk_score/risk_level/reasons
      demo/
        synthetic_data.py        DEMO/SYNTHETIC dataset generator
    tests/                      pytest suite covering every stage
    run_demo.py                CLI: load demo data + run analysis, no API needed
    requirements.txt
    requirements-dev.txt        (only needed to run tests)
  frontend/
    src/
      App.jsx                  page layout + data flow
      api.js                    fetch wrapper for the backend
      components/               Header, OverviewCards, SuspiciousTable,
                                 EventDetailPanel, Timeline, RiskBadge
    package.json
    vite.config.js              dev-server proxy: /api/* -> http://127.0.0.1:8000
```

---

## 1. Installation

### Backend (Windows or any OS)

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

`pywin32` (needed for real Windows Event Log collection) is installed automatically
on Windows via the `requirements.txt` marker. On macOS/Linux it's skipped — the
rest of the app still works fully via the demo dataset.

### Frontend (any OS with Node.js 18+)

```powershell
cd frontend
npm install
```

---

## 2. How to run the backend

The quickest way is the launcher in the project folder. It asks for the
elevated rights live collection needs (Administrator on Windows, `sudo` on
Linux/macOS) and starts the API on port 8000:

```powershell
# Windows (shows a UAC prompt)
powershell -ExecutionPolicy Bypass -File .\start-backend.ps1
```

```bash
# Linux / macOS
bash start-backend.sh
```

Or start it manually, without elevation (the Windows Security log and Linux
auth logs are then skipped with a warning):

```powershell
cd backend
venv\Scripts\activate
python -m uvicorn app.main:app --reload --port 8000
```

- API root: `http://127.0.0.1:8000`
- Interactive API docs (Swagger UI): `http://127.0.0.1:8000/docs`
- SQLite database file is created automatically at `backend/forensics.db`

## 3. How to run the frontend

In a second terminal:

```powershell
cd frontend
npm run dev
```

Open `http://127.0.0.1:5173`. The dev server proxies `/api/*` to the backend
on port 8000 automatically (see `vite.config.js`) — no CORS setup needed.

---

## 4. How to collect real host logs

The application automatically selects the collector for the computer it is
running on. The dashboard button is **Collect live logs**; the sliders button
next to it sets how many events to read and, on macOS/Linux, the time window.
The top bar shows which OS the backend is running on, and that OS's source tab
is marked **This machine**.

Anything that couldn't be read (for example the Windows Security log without
Administrator rights) is returned in the response's `warnings` list and shown
in the dashboard, instead of being silently skipped.

### Windows

Windows collection uses `pywin32` and typically requires running the terminal
**as Administrator** to read the Security log.

- From the API directly:
  ```powershell
  curl -X POST "http://127.0.0.1:8000/collect"
  curl -X POST "http://127.0.0.1:8000/collect?channels=Security,System,Application&max_events_per_channel=200&include_sysmon=true"
  ```

This reads from the **Security**, **System**, and **Application** channels by
default. Sysmon's channel (`Microsoft-Windows-Sysmon/Operational`) is included
only if `include_sysmon=true` **and** Sysmon is actually installed — it is never
required.

If you run this on a non-Windows machine, or without pywin32, you'll get a
clear `400` error explaining why, instead of a crash or fabricated data.

### macOS

macOS collection uses Apple's built-in Unified Logging tool and needs no extra
Python package. For a small live collection:

```powershell
curl -X POST "http://127.0.0.1:8000/collect?last=15m&max_events_per_channel=200"
```

### Linux

Linux collection reads the systemd journal with `journalctl -o json` (the
newest `max_events_per_channel` events within the `last` window). On systems
without journalctl it falls back to `/var/log/auth.log`, `/var/log/secure`,
`/var/log/syslog` and `/var/log/messages`. No extra Python package is needed.

```bash
curl -X POST "http://127.0.0.1:8000/collect?last=1h&max_events_per_channel=500"
```

To include system and authentication logs (SSH logins, sudo, useradd), run the
backend with `sudo`, or add your user to the `adm` / `systemd-journal` group.
Without that, journalctl only returns your own user's entries and the response
includes a warning saying so.

Linux has no numeric event IDs, so `event_id` stays empty; `event_type` is a
label derived from the literal log message, such as `SSH Failed Login`,
`Sudo Denied (Not in sudoers)` or `User Account Created`.

Real Windows, macOS and Linux events are tagged `data_origin: "OBSERVED"` and
receive a canonical `operating_system` value.

### Showing high-risk events on real logs (safe test incident)

A normal machine rarely has high-risk activity in its logs. To demonstrate
detection on **real** evidence instead of the synthetic demo, click
**Stage safe incident** in the dashboard (or `POST /collect/safe-incident`).
The backend must be elevated (use the launcher above).

It runs a short, readable script from `backend/app/safe_incident/` for the
current OS that performs genuine but harmless actions, then undoes them:

| Step | Windows | Linux | macOS |
|---|---|---|---|
| Temporary account `forensics_demo` created | 4720 | `useradd` | `sysadminctl` |
| Account added to the admin group | 4732 (Administrators) | `sudo` / `wheel` | `admin` |
| Failed logons / authentications | 4625 ×5 | sudo wrong password, sudo denied, SSH invalid users (if sshd runs) | `dscl -authonly` ×5 |
| Download-and-execute command | — | written as log **text only** | written as log **text only** |
| Cleanup | group removal + account deleted | `userdel` | group removal + account deleted |

The account's password is random and never shown, nothing is downloaded or
executed, and no audit or security policy is changed. The resulting events are
collected as a new `incident-…` batch and analyzed straight away. On Linux
(verified on Ubuntu 24.04) this produces CRITICAL `Sudo Denied` events and HIGH
account-creation / admin-group events. macOS does not log these account
actions with stable text, so its script also records each action in the
Unified Log with `logger` (tag `forensics-demo`) for the collector to label.

The audit-log-cleared rule (Windows 1102) is deliberately **not** triggered:
clearing a real log is destructive, so that one stays in the synthetic demo.

---

## 5. How to run ML analysis

Collection/demo-loading and analysis are **separate steps**, matching the spec:
you can collect now and analyze later, or re-run analysis after loading more
data.

- From the dashboard: select a source tab, then click **Run analysis**.
  A selected source is analyzed as its own baseline; it is never fitted
  alongside a different OS or the demo data. The **All Sources** tab
  keeps the original behavior of analyzing only un-analyzed events by default.
- From the API:
  ```powershell
  curl -X POST "http://127.0.0.1:8000/analysis/run"                 # analyze only un-analyzed events
  curl -X POST "http://127.0.0.1:8000/analysis/run?batch_id=demo-..." # analyze one specific batch
  curl -X POST "http://127.0.0.1:8000/analysis/run?rerun_all=true"    # re-analyze everything
  curl -X POST "http://127.0.0.1:8000/analysis/run?os=macos&data_origin=OBSERVED" # re-analyze observed macOS only
  ```

## 6. Filter events by source

`/events`, `/events/suspicious`, `/timeline`, and `/stats` all accept the
same source parameters, so counts, tables, and timeline markers cannot drift
between datasets:

```powershell
# short OS form; mac, macos, and Darwin are accepted aliases (linux works too)
curl "http://127.0.0.1:8000/events/suspicious?os=macos&data_origin=OBSERVED"

# long-form OS alias, useful for integrations
curl "http://127.0.0.1:8000/stats?operating_system=Windows&data_origin=OBSERVED"

# demo data remains clearly separate from real evidence
curl "http://127.0.0.1:8000/timeline?data_origin=SYNTHETIC_DEMO"
```

Responses include their resolved `filters` and every event includes both
`data_origin` and `operating_system`. The dashboard's source tabs are
**All Sources**, **Windows**, **macOS**, **Linux** and **Demo**, each showing
how many events it holds. The selected scope is applied to the summary numbers,
suspicious events, the incident trace, and analysis.

---

## 7. How to use demo mode

The system must be demonstrable even on a laptop with nothing interesting in
its real logs. The demo dataset generates ~125-160 realistic-looking but
**clearly synthetic** Windows events: normal background activity (logons, app
launches, service events) plus one compact injected "attack storyline" late
in the day (failed-logon burst → account lockout → suspicious encoded
PowerShell → an unusual process → an outbound connection to an uncommon port
→ a registry Run-key modification → an audit-log-clear attempt).

Every demo event is tagged `data_origin: "SYNTHETIC_DEMO"` end-to-end — in the
database, the API responses, and the dashboard (shown as a **DEMO / SYNTHETIC**
tag next to every such event) — so it can never be mistaken for real evidence.

- From the dashboard: click **"Load Demo Dataset"**, then **"Run Analysis"**.
- From the API: `curl -X POST "http://127.0.0.1:8000/demo/load?num_normal_events=140"`
- Without the API running at all:
  ```powershell
  cd backend
  python run_demo.py --events 140
  ```

Re-running with the same seed produces the same dataset (reproducibility).

---

## 8. Architecture notes

- **Storage**: SQLite via SQLAlchemy (`backend/forensics.db`). No pre-existing
  project/database was found to integrate with, so SQLite was used directly
  per the spec's fallback instruction.
- **Evidence preservation**: the original raw record (JSON) is written once at
  ingestion into `raw_data` and is never modified by any later pipeline stage.
  Only ML/risk columns (`anomaly_score`, `risk_score`, `risk_level`,
  `analysis_reasons`, `features_json`) are updated when analysis (re-)runs.
- **Two distinct scores, always kept separate**:
  - `anomaly_score` (0-1): purely statistical output of Isolation Forest —
    "this is unusual relative to the observed batch," nothing more.
  - `risk_score` (0-100): investigator-facing score combining the anomaly
    score with a small set of named, auditable rules (failed logons,
    suspicious PowerShell flags, unusual outbound ports, log-clear attempts,
    registry persistence, etc). Every point added is tied to a human-readable
    reason string returned in `analysis_reasons` — nothing is an unexplained
    black-box number.
- **Data-origin and OS tagging**: every event carries `data_origin` =
  `OBSERVED` (real host log) or `SYNTHETIC_DEMO` (demo generator), plus a
  canonical `operating_system` when the source establishes one. Both are
  preserved through
  storage and surfaced in the UI, per the "no fabricated evidence" principle.
- **Legacy database compatibility**: on startup, SQLite receives a small
  additive migration for `operating_system`. Existing rows are backfilled only
  when their recorded source establishes an OS; `raw_data` and existing ML/risk
  values are never overwritten.
- **Timeline**: `/timeline` and the dashboard's timeline strip are explicitly
  a **chronological** view only — events sorted by time with risk-level
  markers. This is *not* incident reconstruction/correlation; that's a later
  phase (see below).

---

## 9. Current limitations

- Isolation Forest is trained fresh on each analyzed batch (the batch itself
  is the "observed baseline"); there is no persisted, cross-session model or
  long-term behavioral baseline yet.
- The rule set behind risk scoring is intentionally small and transparent,
  not an exhaustive detection-engineering rule base.
- Real-field extraction from Windows event messages (process name, command
  line, source/destination IP, etc.) is done via targeted regex over the
  rendered message text; it captures the common cases but is not a full
  EVTX/XML field parser.
- No user authentication — this is a local, single-investigator MVP.
- Most detection rules are Windows-specific (event IDs, PowerShell). Linux has
  its own rules (SSH brute force, sudo denial, download-and-execute shells, new
  accounts); macOS events are scored by the ML anomaly signal and generic rules.
- The Linux collector is covered by automated tests with recorded journald and
  syslog samples; it has not yet been run against a live Linux host.
- The timeline is basic and chronological only, not correlated/reconstructed.
- No packaging/installer yet — run via Python/Node directly as described above.

## 10. Future phases (explicitly out of scope for this milestone)

Advanced deep learning (LSTM/Transformers), full SIEM functionality, MITRE
ATT&CK automation, automated incident response or remediation, full attack
graphs, cloud deployment, multi-machine distributed collection, full packet
inspection, a complex LLM agent layer, and complete forensic report
generation are all deliberately deferred to later phases, per the original
project scope.

---

## 11. Running the tests

```powershell
cd backend
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/ -v
```

The test suite covers: normalization (field mapping, evidence preservation, no
fabrication), feature extraction, ML scoring (bounds, reproducibility, and a
sanity check that injected attack events score higher than normal
background activity), risk classification and explainability, the full
ingest→analyze pipeline (including that raw evidence is never mutated), and
every REST endpoint. This includes the OS/source-scope regression test: an
observed macOS analysis cannot score or return synthetic Windows demo rows.
