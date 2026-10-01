"""
FastAPI backend for the AI Log Analysis for Forensics MVP.

Routes (spec section 8):
    GET  /events
    GET  /events/suspicious
    GET  /events/{id}
    GET  /stats
    POST /analysis/run

Plus a couple of MVP-necessary extras:
    POST /demo/load     - load the synthetic demo dataset (section 11)
    POST /collect       - trigger real Windows Event Log collection (section 3)
    POST /collect/safe-incident - stage a harmless real incident, then collect
    GET  /timeline       - chronological event timeline (section 10)
    GET  /health

CORS is left open for localhost dev (the React dashboard runs on a
different port via Vite). No cloud services are used anywhere - this is
a fully local FastAPI + SQLite app (spec section 8: "Do not require
cloud services").
"""

from __future__ import annotations

import json
import platform
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from app import models, pipeline, safe_incident
from app.database import get_db, init_db
from app.demo.synthetic_data import generate as generate_demo_events
from app.filtering import (
    apply_event_scope,
    resolve_data_origin_filter,
    resolve_os_filter,
    scope_payload,
)
from app.collector.windows_collector import collect_events as collect_windows_events, CollectorUnavailableError
from app.collector.macos_collector import collect_events as collect_macos_events, MacOSCollectorUnavailableError
from app.collector.linux_collector import collect_events as collect_linux_events, LinuxCollectorUnavailableError

# platform.system() value -> canonical OS name used throughout the API.
_LIVE_COLLECTORS = {"Windows": "Windows", "Darwin": "macOS", "Linux": "Linux"}


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AI Log Analysis for Forensics - MVP API",
    description=(
        "OS Log Collection + Normalization + Isolation Forest "
        "Anomaly Detection + Explainable Risk Scoring. Local-only, no "
        "cloud dependencies. See /docs for interactive API docs."
    ),
    version="0.1.0",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local MVP - tighten if ever exposed beyond localhost
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------- #
# Serialization helpers
# --------------------------------------------------------------------- #

def _event_to_dict(row: models.Event, include_raw: bool = False) -> dict:
    d = {
        "id": row.id,
        "event_uid": row.event_uid,
        "data_origin": row.data_origin,
        "operating_system": row.operating_system,
        "timestamp": row.timestamp,
        "event_id": row.event_id,
        "log_source": row.log_source,
        "provider": row.provider,
        "level": row.level,
        "severity": row.severity,
        "computer": row.computer,
        "user": row.user,
        "process_id": row.process_id,
        "process_name": row.process_name,
        "parent_process": row.parent_process,
        "command_line": row.command_line,
        "source_ip": row.source_ip,
        "destination_ip": row.destination_ip,
        "source_port": row.source_port,
        "destination_port": row.destination_port,
        "event_type": row.event_type,
        "message": row.message,
        "anomaly_score": row.anomaly_score,
        "risk_score": row.risk_score,
        "risk_level": row.risk_level,
        "analysis_reasons": json.loads(row.analysis_reasons) if row.analysis_reasons else [],
        "analyzed": row.analyzed,
        "batch_id": row.batch_id,
    }
    if include_raw:
        d["raw_data"] = row.raw_data
        d["features"] = json.loads(row.features_json) if row.features_json else {}
    return d


# --------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------- #

@app.get("/health")
def health():
    system = platform.system()
    return {
        "status": "ok",
        "host_os": _LIVE_COLLECTORS.get(system, system),
        "live_collection_supported": system in _LIVE_COLLECTORS,
    }


# --------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------- #

@app.post("/collect")
def collect(
    channels: Optional[str] = Query(None, description="Windows channels, ignored on macOS and Linux"),
    max_events_per_channel: int = Query(200, ge=1, le=5000),
    include_sysmon: bool = Query(False),
    last: str = Query("1h", description="macOS/Linux time window, e.g. 15m, 1h, 1d"),
    db: Session = Depends(get_db),
):
    """Collect real host logs using the collector for the current OS.

    Windows uses Event Log/pywin32. macOS uses Apple's Unified Logging
    system via /usr/bin/log. Linux uses the systemd journal (journalctl),
    falling back to /var/log text files. The normalized downstream
    pipeline is shared. Non-fatal problems (e.g. the Security log needing
    Administrator rights) are returned in ``warnings``.
    """
    channel_list = [c.strip() for c in channels.split(",")] if channels else None
    return _collect_live(db, channel_list, max_events_per_channel, include_sysmon, last, "collect")


def _collect_live(
    db: Session,
    channels: Optional[list[str]],
    max_events_per_channel: int,
    include_sysmon: bool,
    last: str,
    batch_prefix: str,
    warnings: Optional[list[str]] = None,
) -> dict:
    system = platform.system()
    warnings = warnings if warnings is not None else []
    try:
        if system == "Windows":
            raw_events = collect_windows_events(
                channels=channels,
                max_events_per_channel=max_events_per_channel,
                include_sysmon=include_sysmon,
                warnings=warnings,
            )
            source_label = "Windows Event Log"
        elif system == "Darwin":
            raw_events = collect_macos_events(last=last, max_events=max_events_per_channel)
            source_label = "macOS Unified Log"
        elif system == "Linux":
            raw_events = collect_linux_events(last=last, max_events=max_events_per_channel, warnings=warnings)
            source_label = "Linux journal / syslog"
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Live collection is not implemented for {system}. Use synthetic/import mode for now.",
            )
    except (CollectorUnavailableError, MacOSCollectorUnavailableError, LinuxCollectorUnavailableError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    result = pipeline.ingest_raw_events(db, raw_events, batch_id=pipeline.new_batch_id(batch_prefix))
    result["collector"] = source_label
    result["operating_system"] = _LIVE_COLLECTORS.get(system, system)
    result["warnings"] = warnings
    return result


@app.post("/collect/safe-incident")
def collect_safe_incident(db: Session = Depends(get_db)):
    """Stage a harmless test incident on this host, then collect live logs.

    Runs the OS-specific script in ``app/safe_incident/`` (temporary account
    created, added to the admin group, failed logons, suspicious command
    written as log text only - then everything is removed), and collects the
    resulting *real* events as an OBSERVED batch. Needs Administrator/root.
    """
    try:
        incident = safe_incident.run()
    except safe_incident.SafeIncidentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Collect a recent window big enough to include the incident plus some
    # surrounding normal activity as the baseline.
    result = _collect_live(
        db,
        channels=["Security", "System"],
        max_events_per_channel=300,
        include_sysmon=False,
        last="5m",
        batch_prefix="incident",
        warnings=list(incident["warnings"]),
    )
    result["incident_steps"] = incident["steps"]
    return result


@app.post("/demo/load")
def load_demo(
    num_normal_events: int = Query(140, ge=10, le=2000),
    db: Session = Depends(get_db),
):
    """
    Load the synthetic DEMO/SYNTHETIC dataset (spec section 11). Safe
    to call repeatedly - each call is a new batch. Data is clearly
    tagged data_origin=SYNTHETIC_DEMO end-to-end.
    """
    raw_events = generate_demo_events(num_normal_events=num_normal_events)
    result = pipeline.ingest_raw_events(db, raw_events, batch_id=pipeline.new_batch_id("demo"))
    return result


# --------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------- #

@app.post("/analysis/run")
def run_analysis(
    batch_id: Optional[str] = Query(None, description="Analyze only this batch; omit to analyze all un-analyzed events"),
    rerun_all: bool = Query(False, description="Re-analyze every event in the selected scope, or the whole database when no scope is selected"),
    os: Optional[str] = Query(None, description="OS scope: Windows, macOS, or Linux. Aliases such as Darwin are accepted."),
    operating_system: Optional[str] = Query(None, description="Long-form alias for os."),
    data_origin: Optional[str] = Query(None, description="Evidence source scope: OBSERVED or SYNTHETIC_DEMO."),
    db: Session = Depends(get_db),
):
    selected_os = resolve_os_filter(os, operating_system)
    selected_origin = resolve_data_origin_filter(data_origin)
    result = pipeline.run_analysis(
        db,
        batch_id=batch_id,
        rerun_all=rerun_all,
        operating_system=selected_os,
        data_origin=selected_origin,
    )
    return result


# --------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------- #

@app.get("/events")
def list_events(
    limit: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    risk_level: Optional[str] = Query(None),
    os: Optional[str] = Query(None, description="OS scope: Windows, macOS, or Linux."),
    operating_system: Optional[str] = Query(None, description="Long-form alias for os."),
    data_origin: Optional[str] = Query(None, description="Evidence source scope: OBSERVED or SYNTHETIC_DEMO."),
    db: Session = Depends(get_db),
):
    selected_os = resolve_os_filter(os, operating_system)
    selected_origin = resolve_data_origin_filter(data_origin)
    q = apply_event_scope(
        db.query(models.Event),
        models.Event,
        operating_system=selected_os,
        data_origin=selected_origin,
    )
    if risk_level:
        q = q.filter(models.Event.risk_level == risk_level.upper())
    total = q.count()
    rows = q.order_by(models.Event.timestamp.asc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "count": len(rows),
        "filters": scope_payload(selected_os, selected_origin),
        "events": [_event_to_dict(r) for r in rows],
    }


@app.get("/events/suspicious")
def list_suspicious_events(
    min_risk_level: str = Query("MEDIUM", description="Minimum risk level to include: MEDIUM, HIGH, or CRITICAL"),
    limit: int = Query(200, ge=1, le=5000),
    os: Optional[str] = Query(None, description="OS scope: Windows, macOS, or Linux."),
    operating_system: Optional[str] = Query(None, description="Long-form alias for os."),
    data_origin: Optional[str] = Query(None, description="Evidence source scope: OBSERVED or SYNTHETIC_DEMO."),
    db: Session = Depends(get_db),
):
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    threshold = order.get(min_risk_level.upper(), 1)
    allowed_levels = [lvl for lvl, rank in order.items() if rank >= threshold]
    selected_os = resolve_os_filter(os, operating_system)
    selected_origin = resolve_data_origin_filter(data_origin)

    q = (
        apply_event_scope(
            db.query(models.Event),
            models.Event,
            operating_system=selected_os,
            data_origin=selected_origin,
        )
        .filter(models.Event.risk_level.in_(allowed_levels))
    )
    total = q.count()
    rows = (
        q
        .order_by(models.Event.risk_score.desc(), models.Event.timestamp.desc())
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "count": len(rows),
        "filters": scope_payload(selected_os, selected_origin),
        "events": [_event_to_dict(r) for r in rows],
    }


@app.get("/events/{event_row_id}")
def get_event(event_row_id: int, db: Session = Depends(get_db)):
    row = db.query(models.Event).filter(models.Event.id == event_row_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    return _event_to_dict(row, include_raw=True)


# --------------------------------------------------------------------- #
# Timeline (spec section 10 - basic chronological timeline only)
# --------------------------------------------------------------------- #

@app.get("/timeline")
def timeline(
    limit: int = Query(500, ge=1, le=5000),
    batch_id: Optional[str] = Query(None),
    os: Optional[str] = Query(None, description="OS scope: Windows, macOS, or Linux."),
    operating_system: Optional[str] = Query(None, description="Long-form alias for os."),
    data_origin: Optional[str] = Query(None, description="Evidence source scope: OBSERVED or SYNTHETIC_DEMO."),
    db: Session = Depends(get_db),
):
    """
    Basic chronological event timeline. NOT incident reconstruction -
    just events sorted by time, each with its risk level so the
    dashboard can render severity markers along the timeline.

    Returns the most recent ``limit`` events (in chronological order), so
    a large database shows the latest activity rather than the oldest.
    """
    selected_os = resolve_os_filter(os, operating_system)
    selected_origin = resolve_data_origin_filter(data_origin)
    q = apply_event_scope(
        db.query(models.Event),
        models.Event,
        operating_system=selected_os,
        data_origin=selected_origin,
    )
    if batch_id:
        q = q.filter(models.Event.batch_id == batch_id)
    rows = list(reversed(q.order_by(models.Event.timestamp.desc()).limit(limit).all()))
    return {
        "label": "Event Timeline (chronological only - not incident reconstruction)",
        "count": len(rows),
        "filters": scope_payload(selected_os, selected_origin),
        "events": [_event_to_dict(r) for r in rows],
    }


# --------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------- #

@app.get("/stats")
def stats(
    os: Optional[str] = Query(None, description="OS scope: Windows, macOS, or Linux."),
    operating_system: Optional[str] = Query(None, description="Long-form alias for os."),
    data_origin: Optional[str] = Query(None, description="Evidence source scope: OBSERVED or SYNTHETIC_DEMO."),
    db: Session = Depends(get_db),
):
    selected_os = resolve_os_filter(os, operating_system)
    selected_origin = resolve_data_origin_filter(data_origin)
    q = apply_event_scope(
        db.query(models.Event),
        models.Event,
        operating_system=selected_os,
        data_origin=selected_origin,
    )
    total_events = q.count()
    analyzed_events = q.filter(models.Event.analyzed == True).count()  # noqa: E712

    def count_level(level: str) -> int:
        return q.filter(models.Event.risk_level == level).count()

    low = count_level("LOW")
    medium = count_level("MEDIUM")
    high = count_level("HIGH")
    critical = count_level("CRITICAL")
    suspicious = medium + high + critical

    origin_rows = q.with_entities(models.Event.data_origin, func.count(models.Event.id)).group_by(models.Event.data_origin).all()
    origin_breakdown = {origin: count for origin, count in origin_rows}
    os_rows = q.with_entities(models.Event.operating_system, func.count(models.Event.id)).group_by(models.Event.operating_system).all()
    os_breakdown = {(name or "UNKNOWN"): count for name, count in os_rows}

    return {
        "total_events": total_events,
        "analyzed_events": analyzed_events,
        "unanalyzed_events": total_events - analyzed_events,
        "suspicious_events": suspicious,
        "risk_breakdown": {"LOW": low, "MEDIUM": medium, "HIGH": high, "CRITICAL": critical},
        "high_risk_events": high,
        "critical_risk_events": critical,
        "data_origin_breakdown": {
            "OBSERVED": origin_breakdown.get("OBSERVED", 0),
            "SYNTHETIC_DEMO": origin_breakdown.get("SYNTHETIC_DEMO", 0),
        },
        "operating_system_breakdown": os_breakdown,
        "filters": scope_payload(selected_os, selected_origin),
    }
