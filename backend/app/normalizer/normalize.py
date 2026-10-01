"""
Event normalization.

Takes a raw record dict (as produced by the Windows collector or the
synthetic demo generator - both emit the same raw shape, see
`collector/windows_collector.py` and `demo/synthetic_data.py`) and
converts it into a `schemas.NormalizedEvent`.

Forensic principle: normalization NEVER discards the original data.
The full raw record is JSON-serialized into `raw_data` untouched.
"""

from __future__ import annotations

import json
from typing import Any

from app.filtering import infer_operating_system
from app.schemas import NormalizedEvent, DataOrigin

# A small, honest lookup table of well-known Windows event IDs -> a
# human-readable label. This is NOT exhaustive (real deployments should
# extend it), and event IDs not in this table simply fall back to
# "Windows Event <id>" rather than a fabricated label.
EVENT_ID_LABELS: dict[int, str] = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Logoff",
    4648: "Explicit Credential Logon",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
    4689: "Process Termination",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4724: "Password Reset Attempt",
    4732: "Member Added to Security Group",
    4738: "User Account Changed",
    4740: "User Account Locked Out",
    1102: "Audit Log Cleared",
    4104: "PowerShell Script Block Logged",
    4103: "PowerShell Module Logged",
    5140: "Network Share Accessed",
    5156: "Network Connection Allowed",
    5157: "Network Connection Blocked",
    7034: "Service Crashed Unexpectedly",
    7035: "Service Control Request",
    7036: "Service State Change",
    7045: "New Service Installed",
    1000: "Application Error",
    1001: "Application Fault (WER)",
    6005: "Event Log Service Started (Boot)",
    6006: "Event Log Service Stopped (Shutdown)",
    41: "System Rebooted Without Clean Shutdown",
    # Sysmon
    1: "Sysmon: Process Creation",
    3: "Sysmon: Network Connection",
    7: "Sysmon: Image Loaded",
    11: "Sysmon: File Created",
    13: "Sysmon: Registry Value Set",
    22: "Sysmon: DNS Query",
}

# Windows "level" strings -> normalized severity bucket.
LEVEL_TO_SEVERITY: dict[str, str] = {
    "Critical": "Critical",
    "Error": "Error",
    "Warning": "Warning",
    "Information": "Informational",
    "Audit Success": "Informational",
    "Audit Failure": "Warning",
    "Verbose": "Informational",
    # macOS Unified Log message types
    "Fault": "Critical",
    "Default": "Informational",
    "Info": "Informational",
    "Debug": "Informational",
}


def _event_type_label(event_id: Any, log_source: str) -> str:
    try:
        eid = int(event_id)
    except (TypeError, ValueError):
        return "Unknown"

    # Sysmon shares event IDs 1-29 with generic meaning only in Sysmon's
    # own channel, so only use the Sysmon labels when log_source says so.
    if log_source == "Sysmon" and eid in EVENT_ID_LABELS:
        return EVENT_ID_LABELS[eid]
    if log_source != "Sysmon":
        label = EVENT_ID_LABELS.get(eid)
        if label and not label.startswith("Sysmon"):
            return label
    return f"Windows Event {eid}"


def normalize_event(raw: dict) -> NormalizedEvent:
    """
    Convert one raw record dict into a NormalizedEvent.

    `raw` is expected to (at minimum) contain the fields documented in
    the collector/demo generator. Missing optional fields are left as
    None rather than fabricated, per the "no fabricated evidence"
    principle.
    """
    level = raw.get("level")
    severity = LEVEL_TO_SEVERITY.get(level, level)  # fall back to raw level if unknown

    event_type = raw.get("event_type") or _event_type_label(
        raw.get("event_id"), raw.get("log_source", "Unknown")
    )

    data_origin = raw.get("data_origin", DataOrigin.OBSERVED.value)
    operating_system = infer_operating_system(
        operating_system=raw.get("operating_system"),
        log_source=raw.get("log_source"),
        provider=raw.get("provider"),
        data_origin=data_origin,
    )

    normalized = NormalizedEvent(
        data_origin=data_origin,
        operating_system=operating_system,
        timestamp=raw.get("timestamp"),
        event_id=raw.get("event_id"),
        log_source=raw.get("log_source", "Unknown"),
        provider=raw.get("provider"),
        level=level,
        computer=raw.get("computer"),
        user=raw.get("user"),
        process_id=raw.get("process_id"),
        message=raw.get("message"),
        parent_process=raw.get("parent_process"),
        process_name=raw.get("process_name"),
        command_line=raw.get("command_line"),
        source_ip=raw.get("source_ip"),
        destination_ip=raw.get("destination_ip"),
        source_port=raw.get("source_port"),
        destination_port=raw.get("destination_port"),
        event_type=event_type,
        severity=severity,
        raw_data=json.dumps(raw, default=str, sort_keys=True),
    )
    return normalized


def normalize_batch(raw_events: list[dict]) -> list[NormalizedEvent]:
    return [normalize_event(r) for r in raw_events]
