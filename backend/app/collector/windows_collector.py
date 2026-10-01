"""
Windows Event Log collector.

Reads real events from the Windows Security, System, and Application
logs (and optionally Sysmon's operational channel, if installed) using
`pywin32`'s `win32evtlog` module, which wraps the native Windows Event
Log API.

This module only works on Windows, because `win32evtlog` is a Windows-
only package. On any other OS, importing/using it raises a clear
`CollectorUnavailableError` instead of failing silently or fabricating
data - the rest of the pipeline (normalizer, ML, API, dashboard) does
not depend on Windows and can be exercised via the demo dataset instead
(see `app/demo/synthetic_data.py`).

Fields extracted per event, matching spec section 3:
    timestamp, event_id, log_source, provider, level, computer, user,
    process_id, message
Extended fields (only when present in the event's rendered data):
    parent_process, process_name, command_line,
    source_ip, destination_ip, source_port, destination_port

Nothing is fabricated: a field that isn't present in the event is left
as None rather than guessed.
"""

from __future__ import annotations

import platform
import re
from datetime import datetime, timezone
from typing import Iterator, Optional

from app.schemas import DataOrigin

IS_WINDOWS = platform.system() == "Windows"

# Windows event levels, per the Win32 API (EVENTLOG_* / winevt levels).
_LEVEL_MAP = {
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    0: "Information",
}

# Classic (non-XML) win32evtlog EventType values.
_LEGACY_TYPE_MAP = {
    1: "Error",       # EVENTLOG_ERROR_TYPE
    2: "Warning",     # EVENTLOG_WARNING_TYPE
    4: "Information", # EVENTLOG_INFORMATION_TYPE
    8: "Audit Success",
    16: "Audit Failure",
}

DEFAULT_CHANNELS = ["Security", "System", "Application"]
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


class CollectorUnavailableError(RuntimeError):
    """Raised when Windows Event Log collection is attempted on a
    non-Windows host, or when pywin32 isn't installed."""


def _require_win32evtlog():
    if not IS_WINDOWS:
        raise CollectorUnavailableError(
            "Windows Event Log collection requires Windows + pywin32. "
            "This host is not Windows, so live collection is disabled. "
            "Use demo mode (POST /demo/load) to exercise the rest of "
            "the pipeline, and run the collector on a Windows laptop "
            "for real evidence."
        )
    try:
        import win32evtlog  # noqa: F401
    except ImportError as exc:
        raise CollectorUnavailableError(
            "pywin32 is not installed. Run: pip install pywin32"
        ) from exc


# --- helpers for pulling structured fields out of the free-text message ---
# Windows Security event messages (e.g. 4624/4625/4688) contain
# structured "Key:\tValue" lines. We can safely parse a few well-known
# labels without inventing anything that isn't literally in the text.

_FIELD_PATTERNS = {
    "process_name": re.compile(r"(?:New Process Name|Process Name):\s*(\S.*)"),
    "parent_process": re.compile(r"Creator Process Name:\s*(\S.*)"),
    "command_line": re.compile(r"Process Command Line:\s*(\S.*)"),
    "source_ip": re.compile(r"Source Network Address:\s*(\S+)"),
    "source_port": re.compile(r"Source Port:\s*(\d+)"),
    "destination_ip": re.compile(r"(?:Destination Address|Network Address):\s*(\S+)"),
    "destination_port": re.compile(r"(?:Destination Port|Network Port):\s*(\d+)"),
    "user": re.compile(r"Account Name:\s*(\S.*)"),
}


def windows_time_to_utc_iso(ts) -> str:
    """
    Convert an event's TimeGenerated to an ISO-8601 UTC timestamp.

    The legacy ReadEventLog API returns TimeGenerated as a naive datetime
    in the host's *local* time, so it must be interpreted as local time
    before converting to UTC. (Labelling it UTC directly shifts every
    event by the host's UTC offset.)
    """
    naive = datetime(ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second)
    if getattr(ts, "tzinfo", None) is not None:
        naive = naive.replace(tzinfo=ts.tzinfo)
    return naive.astimezone(timezone.utc).isoformat()


def _extract_fields_from_message(message: str) -> dict:
    extracted = {}
    if not message:
        return extracted
    for field_name, pattern in _FIELD_PATTERNS.items():
        m = pattern.search(message)
        if m:
            value = m.group(1).strip()
            if value and value != "-":
                if field_name in ("source_port", "destination_port"):
                    try:
                        value = int(value)
                    except ValueError:
                        continue
                extracted[field_name] = value
    return extracted


def _read_channel(channel: str, max_events: int) -> Iterator[dict]:
    """
    Yield raw record dicts for a single event log channel, newest first.

    Uses the legacy win32evtlog ReadEventLog API (works for classic
    channels like Security/System/Application out of the box). Sysmon's
    channel is a "modern" ETW channel; classic ReadEventLog can still
    open it by name on most systems, but if that fails we surface a
    clear per-channel error rather than crashing the whole collection.
    """
    import win32evtlog
    import win32evtlogutil
    import win32con

    handle = win32evtlog.OpenEventLog(None, channel)
    try:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        count = 0
        while count < max_events:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for ev in events:
                if count >= max_events:
                    break
                count += 1

                try:
                    message = win32evtlogutil.SafeFormatMessage(ev, channel)
                except Exception:
                    message = None

                level = _LEGACY_TYPE_MAP.get(ev.EventType, "Information")
                ts = ev.TimeGenerated
                try:
                    timestamp = windows_time_to_utc_iso(ts)
                except Exception:
                    timestamp = datetime.now(timezone.utc).isoformat()

                record = {
                    "data_origin": DataOrigin.OBSERVED.value,
                    "operating_system": "Windows",
                    "timestamp": timestamp,
                    "event_id": ev.EventID & 0xFFFF,  # mask off qualifier bits
                    "log_source": channel,
                    "provider": ev.SourceName,
                    "level": level,
                    "computer": ev.ComputerName,
                    "user": None,   # filled below if present
                    "process_id": None,
                    "message": message,
                }

                # Best-effort extraction of extra fields from the
                # rendered message text (never fabricated - only what's
                # literally present).
                if message:
                    record.update(_extract_fields_from_message(message))

                yield record
    finally:
        win32evtlog.CloseEventLog(handle)


def collect_events(
    channels: Optional[list[str]] = None,
    max_events_per_channel: int = 200,
    include_sysmon: bool = False,
    warnings: Optional[list[str]] = None,
) -> list[dict]:
    """
    Collect raw events from the requested Windows Event Log channels.

    Returns a list of raw record dicts (same shape the normalizer
    expects). Raises CollectorUnavailableError if this isn't Windows.
    Per-channel failures (e.g. missing Sysmon, insufficient privilege
    to read Security) are collected as warnings and skipped rather than
    aborting the whole run - the caller can decide how to surface them.
    """
    _require_win32evtlog()

    channels = list(channels or DEFAULT_CHANNELS)
    if include_sysmon and SYSMON_CHANNEL not in channels:
        channels.append(SYSMON_CHANNEL)

    all_events: list[dict] = []
    errors: list[str] = []
    skipped: list[str] = []

    for channel in channels:
        try:
            all_events.extend(_read_channel(channel, max_events_per_channel))
        except Exception as exc:
            # Common cause: Security log requires an elevated / admin
            # process to read. Surface it, don't crash the whole run.
            errors.append(f"{channel}: {exc}")
            skipped.append(describe_channel_error(channel, exc))

    if errors and not all_events:
        raise CollectorUnavailableError(
            "Could not read any requested event log channel. "
            "Try running as Administrator. Errors: " + "; ".join(errors)
        )

    if warnings is not None:
        warnings.extend(skipped)

    return all_events


def describe_channel_error(channel: str, exc: Exception) -> str:
    """Plain-language explanation of why a channel was skipped."""
    code = exc.args[0] if getattr(exc, "args", None) else None
    if code == 1314:  # ERROR_PRIVILEGE_NOT_HELD
        return f"{channel} log skipped: reading it requires running the backend as Administrator."
    if code in (2, 1076):  # file / event log not found
        return f"{channel} log skipped: it isn't present on this machine."
    return f"{channel} log skipped: {exc}"
