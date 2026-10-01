"""macOS Unified Logging collector.

Collects real macOS Unified Log records using Apple's built-in ``log``
command. The collector emits the same raw-record shape as the Windows
collector, so the existing normalization -> feature extraction ->
Isolation Forest -> risk scoring pipeline can remain unchanged.

No evidence is fabricated: fields are populated only when present in the
JSON record returned by ``log show``. The complete JSON record is preserved
in ``raw_data`` by the normalizer.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
from datetime import datetime, timezone
from typing import Optional

from app.schemas import DataOrigin

IS_MACOS = platform.system() == "Darwin"


class MacOSCollectorUnavailableError(RuntimeError):
    """Raised when macOS Unified Log collection cannot be performed."""


# Literal message patterns -> event_type label (first match wins). The
# labels match the Windows/Linux ones so the shared risk rules apply.
# Records that match nothing keep the Unified Log category/subsystem.
_EVENT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"incorrect password attempts?", re.I), "Sudo Authentication Failure"),
    (re.compile(r"authentication failure for user|Failed to authenticate user|authentication failed for", re.I), "Authentication Failure"),
    (re.compile(r"new user: name=", re.I), "User Account Created"),
    (re.compile(r"add '\S+' to group '(admin|wheel)'", re.I), "User Added to Admin Group"),
    (re.compile(r"deleted user account", re.I), "User Account Deleted"),
]


def classify_message(message: Optional[str]) -> Optional[str]:
    if not message:
        return None
    for pattern, label in _EVENT_PATTERNS:
        if pattern.search(message):
            return label
    return None


def _parse_timestamp(value) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, str):
        # Apple's JSON output is normally ISO-8601. Keep the original
        # timestamp where possible because it is evidence.
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return value
    return str(value)


def _first(record: dict, *keys):
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def _extract_network_fields(record: dict) -> dict:
    """Extract only explicitly present network fields, if any."""
    out: dict = {}
    for source_key, target_key in (
        ("sourceIPAddress", "source_ip"),
        ("sourceIP", "source_ip"),
        ("destinationIPAddress", "destination_ip"),
        ("destinationIP", "destination_ip"),
        ("sourcePort", "source_port"),
        ("destinationPort", "destination_port"),
    ):
        value = record.get(source_key)
        if value not in (None, "") and target_key not in out:
            if target_key.endswith("_port"):
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    continue
            out[target_key] = value
    return out


def _record_to_raw(record: dict) -> dict:
    process_name = _first(record, "process", "processName", "sender", "senderName")
    process_id = _first(record, "processID", "processId", "pid")
    try:
        process_id = int(process_id) if process_id is not None else None
    except (TypeError, ValueError):
        process_id = None

    message = _first(record, "eventMessage", "message", "composedMessage")
    subsystem = _first(record, "subsystem", "subsystemName")
    category = _first(record, "category")
    event_type = (
        classify_message(str(message) if message is not None else None)
        or category or subsystem or "macOS Unified Log Event"
    )

    # Unified Logging does not expose a Windows-style numeric Event ID.
    # We intentionally leave it None rather than inventing one.
    raw = {
        "data_origin": DataOrigin.OBSERVED.value,
        "operating_system": "macOS",
        "timestamp": _parse_timestamp(_first(record, "timestamp", "time")),
        "event_id": None,
        "log_source": "macOS Unified Log",
        "provider": _first(record, "sender", "senderImagePath", "subsystem"),
        "level": _first(record, "messageType", "level", "type"),
        "computer": platform.node() or None,
        "user": _first(record, "user", "userName", "username"),
        "process_id": process_id,
        "message": str(message) if message is not None else None,
        "process_name": str(process_name) if process_name is not None else None,
        "command_line": _first(record, "commandLine", "command_line"),
        "event_type": str(event_type),
    }
    raw.update(_extract_network_fields(record))
    return raw


def _run_log_show(last: str, max_events: int) -> list[dict]:
    # --style json gives structured Unified Log records and avoids parsing
    # human-formatted terminal output. --info/--debug make collection more
    # complete for forensic analysis; the time window remains user-controlled.
    cmd = [
        "/usr/bin/log", "show",
        "--style", "json",
        "--last", last,
        "--info",
        "--debug",
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except FileNotFoundError as exc:
        raise MacOSCollectorUnavailableError("Apple's /usr/bin/log command is unavailable on this macOS host.") from exc
    except subprocess.TimeoutExpired as exc:
        raise MacOSCollectorUnavailableError("macOS Unified Log collection timed out after 90 seconds. Try a shorter time window.") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        raise MacOSCollectorUnavailableError(f"macOS log show failed: {detail[:1000]}")

    records: list[dict] = []
    # Depending on macOS version, JSON output can be a JSON array or one JSON
    # object per line. Support both formats.
    text = completed.stdout.strip()
    if not text:
        return records
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            candidates = parsed
        elif isinstance(parsed, dict):
            candidates = [parsed]
        else:
            candidates = []
    except json.JSONDecodeError:
        candidates = []
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    candidates.append(obj)
            except json.JSONDecodeError:
                continue

    # `log show` prints oldest first; keep the newest `max_events` so the
    # most recent activity is never the part that gets cut off.
    for obj in candidates[-max_events:]:
        records.append(_record_to_raw(obj))
    return records


def collect_events(
    last: str = "1h",
    max_events: int = 200,
) -> list[dict]:
    """Collect recent macOS Unified Log events.

    ``last`` accepts values understood by Apple's ``log show`` command,
    such as ``15m``, ``1h`` or ``1d``.
    """
    if not IS_MACOS:
        raise MacOSCollectorUnavailableError(
            "macOS Unified Log collection requires macOS. This host is not macOS."
        )
    if max_events < 1:
        return []
    return _run_log_show(last=last, max_events=max_events)
