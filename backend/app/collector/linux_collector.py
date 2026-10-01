"""Linux log collector.

Collects real Linux host logs and emits the same raw-record shape as the
Windows and macOS collectors, so the normalization -> feature extraction
-> Isolation Forest -> risk scoring pipeline stays unchanged.

Sources, in order of preference:
  1. systemd journal via ``journalctl -o json`` (most modern distros).
     Covers the kernel, services, sshd, sudo, su, useradd, PAM, etc.
  2. Classic syslog text files (``/var/log/auth.log``, ``/var/log/secure``,
     ``/var/log/syslog``, ``/var/log/messages``) when journalctl is
     unavailable (non-systemd hosts, some containers/WSL setups).

Reading other users' and system journal entries usually requires root or
membership in the ``adm`` / ``systemd-journal`` group. Anything that could
not be read is reported back as a warning rather than silently dropped.

No evidence is fabricated: fields are populated only when present in the
source record, and Linux has no Windows-style numeric event ID, so
``event_id`` is always None. ``event_type`` is a label derived from
literal message patterns (e.g. "Failed password for ...").
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from app.schemas import DataOrigin

IS_LINUX = platform.system() == "Linux"

# journald PRIORITY (syslog severity 0-7) -> the level vocabulary the
# normalizer already understands.
_PRIORITY_TO_LEVEL = {
    0: "Critical",   # emerg
    1: "Critical",   # alert
    2: "Critical",   # crit
    3: "Error",      # err
    4: "Warning",    # warning
    5: "Information",  # notice
    6: "Information",  # info
    7: "Verbose",    # debug
}

SYSLOG_FILES = ("/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages")

_LAST_PATTERN = re.compile(r"^\d+[smhd]$")

# Literal message patterns -> event_type label. Order matters: the first
# match wins. These labels are what the risk-scoring rules key on.
_EVENT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Failed password for invalid user", re.I), "SSH Failed Login (Invalid User)"),
    (re.compile(r"Invalid user \S+ from", re.I), "SSH Failed Login (Invalid User)"),
    (re.compile(r"Failed (password|publickey) for", re.I), "SSH Failed Login"),
    (re.compile(r"Accepted (password|publickey|keyboard-interactive\S*) for", re.I), "SSH Successful Login"),
    (re.compile(r"pam_unix\(sudo:auth\): authentication failure|incorrect password attempts?", re.I), "Sudo Authentication Failure"),
    (re.compile(r"user NOT in sudoers|is not in the sudoers file", re.I), "Sudo Denied (Not in sudoers)"),
    (re.compile(r"\bCOMMAND=", re.I), "Sudo Command Executed"),
    (re.compile(r"pam_unix\(\S+:auth\): authentication failure", re.I), "Authentication Failure"),
    (re.compile(r"FAILED (SU|su)\b|su: .*authentication failure", re.I), "Authentication Failure"),
    (re.compile(r"(account|user) .* (temporarily )?locked|Consecutive login failures", re.I), "Account Locked Out"),
    (re.compile(r"new user: name=|useradd\[\d+\]: new user", re.I), "User Account Created"),
    (re.compile(r"new group: name=", re.I), "Group Created"),
    (re.compile(r"add '\S+' to (group|shadow group) 'sudo'|usermod.*-aG? sudo|add '\S+' to group 'wheel'", re.I), "User Added to Admin Group"),
    (re.compile(r"password changed for|chpasswd|passwd\[\d+\]: .*password changed", re.I), "Password Changed"),
    (re.compile(r"session opened for user", re.I), "Session Opened"),
    (re.compile(r"session closed for user", re.I), "Session Closed"),
    (re.compile(r"segfault at|general protection fault", re.I), "Process Crash"),
    (re.compile(r"Out of memory: Kill", re.I), "Out of Memory Kill"),
    (re.compile(r"CRON\[\d+\]|\bcron\b.*CMD", re.I), "Scheduled Job Executed"),
]

_SSH_IP = re.compile(r"from ((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,}) port (\d+)")
_SSH_USER = re.compile(r"(?:for invalid user|Invalid user|for|user) (\S+?)(?: from|\(|\s|$)")
_SUDO_USER = re.compile(r"^\s*(\S+) : ")
_SUDO_COMMAND = re.compile(r"COMMAND=(.+)$")

# Classic syslog: "Sep 30 21:08:41 host proc[123]: message"
_SYSLOG_BSD = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
# RFC 3339 syslog (newer rsyslog defaults): "2026-09-30T21:08:41.123456+05:30 host proc[123]: message"
_SYSLOG_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s(?P<host>\S+)\s(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)


class LinuxCollectorUnavailableError(RuntimeError):
    """Raised when Linux log collection cannot be performed."""


def classify_message(message: Optional[str]) -> Optional[str]:
    if not message:
        return None
    for pattern, label in _EVENT_PATTERNS:
        if pattern.search(message):
            return label
    return None


def _extract_fields(message: Optional[str], event_type: Optional[str]) -> dict:
    """Pull only literally-present fields out of well-known auth messages."""
    out: dict = {}
    if not message:
        return out
    if event_type and event_type.startswith("SSH"):
        m = _SSH_IP.search(message)
        if m:
            out["source_ip"] = m.group(1)
            try:
                out["source_port"] = int(m.group(2))
            except ValueError:
                pass
        u = _SSH_USER.search(message)
        if u:
            out["user"] = u.group(1)
    if event_type and event_type.startswith("Sudo"):
        u = _SUDO_USER.search(message)
        if u:
            out["user"] = u.group(1)
        c = _SUDO_COMMAND.search(message)
        if c:
            out["command_line"] = c.group(1).strip()
    return out


def _decode_journal_value(value):
    """journald encodes non-UTF-8 fields as a list of byte values."""
    if isinstance(value, list):
        try:
            return bytes(value).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return str(value)
    return value


def _journal_timestamp(record: dict) -> str:
    micros = record.get("__REALTIME_TIMESTAMP") or record.get("_SOURCE_REALTIME_TIMESTAMP")
    try:
        return datetime.fromtimestamp(int(micros) / 1_000_000, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.now(timezone.utc).isoformat()


def journal_record_to_raw(record: dict) -> dict:
    """Convert one ``journalctl -o json`` object into the shared raw shape."""
    message = _decode_journal_value(record.get("MESSAGE"))
    message = str(message) if message is not None else None
    identifier = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM")
    unit = record.get("_SYSTEMD_UNIT") or record.get("UNIT")

    try:
        priority = int(record.get("PRIORITY"))
    except (TypeError, ValueError):
        priority = None

    try:
        pid = int(record.get("_PID") or record.get("SYSLOG_PID"))
    except (TypeError, ValueError):
        pid = None

    event_type = classify_message(message) or (f"{identifier} log" if identifier else "Linux Journal Event")

    raw = {
        "data_origin": DataOrigin.OBSERVED.value,
        "operating_system": "Linux",
        "timestamp": _journal_timestamp(record),
        "event_id": None,
        "log_source": "Linux Journal",
        "provider": unit or identifier,
        "level": _PRIORITY_TO_LEVEL.get(priority, "Information"),
        "computer": record.get("_HOSTNAME") or platform.node() or None,
        "user": None,
        "process_id": pid,
        "message": message,
        "process_name": _decode_journal_value(record.get("_EXE")) or identifier,
        # journald's _CMDLINE is the *logging* process's own argv (e.g. snapd),
        # not a process the event is about, so it is not used as command_line.
        # Only commands the log itself reports (sudo's COMMAND=) are.
        "command_line": None,
        "event_type": event_type,
        # Untouched original journal entry, preserved as evidence.
        "journal_record": record,
    }
    raw.update({k: v for k, v in _extract_fields(message, event_type).items() if v})
    return raw


def _parse_syslog_timestamp(ts: str, now: datetime) -> str:
    if "T" in ts:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
        except ValueError:
            return ts
    # BSD syslog has no year or timezone: assume the local timezone and the
    # current year, rolling back a year for dates that would be in the future.
    try:
        parsed = datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return ts
    local = parsed.astimezone()
    if local > now.astimezone():
        local = parsed.replace(year=now.year - 1).astimezone()
    return local.astimezone(timezone.utc).isoformat()


def syslog_line_to_raw(line: str, source_file: str, now: Optional[datetime] = None) -> Optional[dict]:
    """Convert one classic syslog line into the shared raw shape."""
    now = now or datetime.now(timezone.utc)
    m = _SYSLOG_RFC3339.match(line) or _SYSLOG_BSD.match(line)
    if not m:
        return None
    message = m.group("msg")
    proc = m.group("proc")
    event_type = classify_message(f"{proc}[{m.group('pid') or 0}]: {message}") or f"{proc} log"
    try:
        pid = int(m.group("pid")) if m.group("pid") else None
    except ValueError:
        pid = None
    raw = {
        "data_origin": DataOrigin.OBSERVED.value,
        "operating_system": "Linux",
        "timestamp": _parse_syslog_timestamp(m.group("ts"), now),
        "event_id": None,
        "log_source": f"Linux {os.path.basename(source_file)}",
        "provider": proc,
        "level": "Information",
        "computer": m.group("host"),
        "user": None,
        "process_id": pid,
        "message": message,
        "process_name": proc,
        "command_line": None,
        "event_type": event_type,
        # Untouched original log line, preserved as evidence.
        "syslog_line": line,
    }
    raw.update({k: v for k, v in _extract_fields(message, event_type).items() if v})
    return raw


def _run_journalctl(last: str, max_events: int, warnings: list[str]) -> list[dict]:
    cmd = [
        "journalctl", "-o", "json", "--no-pager",
        "--since", f"-{last}",
        "-n", str(max_events),
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=90, check=False)
    except subprocess.TimeoutExpired as exc:
        raise LinuxCollectorUnavailableError(
            "journalctl timed out after 90 seconds. Try a shorter time window."
        ) from exc

    if completed.returncode != 0 and not completed.stdout.strip():
        detail = (completed.stderr or "unknown error").strip()
        raise LinuxCollectorUnavailableError(f"journalctl failed: {detail[:1000]}")

    stderr = (completed.stderr or "").strip()
    if "not seeing messages from other users and the system" in stderr:
        warnings.append(
            "Only your own user's journal was readable. Run the backend with sudo, or add "
            "your user to the 'adm' or 'systemd-journal' group, to include system and auth logs."
        )

    records: list[dict] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(journal_record_to_raw(obj))
    return records


def _tail(path: str, max_lines: int) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return list(deque(fh, maxlen=max_lines))


def _read_syslog_files(max_events: int, warnings: list[str]) -> list[dict]:
    records: list[dict] = []
    now = datetime.now(timezone.utc)
    for path in SYSLOG_FILES:
        if not os.path.exists(path):
            continue
        try:
            lines = _tail(path, max_events)
        except PermissionError:
            warnings.append(f"{path}: permission denied (run with sudo or join the 'adm' group).")
            continue
        except OSError as exc:
            warnings.append(f"{path}: {exc}")
            continue
        for line in lines:
            raw = syslog_line_to_raw(line.rstrip("\n"), path, now=now)
            if raw:
                records.append(raw)
    return records


def collect_events(
    last: str = "1h",
    max_events: int = 200,
    warnings: Optional[list[str]] = None,
) -> list[dict]:
    """Collect recent Linux log events (newest ``max_events`` in the window).

    ``last`` is a time window such as ``15m``, ``1h`` or ``1d``. Any
    non-fatal problems (partial permissions, fallback to text logs) are
    appended to ``warnings`` when a list is supplied.
    """
    warnings = warnings if warnings is not None else []
    if not IS_LINUX:
        raise LinuxCollectorUnavailableError(
            "Linux log collection requires Linux. This host is not Linux."
        )
    if max_events < 1:
        return []
    if not _LAST_PATTERN.match(last or ""):
        raise LinuxCollectorUnavailableError(
            "Invalid time window. Use a number followed by s, m, h or d, e.g. 15m or 1h."
        )

    if shutil.which("journalctl"):
        events = _run_journalctl(last, max_events, warnings)
        if events:
            return events
        warnings.append("journalctl returned no events; falling back to /var/log text files.")

    events = _read_syslog_files(max_events, warnings)
    if not events:
        raise LinuxCollectorUnavailableError(
            "No readable Linux logs found. journalctl is unavailable or empty and no "
            "/var/log auth/syslog files could be read. Try running the backend with sudo."
        )
    return events
