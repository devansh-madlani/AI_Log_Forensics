"""
Feature extraction.

Converts a batch of `NormalizedEvent`s into numeric features suitable
for Isolation Forest, per spec section 5. Features are computed
relative to the batch itself (the "observed baseline") - this is an
unsupervised, self-referential baseline, not a claim of global
knowledge about what's normal on any Windows machine.

Two kinds of signal are extracted:
  1. Frequency-based features (how rare is this event_type / process /
     source IP / destination port / user, within this batch). Rare
     things score as more unusual to Isolation Forest.
  2. A small number of simple, explainable content flags (failed logon,
     PowerShell with suspicious flags, has command line, off-hours).
     These are NOT the ML model's doing - they are plain rule checks
     that also get reused later, transparently, by the risk-scoring
     stage (see scoring/risk_scoring.py) to explain *why* something was
     flagged.

Every per-event feature dict is also attached back onto the event
(`event.features`) so it can be persisted and inspected by an
investigator - nothing about the ML input is hidden.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, tzinfo
from typing import Optional

import pandas as pd

from app.schemas import DataOrigin, NormalizedEvent

# Feature columns fed into Isolation Forest, in a fixed order.
FEATURE_COLUMNS = [
    "hour_of_day",
    "is_off_hours",
    "event_type_rarity",
    "process_rarity",
    "source_ip_rarity",
    "dest_port_rarity",
    "user_activity_rarity",
    "is_failed_logon",
    "is_lockout",
    "is_powershell_suspicious",
    "has_command_line",
    "has_network_fields",
    "is_uncommon_dest_port",
    "severity_numeric",
    "message_length",
]

_SEVERITY_NUMERIC = {
    "Informational": 0,
    "Warning": 1,
    "Error": 2,
    "Critical": 3,
}

# Ports considered "common"/expected for ordinary business traffic.
# Anything else is a mild novelty signal, not proof of anything.
_COMMON_PORTS = {80, 443, 53, 389, 445, 135, 88, 3389, 22, 25, 587, 993, 995}

# Cross-platform event_type labels (Windows labels come from the
# normalizer's event-ID table; Linux labels from the Linux collector).
FAILED_LOGON_EVENT_TYPES = {
    "Failed Logon",
    "SSH Failed Login",
    "SSH Failed Login (Invalid User)",
    "Sudo Authentication Failure",
    "Authentication Failure",
}
LOCKOUT_EVENT_TYPES = {"User Account Locked Out", "Account Locked Out"}

# This many failed logons against the same account/source in one batch
# counts as repeated attempts. Not an ML feature column - only a rule input.
REPEATED_FAILED_LOGON_THRESHOLD = 3

# An account creation and an admin-group grant this close together is the
# classic "create a backdoor admin" pattern. Rule input only, like above.
ACCOUNT_PRIVILEGE_WINDOW_S = 15 * 60

ACCOUNT_CREATED_EVENT_TYPES = {"User Account Created"}


def is_admin_group_add(e: NormalizedEvent) -> bool:
    """True when an account was added to an administrator group.

    Windows 4732 fires for *any* local security group (every new account is
    added to "Users"), so it only counts when the Administrators group
    (well-known SID S-1-5-32-544) is named in the event."""
    if e.event_type == "User Added to Admin Group":
        return True
    if e.event_id == 4732:
        msg = (e.message or "").lower()
        return "administrators" in msg or "s-1-5-32-544" in msg
    return False


def _epoch(timestamp: str):
    try:
        return datetime.fromisoformat(timestamp).timestamp()
    except (TypeError, ValueError, OSError):
        return None

_SUSPICIOUS_POWERSHELL_FLAGS = ("-enc", "-encodedcommand", "-nop", "-noni",
                                "-w hidden", "-windowstyle hidden", "iex(", "downloadstring")


def _parse_hour(timestamp: str, data_origin: Optional[str] = None,
                local_tz: Optional[tzinfo] = None) -> int:
    """Hour of day used for the off-hours check.

    Collectors store OBSERVED timestamps in UTC, but "working hours" means
    the host's wall clock, so tz-aware observed timestamps are converted to
    local time (`local_tz`, or the system timezone when None). Naive
    timestamps are already wall-clock and are used as-is.

    SYNTHETIC_DEMO timestamps are authored on a fixed UTC "demo day", so
    their clock is used as written - the demo must flag the same events on
    every host regardless of its timezone."""
    try:
        dt = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return 12  # neutral default if timestamp is unparseable
    if dt.tzinfo is not None and data_origin != DataOrigin.SYNTHETIC_DEMO.value:
        try:
            dt = dt.astimezone(local_tz)
        except (OverflowError, OSError, ValueError):
            pass  # out-of-range for local conversion; keep the stored clock
    return dt.hour


def _rarity(count: int, total: int) -> float:
    """
    Rarity score in [0, 1]: 0 = this value is the most common thing in
    the batch, 1 = it appears only once. Simple inverse-frequency
    encoding - legitimate, explainable, and doesn't require a
    pre-trained embedding of "normal Windows behavior".
    """
    if total <= 0 or count <= 0:
        return 0.0
    return 1.0 - (count / total)


def extract_features(events: list[NormalizedEvent],
                     local_tz: Optional[tzinfo] = None) -> pd.DataFrame:
    """
    Compute the feature matrix for a batch of events. Mutates each
    event's `.features` dict in place (for transparency/storage), and
    returns a DataFrame with one row per event, columns=FEATURE_COLUMNS.

    `local_tz` sets the host timezone used to judge off-hours for observed
    events; None means the system's local timezone.
    """
    if not events:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    event_type_counts = Counter(e.event_type for e in events)
    process_counts = Counter(e.process_name for e in events if e.process_name)
    source_ip_counts = Counter(e.source_ip for e in events if e.source_ip)
    user_counts = Counter(e.user for e in events if e.user)
    dest_port_counts = Counter(e.destination_port for e in events if e.destination_port)

    # Failed logons grouped by who/where they targeted, to spot repeated
    # attempts (password guessing) rather than a single typo.
    def _is_failed(e: NormalizedEvent) -> bool:
        return e.event_id == 4625 or e.event_type in FAILED_LOGON_EVENT_TYPES

    def _failed_key(e: NormalizedEvent) -> str:
        return e.user or e.source_ip or "unknown"

    failed_logon_counts = Counter(_failed_key(e) for e in events if _is_failed(e))

    created_times = [t for e in events if e.event_type in ACCOUNT_CREATED_EVENT_TYPES
                     and (t := _epoch(e.timestamp)) is not None]
    admin_times = [t for e in events if is_admin_group_add(e) and (t := _epoch(e.timestamp)) is not None]

    def _near(t, others) -> bool:
        return t is not None and any(abs(t - o) <= ACCOUNT_PRIVILEGE_WINDOW_S for o in others)

    total = len(events)
    rows = []

    for e in events:
        hour = _parse_hour(e.timestamp, e.data_origin, local_tz)
        is_off_hours = 1 if (hour < 7 or hour >= 20) else 0

        event_type_rarity = _rarity(event_type_counts[e.event_type], total)
        process_rarity = _rarity(process_counts.get(e.process_name, 0), total) if e.process_name else 0.0
        source_ip_rarity = _rarity(source_ip_counts.get(e.source_ip, 0), total) if e.source_ip else 0.0
        user_activity_rarity = _rarity(user_counts.get(e.user, 0), total) if e.user else 0.0
        dest_port_rarity = _rarity(dest_port_counts.get(e.destination_port, 0), total) if e.destination_port else 0.0

        is_failed_logon = 1 if _is_failed(e) else 0
        failed_logon_burst = 1 if (
            is_failed_logon and failed_logon_counts[_failed_key(e)] >= REPEATED_FAILED_LOGON_THRESHOLD
        ) else 0
        t = _epoch(e.timestamp)
        new_account_made_admin = 1 if (
            (e.event_type in ACCOUNT_CREATED_EVENT_TYPES and _near(t, admin_times))
            or (is_admin_group_add(e) and _near(t, created_times))
        ) else 0
        is_lockout = 1 if (e.event_id == 4740 or e.event_type in LOCKOUT_EVENT_TYPES) else 0

        cmdline_lower = (e.command_line or "").lower()
        process_lower = (e.process_name or "").lower()
        is_powershell_suspicious = 1 if (
            "powershell" in process_lower
            and any(flag in cmdline_lower for flag in _SUSPICIOUS_POWERSHELL_FLAGS)
        ) else 0

        has_command_line = 1 if e.command_line else 0
        has_network_fields = 1 if (e.source_ip or e.destination_ip) else 0
        is_uncommon_dest_port = 1 if (e.destination_port and e.destination_port not in _COMMON_PORTS) else 0

        severity_numeric = _SEVERITY_NUMERIC.get(e.severity, 1)
        message_length = len(e.message) if e.message else 0

        feat = {
            "hour_of_day": hour,
            "is_off_hours": is_off_hours,
            "event_type_rarity": round(event_type_rarity, 4),
            "process_rarity": round(process_rarity, 4),
            "source_ip_rarity": round(source_ip_rarity, 4),
            "dest_port_rarity": round(dest_port_rarity, 4),
            "user_activity_rarity": round(user_activity_rarity, 4),
            "is_failed_logon": is_failed_logon,
            "is_lockout": is_lockout,
            "failed_logon_burst": failed_logon_burst,
            "new_account_made_admin": new_account_made_admin,
            "is_powershell_suspicious": is_powershell_suspicious,
            "has_command_line": has_command_line,
            "has_network_fields": has_network_fields,
            "is_uncommon_dest_port": is_uncommon_dest_port,
            "severity_numeric": severity_numeric,
            "message_length": message_length,
        }

        e.features = feat  # attach for storage/inspection
        rows.append(feat)

    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
