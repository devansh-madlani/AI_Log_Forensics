"""
Shared data schemas for the forensic log analysis pipeline.

This module is the single source of truth for the "normalized event"
shape that flows through every stage of the pipeline:

    Collector -> Normalizer -> Feature Extraction -> ML -> Risk Scoring -> API

Keeping one schema in one place means every stage agrees on field
names, and the raw evidence field is never dropped or overwritten.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class DataOrigin(str, Enum):
    """
    Forensic principle: never let synthetic demo data be mistaken for
    real evidence. Every event is explicitly tagged with where it came
    from, and this tag is preserved end-to-end (stored in the DB and
    returned by the API).
    """
    OBSERVED = "OBSERVED"              # real event read from a Windows log
    SYNTHETIC_DEMO = "SYNTHETIC_DEMO"  # generated demo/test data


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class NormalizedEvent:
    """
    Common event schema. One instance = one log event, from any source,
    normalized to the same shape so later pipeline stages don't need to
    know whether the event came from the Security log, the System log,
    Sysmon, or the synthetic demo generator.
    """

    # --- identity -----------------------------------------------------
    event_uid: str = field(default_factory=lambda: str(uuid.uuid4()))
    data_origin: str = DataOrigin.OBSERVED.value
    # Canonical collection platform, e.g. Windows, macOS, Linux. It is
    # separately stored so filters never have to parse or alter raw evidence.
    operating_system: Optional[str] = None

    # --- core fields (per spec section 3) ------------------------------
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id: Optional[int] = None
    log_source: str = "Unknown"          # e.g. "Security", "System", "Application", "Sysmon"
    provider: Optional[str] = None
    level: Optional[str] = None          # Windows level: Information/Warning/Error/Critical/Audit Success/Audit Failure
    computer: Optional[str] = None
    user: Optional[str] = None
    process_id: Optional[int] = None
    message: Optional[str] = None

    # --- extended fields, only populated when actually available ------
    parent_process: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    # --- normalized/derived descriptive fields -------------------------
    event_type: str = "Unknown"          # human-readable label, e.g. "Logon Failure"
    severity: Optional[str] = None       # normalized severity derived from `level`

    # --- evidence preservation ------------------------------------------
    raw_data: str = ""                   # original raw record (string form) - NEVER mutated

    # --- filled in by later stages --------------------------------------
    features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
