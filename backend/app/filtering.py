"""Shared OS/source scope helpers for the API and analysis pipeline.

The normalized ``operating_system`` value is intentionally a small,
display-friendly vocabulary.  It is analysis metadata, not a replacement for
the original raw event: ``raw_data`` remains preserved verbatim.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import HTTPException


OPERATING_SYSTEM_ALIASES = {
    "windows": "Windows",
    "win": "Windows",
    "win32": "Windows",
    "macos": "macOS",
    "mac": "macOS",
    "darwin": "macOS",
    "osx": "macOS",
    "linux": "Linux",
}

DATA_ORIGIN_ALIASES = {
    "observed": "OBSERVED",
    "live": "OBSERVED",
    "synthetic_demo": "SYNTHETIC_DEMO",
    "synthetic": "SYNTHETIC_DEMO",
    "demo": "SYNTHETIC_DEMO",
}


def canonical_operating_system(value: Optional[str]) -> Optional[str]:
    """Return the canonical OS value, or ``None`` when it is not supplied."""
    if value is None or not value.strip():
        return None
    return OPERATING_SYSTEM_ALIASES.get(value.strip().lower())


def canonical_data_origin(value: Optional[str]) -> Optional[str]:
    """Return the canonical evidence-origin value, or ``None`` when absent."""
    if value is None or not value.strip():
        return None
    return DATA_ORIGIN_ALIASES.get(value.strip().lower())


def resolve_os_filter(os_value: Optional[str], operating_system: Optional[str]) -> Optional[str]:
    """Resolve ``os`` and the long-form compatibility alias safely."""
    short = canonical_operating_system(os_value)
    long = canonical_operating_system(operating_system)
    supplied = [value for value in (os_value, operating_system) if value and value.strip()]

    if supplied and (not short if os_value and os_value.strip() else False):
        raise HTTPException(status_code=422, detail="Unsupported OS filter. Use Windows, macOS, or Linux.")
    if supplied and (not long if operating_system and operating_system.strip() else False):
        raise HTTPException(status_code=422, detail="Unsupported OS filter. Use Windows, macOS, or Linux.")
    if short and long and short != long:
        raise HTTPException(status_code=422, detail="os and operating_system must identify the same OS.")
    return short or long


def resolve_data_origin_filter(value: Optional[str]) -> Optional[str]:
    canonical = canonical_data_origin(value)
    if value and value.strip() and not canonical:
        raise HTTPException(
            status_code=422,
            detail="Unsupported data_origin filter. Use OBSERVED or SYNTHETIC_DEMO.",
        )
    return canonical


def infer_operating_system(
    *,
    operating_system: Optional[str] = None,
    log_source: Optional[str] = None,
    provider: Optional[str] = None,
    data_origin: Optional[str] = None,
    raw_data: Optional[str] = None,
) -> Optional[str]:
    """Infer only when the source itself identifies the OS.

    This lets the application classify pre-existing rows that were stored
    before the field existed.  Unknown sources deliberately remain ``None``;
    the application never guesses an OS for evidence that does not establish
    one.  The bundled synthetic data is explicitly documented as a Windows
    scenario, so it is safely classified as Windows.
    """
    canonical = canonical_operating_system(operating_system)
    if canonical:
        return canonical

    if raw_data:
        try:
            raw = json.loads(raw_data)
        except (TypeError, ValueError, json.JSONDecodeError):
            raw = {}
        if isinstance(raw, dict):
            canonical = canonical_operating_system(raw.get("operating_system"))
            if canonical:
                return canonical

    source = (log_source or "").lower()
    provider_value = (provider or "").lower()
    if "macos" in source or "unified log" in source or "/system/library" in provider_value:
        return "macOS"
    if source.startswith("linux") or "journal" in source:
        return "Linux"
    if (
        "windows" in source
        or source in {"security", "system", "application", "sysmon"}
        or "windows" in provider_value
        or "sysmon" in provider_value
    ):
        return "Windows"
    if canonical_data_origin(data_origin) == "SYNTHETIC_DEMO":
        return "Windows"
    return None


def apply_event_scope(query: Any, event_model: Any, *, operating_system: Optional[str], data_origin: Optional[str]):
    """Apply an already-resolved OS/origin scope to a SQLAlchemy event query."""
    if operating_system:
        query = query.filter(event_model.operating_system == operating_system)
    if data_origin:
        query = query.filter(event_model.data_origin == data_origin)
    return query


def scope_payload(operating_system: Optional[str], data_origin: Optional[str]) -> dict:
    """A stable, explicit description returned by scoped API responses."""
    return {"operating_system": operating_system, "data_origin": data_origin}
