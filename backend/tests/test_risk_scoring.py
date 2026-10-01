import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.scoring.risk_scoring import score_event, classify_risk_level
from app.schemas import NormalizedEvent


def _event(**overrides) -> NormalizedEvent:
    base = dict(
        event_id=4624,
        event_type="Successful Logon",
        message="An account was successfully logged on.",
        severity="Informational",
    )
    base.update(overrides)
    e = NormalizedEvent(**base)
    return e


def test_classify_risk_level_boundaries():
    assert classify_risk_level(0) == "LOW"
    assert classify_risk_level(30) == "LOW"
    assert classify_risk_level(31) == "MEDIUM"
    assert classify_risk_level(60) == "MEDIUM"
    assert classify_risk_level(61) == "HIGH"
    assert classify_risk_level(80) == "HIGH"
    assert classify_risk_level(81) == "CRITICAL"
    assert classify_risk_level(100) == "CRITICAL"


def test_normal_event_low_risk_with_zero_anomaly():
    e = _event()
    e.features = {
        "is_failed_logon": 0, "is_lockout": 0, "is_powershell_suspicious": 0,
        "is_uncommon_dest_port": 0, "has_network_fields": 0, "process_rarity": 0.1,
        "has_command_line": 0, "event_type_rarity": 0.1, "is_off_hours": 0,
        "severity_numeric": 0,
    }
    risk_score, risk_level, reasons = score_event(e, anomaly_score=0.05)
    assert risk_level == "LOW"
    assert risk_score < 31


def test_suspicious_powershell_flags_high_or_critical():
    e = _event(event_id=4688, event_type="Process Creation", process_name="powershell.exe",
                command_line="powershell.exe -NoP -W Hidden -Enc ABC123")
    e.features = {
        "is_failed_logon": 0, "is_lockout": 0, "is_powershell_suspicious": 1,
        "is_uncommon_dest_port": 0, "has_network_fields": 0, "process_rarity": 0.9,
        "has_command_line": 1, "event_type_rarity": 0.3, "is_off_hours": 1,
        "severity_numeric": 0,
    }
    risk_score, risk_level, reasons = score_event(e, anomaly_score=0.8)
    assert risk_level in ("HIGH", "CRITICAL")
    assert any("PowerShell" in r for r in reasons)
    assert any("anomaly score" in r.lower() for r in reasons)


def test_audit_log_cleared_is_flagged_with_reason():
    e = _event(event_id=1102, event_type="Audit Log Cleared", message="The audit log was cleared.")
    e.features = {
        "is_failed_logon": 0, "is_lockout": 0, "is_powershell_suspicious": 0,
        "is_uncommon_dest_port": 0, "has_network_fields": 0, "process_rarity": 0,
        "has_command_line": 0, "event_type_rarity": 0.95, "is_off_hours": 0,
        "severity_numeric": 0,
    }
    risk_score, risk_level, reasons = score_event(e, anomaly_score=0.3)
    assert any("anti-forensic" in r.lower() for r in reasons)
    assert risk_score >= 31  # should not be classified as low risk


def test_reasons_always_non_empty():
    e = _event()
    e.features = {}
    _, _, reasons = score_event(e, anomaly_score=0.0)
    assert len(reasons) >= 1


def test_risk_score_never_exceeds_100():
    e = _event(event_id=1102)
    e.features = {
        "is_failed_logon": 1, "is_lockout": 1, "is_powershell_suspicious": 1,
        "is_uncommon_dest_port": 1, "has_network_fields": 1, "process_rarity": 1.0,
        "has_command_line": 1, "event_type_rarity": 1.0, "is_off_hours": 1,
        "severity_numeric": 3,
    }
    risk_score, risk_level, _ = score_event(e, anomaly_score=1.0)
    assert risk_score <= 100
    assert risk_level == "CRITICAL"
