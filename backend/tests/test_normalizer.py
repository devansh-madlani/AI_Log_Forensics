import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.normalizer.normalize import normalize_event, normalize_batch
from app.schemas import DataOrigin


def _raw_logon_failure():
    return {
        "data_origin": DataOrigin.OBSERVED.value,
        "timestamp": "2026-08-20T17:41:12+00:00",
        "event_id": 4625,
        "log_source": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "level": "Audit Failure",
        "computer": "WIN10-LAPTOP",
        "user": "svc_backup",
        "process_id": 1234,
        "message": "An account failed to log on. Account Name:\tsvc_backup",
        "source_ip": "10.0.5.20",
    }


def test_normalize_maps_known_event_id_to_label():
    ne = normalize_event(_raw_logon_failure())
    assert ne.event_type == "Failed Logon"
    assert ne.event_id == 4625
    assert ne.log_source == "Security"


def test_normalize_preserves_raw_data_as_evidence():
    raw = _raw_logon_failure()
    ne = normalize_event(raw)
    # raw_data must be a faithful, parseable copy of the original record
    round_tripped = json.loads(ne.raw_data)
    assert round_tripped["event_id"] == raw["event_id"]
    assert round_tripped["message"] == raw["message"]


def test_normalize_does_not_fabricate_missing_fields():
    raw = _raw_logon_failure()
    raw.pop("source_ip")  # not present
    ne = normalize_event(raw)
    assert ne.source_ip is None
    assert ne.destination_ip is None
    assert ne.command_line is None


def test_normalize_unknown_event_id_falls_back_gracefully():
    raw = _raw_logon_failure()
    raw["event_id"] = 999999
    ne = normalize_event(raw)
    assert ne.event_type == "Windows Event 999999"


def test_normalize_severity_mapping():
    ne = normalize_event(_raw_logon_failure())
    assert ne.severity == "Warning"  # Audit Failure -> Warning


def test_normalize_batch_preserves_order_and_count():
    raws = [_raw_logon_failure() for _ in range(5)]
    events = normalize_batch(raws)
    assert len(events) == 5
    assert all(e.event_id == 4625 for e in events)


def test_synthetic_demo_tag_preserved():
    raw = _raw_logon_failure()
    raw["data_origin"] = DataOrigin.SYNTHETIC_DEMO.value
    ne = normalize_event(raw)
    assert ne.data_origin == "SYNTHETIC_DEMO"
