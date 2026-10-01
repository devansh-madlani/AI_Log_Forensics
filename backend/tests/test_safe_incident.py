import subprocess

import pytest
from fastapi.testclient import TestClient

from app import main, safe_incident
from app.collector import macos_collector
from app.features.feature_extraction import extract_features
from app.main import app
from app.schemas import NormalizedEvent
from app.scoring.risk_scoring import score_event

client = TestClient(app)


def _completed(stdout: str, returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_run_refuses_without_elevation(monkeypatch):
    monkeypatch.setattr(safe_incident, "is_elevated", lambda: False)
    with pytest.raises(safe_incident.SafeIncidentError, match="elevated"):
        safe_incident.run("Linux")


def test_run_rejects_unsupported_os():
    with pytest.raises(safe_incident.SafeIncidentError, match="not available"):
        safe_incident.run("FreeBSD")


def test_run_parses_steps_and_warnings(monkeypatch):
    monkeypatch.setattr(safe_incident, "is_elevated", lambda: True)
    monkeypatch.setattr(safe_incident.time, "sleep", lambda s: None)
    out = "STEP: Created user\nnoise\nNOTE: sshd is not running\nSTEP: Cleanup - deleted\n"
    monkeypatch.setattr(safe_incident.subprocess, "run", lambda *a, **k: _completed(out))
    result = safe_incident.run("Linux")
    assert result == {"steps": ["Created user", "Cleanup - deleted"], "warnings": ["sshd is not running"]}


def test_run_surfaces_script_error(monkeypatch):
    monkeypatch.setattr(safe_incident, "is_elevated", lambda: True)
    monkeypatch.setattr(
        safe_incident.subprocess, "run",
        lambda *a, **k: _completed("ERROR: user forensics_demo already exists; refusing to touch it.", 2),
    )
    with pytest.raises(safe_incident.SafeIncidentError, match="already exists"):
        safe_incident.run("Windows")


def test_endpoint_returns_clear_error_when_not_elevated(monkeypatch):
    monkeypatch.setattr(safe_incident, "is_elevated", lambda: False)
    resp = client.post("/collect/safe-incident")
    assert resp.status_code == 400
    assert "elevated" in resp.json()["detail"]


def test_endpoint_collects_after_staging(monkeypatch):
    monkeypatch.setattr(safe_incident, "run", lambda: {"steps": ["Created user"], "warnings": []})
    monkeypatch.setattr(main.platform, "system", lambda: "Linux")
    raw = {
        "data_origin": "OBSERVED", "operating_system": "Linux",
        "timestamp": "2026-10-01T10:00:00+00:00", "event_id": None,
        "log_source": "journal", "provider": "useradd", "level": "Information",
        "computer": "host", "user": "forensics_demo", "process_id": 1,
        "message": "new user: name=forensics_demo", "event_type": "User Account Created",
    }
    monkeypatch.setattr(main, "collect_linux_events", lambda **k: [raw])
    resp = client.post("/collect/safe-incident")
    assert resp.status_code == 200
    body = resp.json()
    assert body["incident_steps"] == ["Created user"]
    assert body["events_ingested"] == 1
    assert body["batch_id"].startswith("incident-")


@pytest.mark.parametrize("message,label", [
    ("new user: name=forensics_demo created with sysadminctl -addUser", "User Account Created"),
    ("add 'forensics_demo' to group 'admin' (dseditgroup)", "User Added to Admin Group"),
    ("authentication failure for user forensics_demo (dscl -authonly, wrong password 1)", "Authentication Failure"),
    ("removed 'forensics_demo' from group 'admin' and deleted user account forensics_demo", "User Account Deleted"),
    ("3 incorrect password attempts", "Sudo Authentication Failure"),
    ("ordinary log line", None),
])
def test_macos_classifier(message, label):
    assert macos_collector.classify_message(message) == label


def test_macos_keeps_newest_records(monkeypatch):
    lines = "\n".join(f'{{"eventMessage": "m{i}", "timestamp": "2026-10-01T10:00:0{i}Z"}}' for i in range(5))
    monkeypatch.setattr(
        macos_collector.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(args=[], returncode=0, stdout=lines, stderr=""),
    )
    records = macos_collector._run_log_show("5m", max_events=2)
    assert [r["message"] for r in records] == ["m3", "m4"]


def _event(i, user="forensics_demo", event_id=4625, event_type="Failed Logon"):
    return NormalizedEvent(
        event_uid=f"u{i}", data_origin="OBSERVED", operating_system="Windows",
        timestamp="2026-10-01T10:00:00+00:00", event_id=event_id, log_source="Security",
        provider="p", level="Audit Failure", computer="host", user=user, process_id=None,
        message="m", event_type=event_type, severity="Warning", raw_data="{}",
    )


def test_account_created_then_made_admin_is_correlated():
    created = _event(1, event_id=4720, event_type="User Account Created")
    users_group = _event(2, event_id=4732, event_type="Member Added to Security Group")
    users_group.message = "A member was added to a security-enabled local group. Group Name:\tUsers"
    admins = _event(3, event_id=4732, event_type="Member Added to Security Group")
    admins.message = "A member was added to a security-enabled local group. Group Name:\tAdministrators"
    unrelated = _event(4, event_id=4624, event_type="Successful Logon")
    extract_features([created, users_group, admins, unrelated])

    assert created.features["new_account_made_admin"] == 1
    assert admins.features["new_account_made_admin"] == 1
    assert users_group.features["new_account_made_admin"] == 0
    assert unrelated.features["new_account_made_admin"] == 0

    _, _, users_reasons = score_event(users_group, 0.0)
    assert not any("administrator group" in r for r in users_reasons)
    score, level, reasons = score_event(admins, 0.0)
    assert any("backdoor-account" in r for r in reasons) and score >= 55


def test_account_and_admin_far_apart_are_not_correlated():
    created = _event(1, event_id=4720, event_type="User Account Created")
    admins = _event(2, event_type="User Added to Admin Group")
    admins.timestamp = "2026-10-01T14:00:00+00:00"
    extract_features([created, admins])
    assert created.features["new_account_made_admin"] == 0


def test_repeated_failed_logons_add_a_named_reason():
    events = [_event(i) for i in range(3)] + [_event(9, user="someone_else")]
    extract_features(events)
    burst = [e.features["failed_logon_burst"] for e in events]
    assert burst == [1, 1, 1, 0]
    _, _, reasons = score_event(events[0], 0.0)
    assert any("Repeated failed logons" in r for r in reasons)
