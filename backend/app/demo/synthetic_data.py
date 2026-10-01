"""
Synthetic demonstration dataset.

Per spec section 11 ("Demonstration mode"): the system must be
demonstrable even on a laptop with no interesting activity in its real
logs. This module generates realistic-looking but clearly synthetic
Windows event data - mostly normal background activity, plus a smaller
set of built-in "storylines" (failed-logon bursts, suspicious
PowerShell, an unusual outbound connection, a registry modification,
log clearing) that the ML/risk-scoring stages are meant to catch.

Every record produced here is tagged `data_origin = SYNTHETIC_DEMO`
(see app.schemas.DataOrigin) so it can never be confused with real
evidence collected from an actual machine, all the way through the DB
and the API.

Reproducibility: a fixed random seed means re-running `generate()` with
the same arguments produces the same dataset, so results are
reproducible for a demo/rehearsal (spec section 12).
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from app.schemas import DataOrigin

DEMO_SEED = 42
DEMO_COMPUTER = "DEMO-WORKSTATION01"

NORMAL_USERS = ["alice.j", "bob.k", "carol.m", "dave.p"]
NORMAL_APPS = ["outlook.exe", "chrome.exe", "excel.exe", "teams.exe", "explorer.exe", "notepad.exe"]
SUSPICIOUS_USER = "svc_backup"  # a service-ish account, common attacker target
ATTACKER_HOST = "203.0.113.77"   # TEST-NET-3 (RFC 5737) - guaranteed non-routable/example
INTERNAL_SUBNET = "10.0.5."


def _iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat()


def _base_record(dt: datetime, event_id: int, log_source: str, provider: str,
                  level: str, message: str, **extra) -> dict:
    rec = {
        "data_origin": DataOrigin.SYNTHETIC_DEMO.value,
        # This demo deliberately models a Windows workstation; it is not
        # presented as live Windows evidence because data_origin remains
        # SYNTHETIC_DEMO end-to-end.
        "operating_system": "Windows",
        "timestamp": _iso(dt),
        "event_id": event_id,
        "log_source": log_source,
        "provider": provider,
        "level": level,
        "computer": DEMO_COMPUTER,
        "user": None,
        "process_id": random.randint(1000, 9999),
        "message": message,
    }
    rec.update(extra)
    return rec


def _normal_logon(dt: datetime) -> dict:
    user = random.choice(NORMAL_USERS)
    return _base_record(
        dt, 4624, "Security", "Microsoft-Windows-Security-Auditing", "Audit Success",
        f"[DEMO/SYNTHETIC] An account was successfully logged on. Account Name:\t{user}",
        user=user,
    )


def _normal_app_launch(dt: datetime) -> dict:
    user = random.choice(NORMAL_USERS)
    app = random.choice(NORMAL_APPS)
    return _base_record(
        dt, 4688, "Security", "Microsoft-Windows-Security-Auditing", "Audit Success",
        f"[DEMO/SYNTHETIC] A new process has been created. New Process Name:\t{app}",
        user=user, process_name=app,
        parent_process="explorer.exe",
        command_line=app,
    )


def _normal_service_event(dt: datetime) -> dict:
    return _base_record(
        dt, 7036, "System", "Service Control Manager", "Information",
        "[DEMO/SYNTHETIC] The Windows Update service entered the running state.",
    )


def _failed_logon(dt: datetime, user: str) -> dict:
    return _base_record(
        dt, 4625, "Security", "Microsoft-Windows-Security-Auditing", "Audit Failure",
        f"[DEMO/SYNTHETIC] An account failed to log on. Account Name:\t{user}\t"
        f"Source Network Address:\t{INTERNAL_SUBNET}{random.randint(10,250)}",
        user=user, source_ip=f"{INTERNAL_SUBNET}{random.randint(10,250)}",
    )


def _account_lockout(dt: datetime, user: str) -> dict:
    return _base_record(
        dt, 4740, "Security", "Microsoft-Windows-Security-Auditing", "Information",
        f"[DEMO/SYNTHETIC] A user account was locked out. Account Name:\t{user}",
        user=user,
    )


def _suspicious_powershell(dt: datetime) -> dict:
    encoded_blob = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"
    cmdline = f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded_blob}"
    return _base_record(
        dt, 4688, "Security", "Microsoft-Windows-Security-Auditing", "Audit Success",
        "[DEMO/SYNTHETIC] A new process has been created. New Process Name:\tpowershell.exe\t"
        f"Process Command Line:\t{cmdline}",
        user=SUSPICIOUS_USER,
        process_name="powershell.exe",
        parent_process="winword.exe",
        command_line=cmdline,
    )


def _unusual_process(dt: datetime) -> dict:
    path = r"C:\Users\Public\svchost32.exe"
    return _base_record(
        dt, 4688, "Security", "Microsoft-Windows-Security-Auditing", "Audit Success",
        f"[DEMO/SYNTHETIC] A new process has been created. New Process Name:\t{path}",
        user=SUSPICIOUS_USER,
        process_name=path,
        parent_process="powershell.exe",
        command_line=path,
    )


def _suspicious_outbound_connection(dt: datetime) -> dict:
    return _base_record(
        dt, 3, "Sysmon", "Microsoft-Windows-Sysmon", "Information",
        f"[DEMO/SYNTHETIC] Sysmon network connection detected. "
        f"Source Network Address:\t{INTERNAL_SUBNET}42\tSource Port:\t51322\t"
        f"Destination Address:\t{ATTACKER_HOST}\tDestination Port:\t4444",
        user=SUSPICIOUS_USER,
        process_name="svchost32.exe",
        source_ip=f"{INTERNAL_SUBNET}42", source_port=51322,
        destination_ip=ATTACKER_HOST, destination_port=4444,
    )


def _registry_modification(dt: datetime) -> dict:
    return _base_record(
        dt, 13, "Sysmon", "Microsoft-Windows-Sysmon", "Information",
        "[DEMO/SYNTHETIC] Sysmon registry value set: "
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater32 = C:\Users\Public\svchost32.exe",
        user=SUSPICIOUS_USER,
        process_name="svchost32.exe",
    )


def _log_cleared(dt: datetime) -> dict:
    return _base_record(
        dt, 1102, "Security", "Microsoft-Windows-Eventlog", "Information",
        f"[DEMO/SYNTHETIC] The audit log was cleared. Subject: Account Name:\t{SUSPICIOUS_USER}",
        user=SUSPICIOUS_USER,
    )


def _application_error(dt: datetime) -> dict:
    app = random.choice(NORMAL_APPS)
    return _base_record(
        dt, 1000, "Application", "Application Error", "Error",
        f"[DEMO/SYNTHETIC] Faulting application name: {app}, version 1.0.0.0",
    )


def generate(num_normal_events: int = 140, seed: int = DEMO_SEED) -> list[dict]:
    """
    Build a synthetic dataset spanning a single demo "day":
      - a stream of ordinary background activity (logons, app launches,
        service events, an occasional harmless app crash), spread across
        working hours, from a handful of normal users
      - a compact, clearly-flagged intrusion storyline late in the day:
        a burst of failed logons -> account lockout -> suspicious
        PowerShell -> unusual process -> outbound C2-style connection ->
        registry persistence -> an attempt to clear the audit log

    Returns a list of raw record dicts (same shape produced by the real
    Windows collector), all tagged SYNTHETIC_DEMO.
    """
    rng = random.Random(seed)
    random.seed(seed)  # the helper functions above use the module-level `random`

    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    work_start = today + timedelta(hours=8)

    events: list[dict] = []

    # --- normal background activity across the working day -------------
    normal_generators = [_normal_logon, _normal_app_launch, _normal_service_event]
    t = work_start
    for _ in range(num_normal_events):
        t += timedelta(seconds=rng.randint(20, 240))
        gen = rng.choices(normal_generators, weights=[3, 5, 2])[0]
        events.append(gen(t))
        if rng.random() < 0.03:
            events.append(_application_error(t + timedelta(seconds=1)))

    # --- intrusion storyline, injected in the evening -------------------
    storyline_start = work_start + timedelta(hours=9, minutes=41)  # ~17:41
    t = storyline_start

    # Burst of failed logons against the service account
    for i in range(6):
        t += timedelta(seconds=rng.randint(3, 12))
        events.append(_failed_logon(t, SUSPICIOUS_USER))

    t += timedelta(seconds=5)
    events.append(_account_lockout(t, SUSPICIOUS_USER))

    t += timedelta(seconds=90)
    events.append(_suspicious_powershell(t))

    t += timedelta(seconds=20)
    events.append(_unusual_process(t))

    t += timedelta(seconds=15)
    events.append(_suspicious_outbound_connection(t))

    t += timedelta(seconds=30)
    events.append(_registry_modification(t))

    t += timedelta(seconds=45)
    events.append(_log_cleared(t))

    # A little more normal noise after the storyline, so it's not the
    # very last thing in the log (more realistic + exercises sorting).
    for _ in range(8):
        t += timedelta(seconds=rng.randint(30, 200))
        events.append(rng.choice(normal_generators)(t))

    events.sort(key=lambda e: e["timestamp"])
    return events
