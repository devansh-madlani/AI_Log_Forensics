"""
Safe test incident.

Lets an investigator demonstrate the pipeline on *real* host logs without
harming the machine: a small per-OS script performs genuine, reversible,
security-relevant actions (temporary account created, added to the admin
group, failed logons, a suspicious command written as log text only), then
removes everything it created. The resulting events are collected from the
OS like any other live evidence and stay tagged OBSERVED.

Every script lives next to this file so it can be read before running:
    windows.ps1   linux.sh   macos.sh

Nothing is downloaded or executed, no audit/security policy is changed, and
the temporary account (``forensics_demo``) never has a known password.
Creating accounts needs elevation, so the backend must run as Administrator
(Windows) or root (Linux/macOS).
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import time
from pathlib import Path

_SCRIPT_DIR = Path(__file__).parent
_TIMEOUT_S = 120

# platform.system() -> (script file, command prefix)
_SCRIPTS = {
    "Windows": ("windows.ps1", ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]),
    "Linux": ("linux.sh", ["/bin/bash"]),
    "Darwin": ("macos.sh", ["/bin/bash"]),
}


class SafeIncidentError(RuntimeError):
    """Raised when the safe test incident cannot be staged on this host."""


def is_elevated() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _elevation_hint(system: str) -> str:
    if system == "Windows":
        return "Start the backend from an Administrator terminal."
    return "Start the backend with sudo (it needs root to create and delete the temporary user)."


def run(system: str | None = None) -> dict:
    """
    Run the safe test incident for this OS. Returns
    ``{"steps": [...], "warnings": [...]}`` parsed from the script output.
    """
    system = system or platform.system()
    if system not in _SCRIPTS:
        raise SafeIncidentError(f"A safe test incident is not available for {system}.")
    if not is_elevated():
        raise SafeIncidentError(
            "Staging a safe test incident creates and deletes a temporary local account, "
            "which needs elevated rights. " + _elevation_hint(system)
        )

    script, prefix = _SCRIPTS[system]
    try:
        completed = subprocess.run(
            [*prefix, str(_SCRIPT_DIR / script)],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SafeIncidentError(f"Could not start the incident script: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SafeIncidentError("The safe test incident timed out; check that 'forensics_demo' was removed.") from exc

    steps, warnings = [], []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("STEP:"):
            steps.append(line[5:].strip())
        elif line.startswith(("WARNING:", "NOTE:")):
            warnings.append(line.split(":", 1)[1].strip())
        elif line.startswith("ERROR:"):
            raise SafeIncidentError(line[6:].strip())

    if completed.returncode != 0 and not steps:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        raise SafeIncidentError(f"The incident script failed: {detail[:500]}")

    # Give journald / the Unified Log / the Event Log a moment to flush.
    time.sleep(2)
    return {"steps": steps, "warnings": warnings}
