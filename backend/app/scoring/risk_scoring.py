"""
Forensic risk scoring.

Spec section 6 draws a hard line between two different numbers:

  * `anomaly_score`  - purely statistical, from Isolation Forest. It
    says "this is unusual relative to the batch", nothing more.
  * `risk_score`     - investigator-facing 0-100 score that combines
    the anomaly score with a small set of simple, named, contextual
    rules (failed logons, suspicious PowerShell flags, unusual network
    activity, etc).

Every point added to `risk_score` is tied to a human-readable reason
string, so "why flagged" is always traceable back to either "the ML
model found this unusual" or a specific named rule - never an
unexplained black-box number.
"""

from __future__ import annotations

import re

from app.features.feature_extraction import is_admin_group_add
from app.schemas import NormalizedEvent, RiskLevel

# Classic Linux/macOS download-and-execute and reverse-shell patterns.
_SUSPICIOUS_SHELL = re.compile(
    r"(curl|wget)\s[^|;]*\|\s*(ba|z|da)?sh\b"
    r"|base64\s+(-d|--decode)[^|;]*\|\s*(ba|z|da)?sh\b"
    r"|/dev/tcp/"
    r"|\bnc\b[^;|]*\s-e\s"
    r"|\bbash\s+-i\s*>&"
    r"|python[0-9.]*\s+-c\s+['\"]?import\s+(socket|pty)",
    re.IGNORECASE,
)


def _shell_text(e: NormalizedEvent) -> str:
    return f"{e.command_line or ''} {e.message or ''}"

# (reason, predicate(features, event) -> bool, points)
# Kept as simple, auditable rules - not hidden inside the ML model.
_RULES: list[tuple[str, callable, int]] = [
    (
        "Failed logon event",
        lambda f, e: f.get("is_failed_logon") == 1,
        10,
    ),
    (
        "Repeated failed logons for the same account/source (possible password guessing)",
        lambda f, e: f.get("failed_logon_burst") == 1,
        15,
    ),
    (
        "Account lockout following repeated failed logons",
        lambda f, e: f.get("is_lockout") == 1,
        15,
    ),
    (
        "Suspicious PowerShell execution (encoded/hidden-window flags)",
        lambda f, e: f.get("is_powershell_suspicious") == 1,
        30,
    ),
    (
        "Outbound connection to an uncommon destination port",
        lambda f, e: f.get("is_uncommon_dest_port") == 1 and f.get("has_network_fields") == 1,
        20,
    ),
    (
        "Rare / unusual process for this environment",
        lambda f, e: f.get("process_rarity", 0) > 0.85 and f.get("has_command_line") == 1,
        12,
    ),
    (
        "Rare event type relative to observed baseline",
        lambda f, e: f.get("event_type_rarity", 0) > 0.9,
        6,
    ),
    (
        "Activity occurred outside typical working hours",
        lambda f, e: f.get("is_off_hours") == 1,
        5,
    ),
    (
        "Audit log clearing attempt (possible anti-forensic action)",
        lambda f, e: e.event_id == 1102,
        35,
    ),
    (
        "Registry Run-key modification (possible persistence)",
        lambda f, e: e.event_id == 13 and "currentversion\\run" in (e.message or "").lower(),
        25,
    ),
    (
        "Elevated severity level (Error/Critical)",
        lambda f, e: f.get("severity_numeric", 0) >= 2,
        5,
    ),
    # --- cross-platform account changes ------------------------------
    (
        "New user account created (possible persistence)",
        lambda f, e: e.event_type == "User Account Created",
        20,
    ),
    (
        "User added to an administrator group (privilege change)",
        lambda f, e: is_admin_group_add(e),
        30,
    ),
    (
        "Account created and given admin rights within minutes (backdoor-account pattern)",
        lambda f, e: f.get("new_account_made_admin") == 1,
        25,
    ),
    # --- Linux-specific ------------------------------------------------
    (
        "Login attempt for a non-existent user (possible brute force / enumeration)",
        lambda f, e: e.event_type == "SSH Failed Login (Invalid User)",
        10,
    ),
    (
        "sudo denied - user not in sudoers (privilege escalation attempt)",
        lambda f, e: e.event_type == "Sudo Denied (Not in sudoers)",
        25,
    ),
    (
        "Suspicious shell command (download-and-execute or reverse-shell pattern)",
        lambda f, e: bool(_SUSPICIOUS_SHELL.search(_shell_text(e))),
        30,
    ),
]

ANOMALY_WEIGHT = 40  # max points contributed by the raw ML anomaly score
ANOMALY_REASON_THRESHOLD = 0.6  # only mention the ML reason if it meaningfully contributed


def classify_risk_level(risk_score: float) -> str:
    if risk_score <= 30:
        return RiskLevel.LOW.value
    if risk_score <= 60:
        return RiskLevel.MEDIUM.value
    if risk_score <= 80:
        return RiskLevel.HIGH.value
    return RiskLevel.CRITICAL.value


def score_event(event: NormalizedEvent, anomaly_score: float) -> tuple[float, str, list[str]]:
    """
    Compute (risk_score, risk_level, reasons) for one event, given its
    precomputed `.features` dict and its ML anomaly_score (0-1).
    """
    features = event.features or {}
    reasons: list[str] = []
    points = 0.0

    anomaly_contribution = anomaly_score * ANOMALY_WEIGHT
    points += anomaly_contribution
    if anomaly_score >= ANOMALY_REASON_THRESHOLD:
        reasons.append(
            f"High ML anomaly score ({anomaly_score:.2f}) - statistically unusual vs. observed baseline"
        )

    for reason_text, predicate, weight in _RULES:
        try:
            if predicate(features, event):
                points += weight
                reasons.append(reason_text)
        except Exception:
            # A malformed/missing field should never crash scoring -
            # just skip that rule for this event.
            continue

    risk_score = max(0.0, min(100.0, round(points, 1)))
    risk_level = classify_risk_level(risk_score)

    if not reasons:
        reasons.append("No significant anomaly or rule indicators; consistent with observed baseline")

    return risk_score, risk_level, reasons
