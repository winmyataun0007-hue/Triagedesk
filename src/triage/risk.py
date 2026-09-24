"""
Risk scoring.

Severity alone is a poor triage signal: a 'high' alert on a test box matters less
than a 'medium' one on the domain controller. The risk score fuses several
factors into one 0-100 number the analyst can sort by:

  * base severity of the alert,
  * threat-intelligence confidence on the source,
  * business criticality of the targeted asset,
  * whether the source is an internal host (possible compromise),
  * corroboration (multiple alerts of different categories on the same actor).

Every contribution is explainable, which matters for a defensible triage process.
"""

from __future__ import annotations

from src.common.models import Alert, SEVERITY_SCORE


def score_alert(alert: Alert, asset_boost_levels: int = 0) -> int:
    score = SEVERITY_SCORE.get(alert.severity, 50)
    e = alert.enrichment or {}

    # Threat-intel on the source raises confidence this is real.
    ti = e.get("threat_intel")
    if ti:
        score += int(ti.get("confidence", 0) * 0.12)   # up to +11

    # Targeting a critical asset raises impact.
    score += asset_boost_levels * 8                     # crown_jewel +16, high +8, low -8

    # An internal source acting maliciously is worse (compromise/insider).
    if e.get("src_internal") is True and alert.category in (
            "malware", "exfiltration", "c2", "intrusion"):
        score += 8

    # A hash match is near-certain badness.
    if e.get("hash_intel"):
        score += 10

    return max(1, min(100, score))


def combined_incident_score(alert_scores: list[int], distinct_categories: int,
                            distinct_techniques: int) -> int:
    """Incident risk = strongest alert, raised by breadth of activity."""
    if not alert_scores:
        return 0
    base = max(alert_scores)
    breadth = min(15, 4 * (distinct_categories - 1) + 3 * (distinct_techniques - 1))
    return max(1, min(100, base + breadth))
