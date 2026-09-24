"""
Alert correlation.

One attack produces many alerts. A brute-force burst alone can be dozens. If the
analyst sees each alert individually they drown; the platform's job is to group
related alerts into a single incident they can work as one case.

Correlation key: the acting entity. For an external attacker that is the source
IP; for activity with no external source (e.g. an EDR detection on a host) it is
the affected host. Alerts sharing a key within a time window join the same
incident. This is a transparent, explainable rule — not a black box — which suits
a project that must be defended in a viva.
"""

from __future__ import annotations

from typing import Optional

from src.common.models import (Alert, Incident, SEVERITIES, sev_rank)
from src.common.util import new_id
from src.triage.risk import combined_incident_score


class Correlator:
    def __init__(self, window_seconds: float = 1800.0):
        self.window = window_seconds
        # actor_key -> incident_id currently open for it
        self._open: dict[str, str] = {}
        self.incidents: dict[str, Incident] = {}
        self._members: dict[str, list[Alert]] = {}

    @staticmethod
    def actor_key(a: Alert) -> str:
        if a.src_ip:
            return f"ip:{a.src_ip}"
        if a.host:
            return f"host:{a.host}"
        if a.dst_ip:
            return f"dst:{a.dst_ip}"
        return "unknown"

    def add(self, alert: Alert, asset_boost_levels: int = 0) -> Incident:
        key = self.actor_key(alert)
        inc = self.incidents.get(self._open.get(key, ""))

        if inc and (alert.ts - inc.updated_at) <= self.window and inc.status != "resolved":
            self._attach(inc, alert)
        else:
            inc = self._create(alert)
            self._open[key] = inc.incident_id

        self._recompute(inc, asset_boost_levels)
        alert.incident_id = inc.incident_id
        return inc

    def _create(self, alert: Alert) -> Incident:
        inc = Incident(
            incident_id=new_id("in_"),
            created_at=alert.ts, updated_at=alert.ts,
            title=alert.title, severity=alert.severity, risk_score=alert.risk_score,
            src_ip=alert.src_ip, alert_count=0,
        )
        self.incidents[inc.incident_id] = inc
        self._members[inc.incident_id] = []
        self._attach(inc, alert)
        return inc

    def _attach(self, inc: Incident, alert: Alert) -> None:
        self._members[inc.incident_id].append(alert)
        inc.updated_at = max(inc.updated_at, alert.ts)
        inc.created_at = min(inc.created_at, alert.ts)

    def _recompute(self, inc: Incident, asset_boost_levels: int) -> None:
        members = self._members[inc.incident_id]
        inc.alert_count = len(members)

        # Severity: highest member severity, nudged by asset criticality.
        top = max(members, key=lambda a: sev_rank(a.severity))
        sev_idx = sev_rank(top.severity)
        sev_idx = max(0, min(len(SEVERITIES) - 1, sev_idx + _sign(asset_boost_levels)))
        inc.severity = SEVERITIES[sev_idx]

        inc.techniques = sorted({a.technique for a in members if a.technique})
        inc.categories = sorted({a.category for a in members if a.category})
        inc.hosts = sorted({a.host for a in members if a.host} |
                           {a.dst_ip for a in members if a.dst_ip})
        inc.risk_score = combined_incident_score(
            [a.risk_score for a in members], len(inc.categories), len(inc.techniques))
        inc.title = self._title(inc, top, members)
        inc.summary = self._summary(inc, members)

    def _title(self, inc: Incident, top: Alert, members: list[Alert]) -> str:
        who = inc.src_ip or (members[0].host if members and members[0].host else "unknown source")
        return f"{top.title} — {who}" if inc.alert_count == 1 else \
               f"{top.title} (+{inc.alert_count - 1} related) — {who}"

    def _summary(self, inc: Incident, members: list[Alert]) -> str:
        cats = ", ".join(inc.categories[:4]) or "n/a"
        span = inc.updated_at - inc.created_at
        return (f"{inc.alert_count} alert(s) over {int(span/60)}m from "
                f"{inc.src_ip or 'internal activity'}. Categories: {cats}. "
                f"Sources: {', '.join(sorted({a.source for a in members}))}.")

    def members(self, incident_id: str) -> list[Alert]:
        return self._members.get(incident_id, [])


def _sign(x: int) -> int:
    return (x > 0) - (x < 0)
