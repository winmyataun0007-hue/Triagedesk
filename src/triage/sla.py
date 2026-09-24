"""
SLA engine — the feature that makes this more than a CRUD alert list.

Each incident carries two deadlines derived from its severity: one to acknowledge
and one to resolve. This module sets those deadlines when an incident is created,
recomputes live SLA status (on track / at risk / breached), and escalates
incidents whose acknowledgement deadline has passed. It is what lets the platform
report real SOC performance metrics: MTTA, MTTR and SLA compliance.

The clock works on absolute timestamps, so it behaves correctly for incidents
created seconds ago and for seeded historical incidents alike.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import yaml

from src.common.models import Incident
from src.common.util import now

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class SlaState:
    ack_status: str          # met | on_track | at_risk | breached
    resolve_status: str
    ack_remaining: Optional[float]      # seconds; negative if breached
    resolve_remaining: Optional[float]


class SlaEngine:
    def __init__(self, path: Optional[str] = None):
        with open(path or os.path.join(ROOT, "config", "sla.yaml")) as fh:
            cfg = yaml.safe_load(fh)
        self.policies = cfg["policies"]
        self.warn = cfg.get("warning_fraction", 0.25)
        self.escalate_on_ack_breach = cfg.get("escalate_on_ack_breach", True)

    def policy(self, severity: str) -> dict:
        return self.policies.get(severity, self.policies["medium"])

    def apply_new(self, inc: Incident) -> None:
        """Set priority and SLA due-times at incident creation."""
        p = self.policy(inc.severity)
        inc.priority = p["priority"]
        inc.ack_due_at = inc.created_at + p["ack_minutes"] * 60
        inc.resolve_due_at = inc.created_at + p["resolve_minutes"] * 60

    def refresh(self, inc: Incident, at: Optional[float] = None) -> SlaState:
        """Recompute breach flags and escalation. Mutates inc; returns live state."""
        t = at if at is not None else now()

        # Acknowledgement clock
        if inc.acknowledged_at is not None:
            ack_status = "met"
            ack_remaining = inc.ack_due_at - inc.acknowledged_at if inc.ack_due_at else None
            inc.ack_breached = (inc.ack_due_at is not None and inc.acknowledged_at > inc.ack_due_at)
        else:
            ack_remaining = (inc.ack_due_at - t) if inc.ack_due_at else None
            if ack_remaining is None:
                ack_status = "on_track"
            elif ack_remaining < 0:
                ack_status = "breached"; inc.ack_breached = True
            elif ack_remaining < self._window(inc, "ack") * self.warn:
                ack_status = "at_risk"
            else:
                ack_status = "on_track"

        # Resolution clock
        if inc.resolved_at is not None:
            resolve_status = "met"
            resolve_remaining = inc.resolve_due_at - inc.resolved_at if inc.resolve_due_at else None
            inc.resolve_breached = (inc.resolve_due_at is not None and inc.resolved_at > inc.resolve_due_at)
        else:
            resolve_remaining = (inc.resolve_due_at - t) if inc.resolve_due_at else None
            if resolve_remaining is None:
                resolve_status = "on_track"
            elif resolve_remaining < 0:
                resolve_status = "breached"; inc.resolve_breached = True
            elif resolve_remaining < self._window(inc, "resolve") * self.warn:
                resolve_status = "at_risk"
            else:
                resolve_status = "on_track"

        # Escalation reflects CURRENT state: an incident is escalated while its
        # acknowledgement deadline has passed and no analyst has picked it up.
        # Acknowledging it clears the escalation.
        inc.escalated = bool(self.escalate_on_ack_breach and inc.ack_breached
                             and inc.acknowledged_at is None)

        return SlaState(ack_status, resolve_status, ack_remaining, resolve_remaining)

    def _window(self, inc: Incident, which: str) -> float:
        p = self.policy(inc.severity)
        return p["ack_minutes"] * 60 if which == "ack" else p["resolve_minutes"] * 60

    # -- fleet metrics ------------------------------------------------------

    @staticmethod
    def metrics(incidents: list[Incident]) -> dict:
        """Compute MTTA, MTTR and SLA compliance across a set of incidents."""
        ttas, ttrs = [], []
        ack_total = ack_met = res_total = res_met = 0
        for i in incidents:
            if i.acknowledged_at is not None:
                ttas.append(i.acknowledged_at - i.created_at)
                ack_total += 1
                ack_met += 0 if i.ack_breached else 1
            if i.resolved_at is not None:
                ttrs.append(i.resolved_at - i.created_at)
                res_total += 1
                res_met += 0 if i.resolve_breached else 1
        mtta = sum(ttas) / len(ttas) if ttas else None
        mttr = sum(ttrs) / len(ttrs) if ttrs else None
        ack_compliance = (ack_met / ack_total * 100) if ack_total else None
        res_compliance = (res_met / res_total * 100) if res_total else None
        return {
            "mtta_seconds": mtta, "mttr_seconds": mttr,
            "ack_compliance_pct": ack_compliance, "resolve_compliance_pct": res_compliance,
            "acknowledged": ack_total, "resolved": res_total,
        }
